/*
  https_feasibility.ino - BearSSL HTTPS feasibility configuration + instrumentation.

  Links only when USE_WEBSERVER_HTTPS is defined. Uses core BearSSL
  WiFiServerSecure with ECDSA P-256 and explicit buffer sizes.

  Pinned core (framework-arduinoespressif8266 2.8.0) limitations:
  - WiFiServerSecure has no ServerSessions / setCache API.
  - Server TLS versions fixed in WiFiClientSecureBearSSL.cpp to TLS 1.0–1.2.
  - Server EC suites fixed in suites_server_ec_P (includes CBC/3DES).
  - Secondary stack: cores/esp8266/StackThunk.cpp allocates 6200 bytes on first ref.
  - Project bearssl-esp8266 (library name "BearSSL") replaces SDK libbearssl.a and
    needs tls_mini's stack_thunk_yield (hence -DUSE_TLS on this env). Yield points
    inside that crypto library therefore apply to server handshakes too; the MQTT
    light *client* wrapper itself is separate.
*/

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

#include "tasmota_support/https_feasibility.h"

static BearSSL::X509List *HttpsFeasibilityCert = nullptr;
static BearSSL::PrivateKey *HttpsFeasibilityKey = nullptr;
static bool HttpsFeasibilityReady = false;

#if HTTPS_FEASIBILITY_INSTRUMENT
struct HttpsFeasibilityMetrics {
  uint32_t heap_before_init;
  uint32_t heap_after_init;
  uint32_t heap_before_hs;
  uint32_t heap_after_hs;
  uint32_t heap_min_conn;
  uint32_t heap_after_disconnect;
  uint32_t max_free_block_min;
  uint8_t  frag_max;
  uint32_t hs_duration_ms;
  uint32_t hs_duration_max_ms;
  uint32_t conn_ok;
  uint32_t conn_fail;
  int32_t  last_ssl_error;
  uint32_t disconnects;
  bool     client_was_connected;
  bool     boot_logged;
  uint32_t hs_pending_start_ms;
  bool     hs_pending;
};
static HttpsFeasibilityMetrics HttpsMetrics = {};

static void HttpsFeasibilitySampleFloor(void) {
  uint32_t free_heap = ESP.getFreeHeap();
  uint32_t max_block = ESP.getMaxFreeBlockSize();
  uint8_t frag = ESP.getHeapFragmentation();
  if ((0 == HttpsMetrics.heap_min_conn) || (free_heap < HttpsMetrics.heap_min_conn)) {
    HttpsMetrics.heap_min_conn = free_heap;
  }
  if ((0 == HttpsMetrics.max_free_block_min) || (max_block < HttpsMetrics.max_free_block_min)) {
    HttpsMetrics.max_free_block_min = max_block;
  }
  if (frag > HttpsMetrics.frag_max) {
    HttpsMetrics.frag_max = frag;
  }
}

void HttpsFeasibilityLogBootOnce(void) {
  if (HttpsMetrics.boot_logged) { return; }
  HttpsMetrics.boot_logged = true;
  // Reset reason only — no credentials. Unexpected restarts show up here across trials.
  AddLog(LOG_LEVEL_INFO,
         PSTR("HTTPS: boot reset='%s' free_heap=%u max_block=%u frag=%u"),
         ESP.getResetReason().c_str(),
         ESP.getFreeHeap(),
         ESP.getMaxFreeBlockSize(),
         ESP.getHeapFragmentation());
}

void HttpsFeasibilityNoteInitHeaps(uint32_t heap_before, uint32_t heap_after) {
  HttpsMetrics.heap_before_init = heap_before;
  HttpsMetrics.heap_after_init = heap_after;
  HttpsMetrics.heap_min_conn = heap_after;
  HttpsMetrics.max_free_block_min = ESP.getMaxFreeBlockSize();
  HttpsMetrics.frag_max = ESP.getHeapFragmentation();
  AddLog(LOG_LEVEL_INFO,
         PSTR("HTTPS: init heap before=%u after=%u delta=%d max_block=%u frag=%u"),
         heap_before,
         heap_after,
         (int32_t)heap_after - (int32_t)heap_before,
         HttpsMetrics.max_free_block_min,
         HttpsMetrics.frag_max);
}

void HttpsFeasibilityBeforeHandleClient(BearSSL::ESP8266WebServerSecure *server) {
  if (server == nullptr) { return; }
  HttpsMetrics.client_was_connected = server->client().connected();
  if (!HttpsMetrics.client_was_connected) {
    HttpsMetrics.hs_pending = true;
    HttpsMetrics.hs_pending_start_ms = millis();
    HttpsMetrics.heap_before_hs = ESP.getFreeHeap();
  }
  HttpsFeasibilitySampleFloor();
}

void HttpsFeasibilityAfterHandleClient(BearSSL::ESP8266WebServerSecure *server) {
  if (server == nullptr) { return; }

  bool connected = server->client().connected();
  HttpsFeasibilitySampleFloor();

  if (HttpsMetrics.hs_pending && connected && !HttpsMetrics.client_was_connected) {
    uint32_t dur = millis() - HttpsMetrics.hs_pending_start_ms;
    HttpsMetrics.hs_duration_ms = dur;
    if (dur > HttpsMetrics.hs_duration_max_ms) {
      HttpsMetrics.hs_duration_max_ms = dur;
    }
    HttpsMetrics.heap_after_hs = ESP.getFreeHeap();
    int err = server->client().getLastSSLError();
    HttpsMetrics.last_ssl_error = err;
    if (err == 0) {
      HttpsMetrics.conn_ok++;
      AddLog(LOG_LEVEL_INFO,
             PSTR("HTTPS: hs ok ms=%u heap %u->%u min=%u max_block=%u frag=%u conn_ok=%u"),
             dur,
             HttpsMetrics.heap_before_hs,
             HttpsMetrics.heap_after_hs,
             HttpsMetrics.heap_min_conn,
             ESP.getMaxFreeBlockSize(),
             ESP.getHeapFragmentation(),
             HttpsMetrics.conn_ok);
    } else {
      HttpsMetrics.conn_fail++;
      AddLog(LOG_LEVEL_INFO,
             PSTR("HTTPS: hs fail err=%d ms=%u heap %u->%u min=%u conn_fail=%u"),
             err,
             dur,
             HttpsMetrics.heap_before_hs,
             HttpsMetrics.heap_after_hs,
             HttpsMetrics.heap_min_conn,
             HttpsMetrics.conn_fail);
    }
    HttpsMetrics.hs_pending = false;
  } else if (HttpsMetrics.hs_pending && !connected && !HttpsMetrics.client_was_connected) {
    // available() ran but left no connected client (OOM / handshake reject).
    int err = server->client().getLastSSLError();
    if (err != 0) {
      HttpsMetrics.conn_fail++;
      HttpsMetrics.last_ssl_error = err;
      AddLog(LOG_LEVEL_INFO,
             PSTR("HTTPS: hs abort err=%d heap=%u min=%u conn_fail=%u"),
             err,
             ESP.getFreeHeap(),
             HttpsMetrics.heap_min_conn,
             HttpsMetrics.conn_fail);
    }
    HttpsMetrics.hs_pending = false;
  }

  if (HttpsMetrics.client_was_connected && !connected) {
    HttpsMetrics.disconnects++;
    HttpsMetrics.heap_after_disconnect = ESP.getFreeHeap();
    AddLog(LOG_LEVEL_DEBUG,
           PSTR("HTTPS: disconnect heap=%u max_block=%u frag=%u disc=%u"),
           HttpsMetrics.heap_after_disconnect,
           ESP.getMaxFreeBlockSize(),
           ESP.getHeapFragmentation(),
           HttpsMetrics.disconnects);
  }
}

bool HttpsFeasibilityCmnd(void) {
  if (strcasecmp_P(XdrvMailbox.topic, PSTR("HttpsMetrics")) != 0) {
    return false;
  }
  Response_P(
    PSTR("{\"HttpsMetrics\":{"
         "\"HeapBeforeInit\":%u,\"HeapAfterInit\":%u,"
         "\"HeapBeforeHs\":%u,\"HeapAfterHs\":%u,\"HeapMin\":%u,"
         "\"HeapAfterDisc\":%u,\"MaxBlockMin\":%u,\"FragMax\":%u,"
         "\"HsMs\":%u,\"HsMaxMs\":%u,\"ConnOk\":%u,\"ConnFail\":%u,"
         "\"LastSslErr\":%d,\"Disconnects\":%u,"
         "\"RxBuf\":%u,\"TxBuf\":%u}}"),
    HttpsMetrics.heap_before_init,
    HttpsMetrics.heap_after_init,
    HttpsMetrics.heap_before_hs,
    HttpsMetrics.heap_after_hs,
    HttpsMetrics.heap_min_conn,
    HttpsMetrics.heap_after_disconnect,
    HttpsMetrics.max_free_block_min,
    HttpsMetrics.frag_max,
    HttpsMetrics.hs_duration_ms,
    HttpsMetrics.hs_duration_max_ms,
    HttpsMetrics.conn_ok,
    HttpsMetrics.conn_fail,
    HttpsMetrics.last_ssl_error,
    HttpsMetrics.disconnects,
    (uint32_t)HTTPS_FEASIBILITY_RX_BUF,
    (uint32_t)HTTPS_FEASIBILITY_TX_BUF);
  return true;
}
#endif  // HTTPS_FEASIBILITY_INSTRUMENT

bool HttpsFeasibilityConfigureServer(BearSSL::ESP8266WebServerSecure *server) {
  if (server == nullptr) {
    return false;
  }

#if HTTPS_FEASIBILITY_INSTRUMENT
  HttpsFeasibilityLogBootOnce();
#endif

  if (!HttpsFeasibilityReady) {
    HttpsFeasibilityCert = new BearSSL::X509List(HTTPS_FEASIBILITY_SERVER_CERT);
    HttpsFeasibilityKey = new BearSSL::PrivateKey(HTTPS_FEASIBILITY_SERVER_KEY);
    if ((HttpsFeasibilityCert == nullptr) || (HttpsFeasibilityKey == nullptr) ||
        !HttpsFeasibilityKey->isEC()) {
      AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: cert/key allocation or EC key check failed"));
      delete HttpsFeasibilityCert;
      delete HttpsFeasibilityKey;
      HttpsFeasibilityCert = nullptr;
      HttpsFeasibilityKey = nullptr;
      return false;
    }
    HttpsFeasibilityReady = true;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: EC P-256 ready rx=%u tx=%u (overlay TLS1.2 + ECDHE-ECDSA-AES128-GCM; no session cache)"),
           (uint32_t)HTTPS_FEASIBILITY_RX_BUF,
           (uint32_t)HTTPS_FEASIBILITY_TX_BUF);
  }

  // Pointers retained for server lifetime (required by WiFiServerSecure::setECCert).
  // stack_thunk_add_ref() runs in WiFiServerSecure ctor (6200-byte secondary stack).
  // TLS version/cipher enforcement is in the M5-00D project-local framework overlay
  // (https_feasibility_local/scripts/bearssl_server_secure_overlay.py), not via a
  // public WiFiServerSecure API on this pinned core.
  server->getServer().setBufferSizes(HTTPS_FEASIBILITY_RX_BUF, HTTPS_FEASIBILITY_TX_BUF);
  server->getServer().setECCert(
      HttpsFeasibilityCert,
      BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
      HttpsFeasibilityKey);
  return true;
}

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS
