/*
  https_feasibility.ino - BearSSL HTTPS feasibility configuration + instrumentation.

  M5-00G: handshake success/fail/duration come from WiFiServerSecure::available()
  wrapping the TLS accept path, with heap samples at overlay TLS checkpoints.
  Heap "min" values are sampled at checkpoints — not an allocator high-water mark.
*/

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

#include "tasmota_support/https_feasibility.h"

static BearSSL::X509List *HttpsFeasibilityCert = nullptr;
static BearSSL::PrivateKey *HttpsFeasibilityKey = nullptr;
static bool HttpsFeasibilityReady = false;

extern "C" int HttpsFeasibilityTlsAcceptErr = 0;

#if HTTPS_FEASIBILITY_INSTRUMENT

// Checkpoint stages from overlay _connectSSLServerEC:
// 0 before alloc, 1 after iobuf, 2 after engine reset, 3 after handshake attempt.
enum : uint8_t {
  HTTPS_CKPT_BEFORE_ALLOC = 0,
  HTTPS_CKPT_AFTER_IOBUF = 1,
  HTTPS_CKPT_AFTER_ENGINE = 2,
  HTTPS_CKPT_AFTER_HS = 3,
};

struct HttpsFeasibilityMetrics {
  uint32_t heap_before_init;
  uint32_t heap_after_init;
  uint32_t heap_before_accept;       // sampled
  uint32_t heap_ckpt_after_iobuf;    // sampled
  uint32_t heap_ckpt_after_engine;   // sampled
  uint32_t heap_after_hs;            // sampled
  uint32_t heap_min_sampled;         // min of sampled free-heap checkpoints
  uint32_t heap_after_disconnect;    // sampled
  uint32_t max_free_block_min;       // min sampled max-block
  uint8_t  frag_max;
  uint32_t hs_duration_ms;
  uint32_t hs_duration_max_ms;
  uint32_t hs_ok;
  uint32_t hs_fail;
  uint32_t hs_unknown;
  uint32_t http_seen;                // handleClient observed an active TLS client
  int32_t  last_ssl_error;
  uint32_t disconnects;
  bool     client_was_connected;
  bool     boot_logged;
  bool     accept_in_progress;
  uint32_t accept_start_ms;
  bool     peak_is_sampled;          // always true: documents measurement method
};
static HttpsFeasibilityMetrics HttpsMetrics = {};

static void HttpsFeasibilitySampleFloor(uint32_t *heap_slot) {
  uint32_t free_heap = ESP.getFreeHeap();
  uint32_t max_block = ESP.getMaxFreeBlockSize();
  uint8_t frag = ESP.getHeapFragmentation();
  if (heap_slot) {
    *heap_slot = free_heap;
  }
  if ((0 == HttpsMetrics.heap_min_sampled) || (free_heap < HttpsMetrics.heap_min_sampled)) {
    HttpsMetrics.heap_min_sampled = free_heap;
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
  HttpsMetrics.peak_is_sampled = true;
  AddLog(LOG_LEVEL_INFO,
         PSTR("HTTPS: boot reset='%s' free_heap=%u max_block=%u frag=%u (heap mins are sampled)"),
         ESP.getResetReason().c_str(),
         ESP.getFreeHeap(),
         ESP.getMaxFreeBlockSize(),
         ESP.getHeapFragmentation());
}

void HttpsFeasibilityNoteInitHeaps(uint32_t heap_before, uint32_t heap_after) {
  HttpsMetrics.heap_before_init = heap_before;
  HttpsMetrics.heap_after_init = heap_after;
  HttpsMetrics.heap_min_sampled = heap_after;
  HttpsMetrics.max_free_block_min = ESP.getMaxFreeBlockSize();
  HttpsMetrics.frag_max = ESP.getHeapFragmentation();
  HttpsMetrics.peak_is_sampled = true;
  AddLog(LOG_LEVEL_INFO,
         PSTR("HTTPS: init heap before=%u after=%u delta=%d max_block=%u frag=%u"),
         heap_before,
         heap_after,
         (int32_t)heap_after - (int32_t)heap_before,
         HttpsMetrics.max_free_block_min,
         HttpsMetrics.frag_max);
}

extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail) {
  (void)detail;
  // No AddLog here — keep BearSSL path allocation-light.
  switch (stage) {
    case HTTPS_CKPT_BEFORE_ALLOC:
      HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_before_accept);
      break;
    case HTTPS_CKPT_AFTER_IOBUF:
      HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_ckpt_after_iobuf);
      break;
    case HTTPS_CKPT_AFTER_ENGINE:
      HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_ckpt_after_engine);
      break;
    case HTTPS_CKPT_AFTER_HS:
      HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_after_hs);
      break;
    default:
      HttpsFeasibilitySampleFloor(nullptr);
      break;
  }
}

void HttpsFeasibilityOnAcceptBegin(void) {
  HttpsMetrics.accept_in_progress = true;
  HttpsMetrics.accept_start_ms = millis();
  HttpsFeasibilityTlsAcceptErr = 0;
}

void HttpsFeasibilityOnAcceptEnd(BearSSL::WiFiClientSecure &client) {
  if (!HttpsMetrics.accept_in_progress) {
    return;
  }
  HttpsMetrics.accept_in_progress = false;

  const uint32_t dur = millis() - HttpsMetrics.accept_start_ms;
  HttpsMetrics.hs_duration_ms = dur;
  if (dur > HttpsMetrics.hs_duration_max_ms) {
    HttpsMetrics.hs_duration_max_ms = dur;
  }

  const bool connected = client.connected();
  int err = HttpsFeasibilityTlsAcceptErr;
  if (err == 0) {
    err = client.getLastSSLError();
  }
  HttpsMetrics.last_ssl_error = err;

  if (connected && (err == 0)) {
    HttpsMetrics.hs_ok++;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: hs ok ms=%u heap_samp before=%u iobuf=%u eng=%u after=%u min_samp=%u max_block_min=%u ok=%u"),
           dur,
           HttpsMetrics.heap_before_accept,
           HttpsMetrics.heap_ckpt_after_iobuf,
           HttpsMetrics.heap_ckpt_after_engine,
           HttpsMetrics.heap_after_hs,
           HttpsMetrics.heap_min_sampled,
           HttpsMetrics.max_free_block_min,
           HttpsMetrics.hs_ok);
  } else if (!connected && (err != 0)) {
    HttpsMetrics.hs_fail++;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: hs fail err=%d ms=%u heap_samp before=%u after=%u min_samp=%u fail=%u"),
           err,
           dur,
           HttpsMetrics.heap_before_accept,
           HttpsMetrics.heap_after_hs,
           HttpsMetrics.heap_min_sampled,
           HttpsMetrics.hs_fail);
  } else if (!connected && (err == 0)) {
    // No pending TCP client, or outcome cleared before error capture.
    HttpsMetrics.hs_unknown++;
    AddLog(LOG_LEVEL_DEBUG,
           PSTR("HTTPS: hs unknown (no client/err) ms=%u unknown=%u"),
           dur,
           HttpsMetrics.hs_unknown);
  } else {
    // connected but err != 0 — treat as failure once.
    HttpsMetrics.hs_fail++;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: hs fail-connected err=%d ms=%u fail=%u"),
           err,
           dur,
           HttpsMetrics.hs_fail);
  }
}

void HttpsFeasibilityBeforeHandleClient(void *webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(webserver);
  if (server == nullptr) { return; }
  HttpsMetrics.client_was_connected = server->client().connected();
}

void HttpsFeasibilityAfterHandleClient(void *webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(webserver);
  if (server == nullptr) { return; }

  const bool connected = server->client().connected();
  if (connected) {
    HttpsMetrics.http_seen++;
  }

  if (HttpsMetrics.client_was_connected && !connected) {
    HttpsMetrics.disconnects++;
    HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_after_disconnect);
    AddLog(LOG_LEVEL_DEBUG,
           PSTR("HTTPS: disconnect heap_samp=%u max_block=%u frag=%u disc=%u"),
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
         "\"HeapBeforeAccept\":%u,\"HeapAfterIobuf\":%u,\"HeapAfterEngine\":%u,\"HeapAfterHs\":%u,"
         "\"HeapMinSampled\":%u,\"HeapAfterDisc\":%u,\"MaxBlockMin\":%u,\"FragMax\":%u,"
         "\"PeakIsSampled\":%u,"
         "\"HsMs\":%u,\"HsMaxMs\":%u,\"HsOk\":%u,\"HsFail\":%u,\"HsUnknown\":%u,"
         "\"HttpSeen\":%u,\"LastSslErr\":%d,\"Disconnects\":%u,"
         "\"RxBuf\":%u,\"TxBuf\":%u}}"),
    HttpsMetrics.heap_before_init,
    HttpsMetrics.heap_after_init,
    HttpsMetrics.heap_before_accept,
    HttpsMetrics.heap_ckpt_after_iobuf,
    HttpsMetrics.heap_ckpt_after_engine,
    HttpsMetrics.heap_after_hs,
    HttpsMetrics.heap_min_sampled,
    HttpsMetrics.heap_after_disconnect,
    HttpsMetrics.max_free_block_min,
    HttpsMetrics.frag_max,
    HttpsMetrics.peak_is_sampled ? 1 : 0,
    HttpsMetrics.hs_duration_ms,
    HttpsMetrics.hs_duration_max_ms,
    HttpsMetrics.hs_ok,
    HttpsMetrics.hs_fail,
    HttpsMetrics.hs_unknown,
    HttpsMetrics.http_seen,
    HttpsMetrics.last_ssl_error,
    HttpsMetrics.disconnects,
    (uint32_t)HTTPS_FEASIBILITY_RX_BUF,
    (uint32_t)HTTPS_FEASIBILITY_TX_BUF);
  return true;
}

#else  // !HTTPS_FEASIBILITY_INSTRUMENT

extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail) {
  (void)stage;
  (void)detail;
}

#endif  // HTTPS_FEASIBILITY_INSTRUMENT

bool HttpsFeasibilityConfigureServer(void *webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(webserver);
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
           PSTR("HTTPS: EC P-256 ready rx=%u tx=%u (self-signed lab cert; overlay TLS1.2+GCM)"),
           (uint32_t)HTTPS_FEASIBILITY_RX_BUF,
           (uint32_t)HTTPS_FEASIBILITY_TX_BUF);
  }

  server->getServer().setBufferSizes(HTTPS_FEASIBILITY_RX_BUF, HTTPS_FEASIBILITY_TX_BUF);
  server->getServer().setECCert(
      HttpsFeasibilityCert,
      BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
      HttpsFeasibilityKey);
  return true;
}

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS
