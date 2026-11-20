/*
  https_feasibility.ino - Optional BearSSL HTTPS listener + experimental safeguards.

  M5-01A: HTTPS is disabled by default. HTTP remains independent on :80.
  Activation uses RAM trial mode, explicit confirm into Settings->sbflag1.https_webserver,
  automatic trial expiry, and factory-reset clear (memset of Settings).
*/

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

#include "tasmota_support/https_feasibility.h"
#include <TasmotaWebServer.h>

static BearSSL::X509List *HttpsFeasibilityCert = nullptr;
static BearSSL::PrivateKey *HttpsFeasibilityKey = nullptr;
static bool HttpsFeasibilityReady = false;

extern "C" int HttpsFeasibilityTlsAcceptErr = 0;
extern "C" int8_t HttpsFeasibilityTlsHsOk = -1;

static HttpsFeasibilityMode HttpsMode = HTTPS_MODE_OFF;
static uint32_t HttpsTrialDeadlineMs = 0;
static bool HttpsListenerRunning = false;
static uint8_t HttpsBootFailCount = 0;
static char HttpsLastError[40] = "";

#if HTTPS_FEASIBILITY_INSTRUMENT

enum : uint8_t {
  HTTPS_CKPT_BEFORE_ALLOC = 0,
  HTTPS_CKPT_AFTER_IOBUF = 1,
  HTTPS_CKPT_AFTER_ENGINE = 2,
  HTTPS_CKPT_AFTER_HS = 3,
};

struct HttpsFeasibilityMetrics {
  uint32_t heap_before_init;
  uint32_t heap_after_init;
  uint32_t heap_before_accept;
  uint32_t heap_ckpt_after_iobuf;
  uint32_t heap_ckpt_after_engine;
  uint32_t heap_after_hs;
  uint32_t heap_min_sampled;
  uint32_t heap_after_disconnect;
  uint32_t max_free_block_min;
  uint8_t  frag_max;
  uint32_t hs_duration_ms;
  uint32_t hs_duration_max_ms;
  uint32_t hs_ok;
  uint32_t hs_fail;
  uint32_t hs_unknown;
  uint32_t http_client_polls;
  int32_t  last_ssl_error;
  uint32_t disconnects;
  bool     last_transport_connected;
  bool     client_was_connected;
  bool     boot_logged;
  bool     accept_in_progress;
  uint32_t accept_start_ms;
  bool     peak_is_sampled;
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
         PSTR("HTTPS: boot reset='%s' free_heap=%u max_block=%u frag=%u (HTTPS default OFF)"),
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
         PSTR("HTTPS: listener heap before=%u after=%u delta=%d max_block=%u frag=%u"),
         heap_before,
         heap_after,
         (int32_t)heap_after - (int32_t)heap_before,
         HttpsMetrics.max_free_block_min,
         HttpsMetrics.frag_max);
}

extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail) {
  (void)detail;
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
  HttpsFeasibilityTlsHsOk = -1;
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

  HttpsMetrics.last_transport_connected = client.connected();

  int err = HttpsFeasibilityTlsAcceptErr;
  if ((err == 0) && (HttpsFeasibilityTlsHsOk == 0)) {
    err = client.getLastSSLError();
  }
  HttpsMetrics.last_ssl_error = err;

  const int8_t hs = HttpsFeasibilityTlsHsOk;
  if (hs == 1) {
    HttpsMetrics.hs_ok++;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: hs ok ms=%u transport=%u min_samp=%u ok=%u"),
           dur,
           HttpsMetrics.last_transport_connected ? 1 : 0,
           HttpsMetrics.heap_min_sampled,
           HttpsMetrics.hs_ok);
  } else if (hs == 0) {
    HttpsMetrics.hs_fail++;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: hs fail err=%d ms=%u fail=%u"),
           err, dur, HttpsMetrics.hs_fail);
  } else {
    HttpsMetrics.hs_unknown++;
  }
}

void HttpsFeasibilityBeforeHandleClient(void *https_webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(https_webserver);
  if (server == nullptr) { return; }
  HttpsMetrics.client_was_connected = server->client().connected();
}

void HttpsFeasibilityAfterHandleClient(void *https_webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(https_webserver);
  if (server == nullptr) { return; }

  const bool connected = server->client().connected();
  if (connected) {
    HttpsMetrics.http_client_polls++;
  }

  if (HttpsMetrics.client_was_connected && !connected) {
    HttpsMetrics.disconnects++;
    HttpsFeasibilitySampleFloor(&HttpsMetrics.heap_after_disconnect);
  }
}

#else  // !HTTPS_FEASIBILITY_INSTRUMENT

extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail) {
  (void)stage;
  (void)detail;
}

#endif  // HTTPS_FEASIBILITY_INSTRUMENT

bool HttpsFeasibilityIsCompiled(void) {
  return true;
}

bool HttpsFeasibilityIsListenerRunning(void) {
  return HttpsListenerRunning;
}

uint8_t HttpsFeasibilityGetMode(void) {
  return (uint8_t)HttpsMode;
}

bool HttpsFeasibilityConfirmedPersisted(void) {
  return Settings->sbflag1.https_webserver;
}

void HttpsFeasibilityOnSettingsDefault(void) {
  // Settings memset already clears https_webserver; ensure runtime matches.
  HttpsMode = HTTPS_MODE_OFF;
  HttpsTrialDeadlineMs = 0;
  HttpsListenerRunning = false;
  HttpsLastError[0] = '\0';
}

static void HttpsFeasibilitySetError(const char *msg) {
  strlcpy(HttpsLastError, msg ? msg : "", sizeof(HttpsLastError));
}

bool HttpsFeasibilityConfigureServer(void *https_webserver) {
  auto *server = static_cast<HttpsFeasibilityWebServer *>(https_webserver);
  if (server == nullptr) {
    HttpsFeasibilitySetError("null_server");
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
      HttpsFeasibilitySetError("cert_key");
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
  HttpsFeasibilitySetError("");
  return true;
}

bool HttpsFeasibilityStartListener(void *facade_webserver) {
  auto *facade = static_cast<TasmotaWebServer *>(facade_webserver);
  if (facade == nullptr) {
    HttpsFeasibilitySetError("no_facade");
    return false;
  }
  if (HttpsListenerRunning && facade->httpsServer() != nullptr) {
    return true;
  }

  const uint32_t heap_before = ESP.getFreeHeap();
  auto *https = new TasmotaHttpsWebServer(HTTPS_FEASIBILITY_PORT);
  if (https == nullptr) {
    HttpsFeasibilitySetError("oom_server");
    AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: listener allocation failed — HTTP unchanged"));
    return false;
  }

  if (!HttpsFeasibilityConfigureServer(https)) {
    delete https;
    AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: configure failed — HTTP unchanged"));
    return false;
  }

  facade->attachHttps(https);

  const char* headerkeys[] = { "Referer", "Host" };
  https->collectHeaders(headerkeys, 2);

  // Caller must invoke WebServerRegisterRoutesForHttps() then we begin().
  // For boot-restore path the caller registers then we need begin — done below
  // after optional mode mark. Routes may be empty until caller registers; begin
  // is deferred to HttpsFeasibilityBeginListener().
  HttpsListenerRunning = false;  // not accepting until BeginListener
  (void)heap_before;
  if (Settings->sbflag1.https_webserver) {
    HttpsMode = HTTPS_MODE_CONFIRMED;
  }
  AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: listener configured on port %u (await route bind)"),
         (uint32_t)HTTPS_FEASIBILITY_PORT);
  return true;
}

bool HttpsFeasibilityBeginListener(void *facade_webserver) {
  auto *facade = static_cast<TasmotaWebServer *>(facade_webserver);
  if ((facade == nullptr) || (facade->httpsServer() == nullptr)) {
    return false;
  }
  const uint32_t heap_before = ESP.getFreeHeap();
  facade->httpsServer()->begin();
  HttpsListenerRunning = true;
  HttpsBootFailCount = 0;
#if HTTPS_FEASIBILITY_INSTRUMENT
  HttpsFeasibilityNoteInitHeaps(heap_before, ESP.getFreeHeap());
#endif
  AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: listener accepting on port %u (HTTP :80 independent)"),
         (uint32_t)HTTPS_FEASIBILITY_PORT);
  return true;
}

void HttpsFeasibilityStopListener(void *facade_webserver) {
  auto *facade = static_cast<TasmotaWebServer *>(facade_webserver);
  if (facade == nullptr) {
    return;
  }
  TasmotaHttpsWebServer *https = facade->httpsServer();
  if (https != nullptr) {
    https->close();
    delete https;
    facade->attachHttps(nullptr);
  }
  HttpsListenerRunning = false;
  if (HttpsMode != HTTPS_MODE_CONFIRMED) {
    HttpsMode = HTTPS_MODE_OFF;
  }
  HttpsTrialDeadlineMs = 0;
  AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: listener stopped (HTTP unchanged)"));
}

void HttpsFeasibilitySuspendForManager(void *facade_webserver) {
  auto *facade = static_cast<TasmotaWebServer *>(facade_webserver);
  if (facade == nullptr) { return; }
  // Drop the TLS listener during captive/manager; keep confirmed persistence.
  if (!HttpsListenerRunning && (facade->httpsServer() == nullptr)) {
    return;
  }
  HttpsFeasibilityStopListener(facade_webserver);
  if (Settings->sbflag1.https_webserver) {
    HttpsMode = HTTPS_MODE_CONFIRMED;  // listener restarted when STA web returns
  } else {
    HttpsMode = HTTPS_MODE_OFF;
  }
  AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: suspended for Wi-Fi manager (HTTP captive active)"));
}

void HttpsFeasibilityNoteBootFailure(void *facade_webserver) {
  (void)facade_webserver;
  AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: persisted enable failed — HTTP continues"));
  if (!Settings->sbflag1.https_webserver) {
    return;
  }
  if (HttpsBootFailCount < 255) {
    HttpsBootFailCount++;
  }
  // After repeated confirmed-start failures within this uptime, clear persistence once.
  // Survives soft issues without wiping Wi-Fi; lost on power cycle (by design — avoids RTC redesign).
  if (HttpsBootFailCount >= HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT) {
    Settings->sbflag1.https_webserver = 0;
    HttpsMode = HTTPS_MODE_OFF;
    HttpsBootFailCount = 0;
    SettingsSave(0);
    HttpsFeasibilitySetError("boot_fail_suppressed");
    AddLog(LOG_LEVEL_ERROR,
           PSTR("HTTPS: confirmed mode suppressed after %u start failures"),
           (uint32_t)HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT);
  } else {
    HttpsFeasibilitySetError("boot_fail");
  }
}

void HttpsFeasibilityEverySecond(void *facade_webserver) {
  if (HttpsMode != HTTPS_MODE_TRIAL) {
    return;
  }
  if (HttpsTrialDeadlineMs == 0) {
    return;
  }
  if ((int32_t)(millis() - HttpsTrialDeadlineMs) < 0) {
    return;
  }
  AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: trial expired — reverting (not persisted)"));
  HttpsFeasibilityStopListener(facade_webserver);
  HttpsMode = HTTPS_MODE_OFF;
  // Ensure confirmed bit stays clear for unconfirmed trials.
  Settings->sbflag1.https_webserver = 0;
}

static void HttpsFeasibilityRespondStatus(void) {
  Response_P(
    PSTR("{\"HttpsWeb\":{"
         "\"Compiled\":1,"
         "\"Mode\":\"%s\","
         "\"Listener\":%u,"
         "\"Persisted\":%u,"
         "\"Port\":%u,"
         "\"TrialRemainSec\":%u,"
         "\"LastError\":\"%s\","
         "\"HttpRedirectToHttps\":0"
#if HTTPS_FEASIBILITY_INSTRUMENT
         ",\"HsOk\":%u,\"HsFail\":%u,\"HsUnknown\":%u,"
         "\"HttpClientPolls\":%u,\"LastSslErr\":%d,\"TransportConnected\":%u,"
         "\"HeapMinSampled\":%u,\"PeakIsSampled\":%u"
#endif
         "}}"),
    (HttpsMode == HTTPS_MODE_CONFIRMED) ? "Confirmed" :
      (HttpsMode == HTTPS_MODE_TRIAL) ? "Trial" : "Off",
    HttpsListenerRunning ? 1 : 0,
    HttpsFeasibilityConfirmedPersisted() ? 1 : 0,
    (uint32_t)HTTPS_FEASIBILITY_PORT,
    (HttpsMode == HTTPS_MODE_TRIAL && HttpsTrialDeadlineMs)
      ? (uint32_t)((HttpsTrialDeadlineMs - millis()) / 1000UL) : 0U,
    HttpsLastError[0] ? HttpsLastError : ""
#if HTTPS_FEASIBILITY_INSTRUMENT
    ,
    HttpsMetrics.hs_ok,
    HttpsMetrics.hs_fail,
    HttpsMetrics.hs_unknown,
    HttpsMetrics.http_client_polls,
    HttpsMetrics.last_ssl_error,
    HttpsMetrics.last_transport_connected ? 1 : 0,
    HttpsMetrics.heap_min_sampled,
    HttpsMetrics.peak_is_sampled ? 1 : 0
#endif
  );
}

bool HttpsFeasibilityCmnd(void) {
  // HttpsWeb and HttpsMetrics share this handler.
  if (strcasecmp_P(XdrvMailbox.topic, PSTR("HttpsMetrics")) == 0) {
    HttpsFeasibilityRespondStatus();
    return true;
  }
  if (strcasecmp_P(XdrvMailbox.topic, PSTR("HttpsWeb")) != 0) {
    return false;
  }

  // External facade pointer is provided via Webserver global in caller context.
  extern TasmotaWebServer *Webserver;

  if (0 == XdrvMailbox.data_len) {
    HttpsFeasibilityRespondStatus();
    return true;
  }

  if (strcasecmp_P(XdrvMailbox.data, PSTR("0")) == 0 ||
      strcasecmp_P(XdrvMailbox.data, PSTR("Off")) == 0 ||
      strcasecmp_P(XdrvMailbox.data, PSTR("Stop")) == 0) {
    const bool was_persisted = Settings->sbflag1.https_webserver;
    Settings->sbflag1.https_webserver = 0;
    HttpsMode = HTTPS_MODE_OFF;
    HttpsFeasibilityStopListener(Webserver);
    if (was_persisted) { SettingsSave(0); }
    HttpsFeasibilityRespondStatus();
    return true;
  }

  if (strcasecmp_P(XdrvMailbox.data, PSTR("1")) == 0 ||
      strcasecmp_P(XdrvMailbox.data, PSTR("Trial")) == 0 ||
      strcasecmp_P(XdrvMailbox.data, PSTR("Start")) == 0) {
    // Trial: do NOT persist. Reboot must not re-enable.
    // Confirmed → Trial demotes persistence first.
    const bool was_persisted = Settings->sbflag1.https_webserver;
    Settings->sbflag1.https_webserver = 0;
    if (was_persisted) { SettingsSave(0); }

    if (HttpsListenerRunning) {
      HttpsFeasibilityStopListener(Webserver);
    }
    HttpsMode = HTTPS_MODE_OFF;

    if (!HttpsFeasibilityStartListener(Webserver)) {
      HttpsMode = HTTPS_MODE_OFF;
      HttpsFeasibilityRespondStatus();
      return true;
    }
    extern void WebServerRegisterRoutesForHttps(void);
    WebServerRegisterRoutesForHttps();
    if (!HttpsFeasibilityBeginListener(Webserver)) {
      HttpsFeasibilityStopListener(Webserver);
      HttpsMode = HTTPS_MODE_OFF;
      HttpsFeasibilityRespondStatus();
      return true;
    }

    HttpsMode = HTTPS_MODE_TRIAL;
    HttpsTrialDeadlineMs = millis() + (HTTPS_FEASIBILITY_TRIAL_SEC * 1000UL);
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: trial active for %u s — confirm with HttpsWeb Confirm"),
           (uint32_t)HTTPS_FEASIBILITY_TRIAL_SEC);
    HttpsFeasibilityRespondStatus();
    return true;
  }

  if (strcasecmp_P(XdrvMailbox.data, PSTR("2")) == 0 ||
      strcasecmp_P(XdrvMailbox.data, PSTR("Confirm")) == 0) {
    if (!HttpsListenerRunning) {
      HttpsFeasibilitySetError("confirm_without_trial");
      AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: Confirm ignored — start a trial first"));
      HttpsFeasibilityRespondStatus();
      return true;
    }
    Settings->sbflag1.https_webserver = 1;
    HttpsMode = HTTPS_MODE_CONFIRMED;
    HttpsTrialDeadlineMs = 0;
    SettingsSave(0);
    AddLog(LOG_LEVEL_INFO, PSTR("HTTPS: confirmed — persisted (factory reset clears)"));
    HttpsFeasibilityRespondStatus();
    return true;
  }

  HttpsFeasibilityRespondStatus();
  return true;
}

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS
