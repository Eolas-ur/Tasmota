/*
  https_feasibility.ino - BearSSL HTTPS feasibility configuration (ESP8266).

  Links only when USE_WEBSERVER_HTTPS is defined. Uses core BearSSL
  WiFiServerSecure with ECDSA P-256 and explicit buffer sizes.

  Note: the pinned Arduino-ESP8266 package used here does not expose
  ServerSessions/setCache on WiFiServerSecure; session resumption is therefore
  unavailable without a core upgrade (documented in M5-00B report).
*/

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

#include "tasmota_support/https_feasibility.h"

static BearSSL::X509List *HttpsFeasibilityCert = nullptr;
static BearSSL::PrivateKey *HttpsFeasibilityKey = nullptr;
static bool HttpsFeasibilityReady = false;

bool HttpsFeasibilityConfigureServer(BearSSL::ESP8266WebServerSecure *server) {
  if (server == nullptr) {
    return false;
  }

  if (!HttpsFeasibilityReady) {
    HttpsFeasibilityCert = new BearSSL::X509List(HTTPS_FEASIBILITY_SERVER_CERT);
    HttpsFeasibilityKey = new BearSSL::PrivateKey(HTTPS_FEASIBILITY_SERVER_KEY);
    if ((HttpsFeasibilityCert == nullptr) || (HttpsFeasibilityKey == nullptr)) {
      AddLog(LOG_LEVEL_ERROR, PSTR("HTTPS: cert/key allocation failed"));
      return false;
    }
    HttpsFeasibilityReady = true;
    AddLog(LOG_LEVEL_INFO,
           PSTR("HTTPS: feasibility EC P-256 configured rx=%u tx=%u (no session cache API in core)"),
           (uint32_t)HTTPS_FEASIBILITY_RX_BUF,
           (uint32_t)HTTPS_FEASIBILITY_TX_BUF);
  }

  // Core BearSSL server allocates a secondary stack via stack_thunk_add_ref()
  // in WiFiServerSecure constructors (~5.6–6.7 KB published).
  // Buffer sizes must be set before begin().
  server->getServer().setBufferSizes(HTTPS_FEASIBILITY_RX_BUF, HTTPS_FEASIBILITY_TX_BUF);
  server->getServer().setECCert(
      HttpsFeasibilityCert,
      BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
      HttpsFeasibilityKey);
  return true;
}

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS
