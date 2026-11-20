/*
  https_feasibility.h - Compile-gated BearSSL HTTPS feasibility helpers (ESP8266).

  Enabled only with -DUSE_WEBSERVER_HTTPS on env:tasmota-https-feasibility.
  Certificates are supplied via an external include path (not tracked in Git).

  M5-01A/D: HTTPS is an optional second listener on :443. Plain HTTP on :80 remains
  the default. Runtime activation uses trial/confirm/rollback. Listener teardown is
  deferred while an HTTPS request handler is executing (M5-01D).

  Security (M5-00D): project-local overlay of WiFiClientSecureBearSSL.cpp
  (TLS 1.2 only + ECDHE-ECDSA-AES128-GCM for EC server).

  Trust: certificates are non-production / self-signed. Browsers and strict TLS
  clients will warn or require an explicit trust exception. No public CA chain.

  Reserved (not implemented): HttpRedirectToHttps — default disabled forever until
  a later milestone validates HTTPS reliability.
*/

#ifndef HTTPS_FEASIBILITY_H
#define HTTPS_FEASIBILITY_H

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

#ifndef HTTPS_FEASIBILITY_RX_BUF
#define HTTPS_FEASIBILITY_RX_BUF  4096
#endif
#ifndef HTTPS_FEASIBILITY_TX_BUF
#define HTTPS_FEASIBILITY_TX_BUF  1024
#endif
#ifndef HTTPS_FEASIBILITY_PORT
#define HTTPS_FEASIBILITY_PORT  443
#endif

#ifndef HTTPS_FEASIBILITY_INSTRUMENT
#define HTTPS_FEASIBILITY_INSTRUMENT  1
#endif

#ifndef HTTPS_FEASIBILITY_TRIAL_SEC
#define HTTPS_FEASIBILITY_TRIAL_SEC  300
#endif

#ifndef HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT
#define HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT  3
#endif

#include <ESP8266WebServer.h>
#include <ESP8266WebServerSecure.h>
#include <BearSSLHelpers.h>
#include <WiFiServerSecure.h>

#include "https_feasibility_certs.h"

#if HTTPS_FEASIBILITY_INSTRUMENT
void HttpsFeasibilityOnAcceptBegin(void);
void HttpsFeasibilityOnAcceptEnd(BearSSL::WiFiClientSecure &client);
#endif

// Instrumentable WiFiServerSecure so available() owns TLS lifecycle timing.
class HttpsFeasibilityWiFiServer : public BearSSL::WiFiServerSecure {
public:
  using BearSSL::WiFiServerSecure::WiFiServerSecure;
  using ClientType = BearSSL::WiFiClientSecure;

  BearSSL::WiFiClientSecure available(uint8_t *status = nullptr) {
#if HTTPS_FEASIBILITY_INSTRUMENT
    if (hasClient()) {
      HttpsFeasibilityOnAcceptBegin();
      BearSSL::WiFiClientSecure client = BearSSL::WiFiServerSecure::available(status);
      HttpsFeasibilityOnAcceptEnd(client);
      return client;
    }
#endif
    return BearSSL::WiFiServerSecure::available(status);
  }
};

using HttpsFeasibilityWebServer =
    esp8266webserver::ESP8266WebServerTemplate<HttpsFeasibilityWiFiServer>;

bool HttpsFeasibilityConfigureServer(void *https_webserver);

extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail);
extern "C" int HttpsFeasibilityTlsAcceptErr;
extern "C" int8_t HttpsFeasibilityTlsHsOk;

enum HttpsFeasibilityMode : uint8_t {
  HTTPS_MODE_OFF = 0,
  HTTPS_MODE_TRIAL = 1,
  HTTPS_MODE_CONFIRMED = 2,
};

bool HttpsFeasibilityIsCompiled(void);
bool HttpsFeasibilityIsListenerRunning(void);
uint8_t HttpsFeasibilityGetMode(void);
bool HttpsFeasibilityConfirmedPersisted(void);
bool HttpsFeasibilityShutdownPending(void);

// Call order: StartListener → WebServerRegisterRoutesForHttps → BeginListener.
bool HttpsFeasibilityStartListener(void *facade_webserver);
bool HttpsFeasibilityBeginListener(void *facade_webserver);

// Safe stop: defers destruction while an HTTPS handler is executing.
void HttpsFeasibilityStopListener(void *facade_webserver);
void HttpsFeasibilitySuspendForManager(void *facade_webserver);
void HttpsFeasibilityNoteBootFailure(void *facade_webserver);
void HttpsFeasibilityProcessDeferred(void *facade_webserver);

bool HttpsFeasibilityCmnd(void);
void HttpsFeasibilityEverySecond(void *facade_webserver);
void HttpsFeasibilityOnSettingsDefault(void);

#if HTTPS_FEASIBILITY_INSTRUMENT
void HttpsFeasibilityNoteInitHeaps(uint32_t heap_before, uint32_t heap_after);
void HttpsFeasibilityBeforeHandleClient(void *https_webserver);
void HttpsFeasibilityAfterHandleClient(void *https_webserver);
void HttpsFeasibilityLogBootOnce(void);
#endif

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS

#endif  // HTTPS_FEASIBILITY_H
