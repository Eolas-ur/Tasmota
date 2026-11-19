/*
  https_feasibility.h - Compile-gated BearSSL HTTPS feasibility helpers (ESP8266).

  Enabled only with -DUSE_WEBSERVER_HTTPS on env:tasmota-https-feasibility.
  Certificates are supplied via an external include path (not tracked in Git).

  Security (M5-00D): project-local overlay of WiFiClientSecureBearSSL.cpp
  (TLS 1.2 only + ECDHE-ECDSA-AES128-GCM for EC server).

  Trust: certificates are non-production / self-signed. Browsers and strict TLS
  clients will warn or require an explicit trust exception. No public CA chain.
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

// void* avoids Arduino .ino auto-prototype issues with incomplete template types.
bool HttpsFeasibilityConfigureServer(void *webserver);

// Overlay TLS checkpoints (no logging inside BearSSL TU).
extern "C" void HttpsFeasibilityTlsCkpt(uint8_t stage, int32_t detail);
extern "C" int HttpsFeasibilityTlsAcceptErr;

#if HTTPS_FEASIBILITY_INSTRUMENT
void HttpsFeasibilityNoteInitHeaps(uint32_t heap_before, uint32_t heap_after);
void HttpsFeasibilityBeforeHandleClient(void *webserver);
void HttpsFeasibilityAfterHandleClient(void *webserver);
bool HttpsFeasibilityCmnd(void);
void HttpsFeasibilityLogBootOnce(void);
#endif

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS

#endif  // HTTPS_FEASIBILITY_H
