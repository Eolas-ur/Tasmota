/*
  https_feasibility.h - Compile-gated BearSSL HTTPS feasibility helpers (ESP8266).

  Enabled only with -DUSE_WEBSERVER_HTTPS on env:tasmota-https-feasibility.
  Certificates are supplied via an external include path (not tracked in Git).

  Security (M5-00D): env:tasmota-https-feasibility applies a project-local overlay of
  WiFiClientSecureBearSSL.cpp (TLS 1.2 only + ECDHE-ECDSA-AES128-GCM for EC server).
  Stock pinned core still allows TLS 1.0-1.2 and CBC/3DES; ordinary builds are unchanged.
*/

#ifndef HTTPS_FEASIBILITY_H
#define HTTPS_FEASIBILITY_H

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

// Default BearSSL server RX is BR_SSL_BUFSIZE_INPUT (16384+325).
// WiFiServerSecure::setBufferSizes stores raw sizes (no +325/+85 overhead).
#ifndef HTTPS_FEASIBILITY_RX_BUF
#define HTTPS_FEASIBILITY_RX_BUF  4096
#endif
#ifndef HTTPS_FEASIBILITY_TX_BUF
#define HTTPS_FEASIBILITY_TX_BUF  1024
#endif
#ifndef HTTPS_FEASIBILITY_PORT
#define HTTPS_FEASIBILITY_PORT  443
#endif

// Runtime diagnostics (serial AddLog only; no secrets).
#ifndef HTTPS_FEASIBILITY_INSTRUMENT
#define HTTPS_FEASIBILITY_INSTRUMENT  1
#endif

#include <ESP8266WebServerSecure.h>
#include <BearSSLHelpers.h>

#include "https_feasibility_certs.h"

bool HttpsFeasibilityConfigureServer(BearSSL::ESP8266WebServerSecure *server);

#if HTTPS_FEASIBILITY_INSTRUMENT
void HttpsFeasibilityNoteInitHeaps(uint32_t heap_before, uint32_t heap_after);
void HttpsFeasibilityBeforeHandleClient(BearSSL::ESP8266WebServerSecure *server);
void HttpsFeasibilityAfterHandleClient(BearSSL::ESP8266WebServerSecure *server);
bool HttpsFeasibilityCmnd(void);
void HttpsFeasibilityLogBootOnce(void);
#endif

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS

#endif  // HTTPS_FEASIBILITY_H
