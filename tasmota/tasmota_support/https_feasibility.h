/*
  https_feasibility.h - Compile-gated BearSSL HTTPS feasibility helpers (ESP8266).

  Enabled only with -DUSE_WEBSERVER_HTTPS on env:tasmota-https-feasibility.
  Certificates are supplied via an external include path (not tracked in Git).
*/

#ifndef HTTPS_FEASIBILITY_H
#define HTTPS_FEASIBILITY_H

#ifdef USE_WEBSERVER_HTTPS
#ifdef ESP8266

// Default BearSSL server RX is BR_SSL_BUFSIZE_INPUT (16384+325).
// These values are compile-time knobs for size/RAM experiments; runtime safety
// of reduced RX vs browser record sizes is NOT established by compilation alone.
#ifndef HTTPS_FEASIBILITY_RX_BUF
#define HTTPS_FEASIBILITY_RX_BUF  4096
#endif
#ifndef HTTPS_FEASIBILITY_TX_BUF
#define HTTPS_FEASIBILITY_TX_BUF  1024
#endif
#ifndef HTTPS_FEASIBILITY_PORT
#define HTTPS_FEASIBILITY_PORT  443
#endif

#include <ESP8266WebServerSecure.h>
#include <BearSSLHelpers.h>

// External non-production cert header (build_flags -I .../certs).
#include "https_feasibility_certs.h"

bool HttpsFeasibilityConfigureServer(BearSSL::ESP8266WebServerSecure *server);

#endif  // ESP8266
#endif  // USE_WEBSERVER_HTTPS

#endif  // HTTPS_FEASIBILITY_H
