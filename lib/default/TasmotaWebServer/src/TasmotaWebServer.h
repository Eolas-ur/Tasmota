/*
  TasmotaWebServer.h - lib/default/TasmotaWebServer/library.json

  Copyright (C) 2021  Theo Arends & Stephan Hadinger

  This library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __TASMOTA_WEBSERVER__
#define __TASMOTA_WEBSERVER__

#ifdef ESP8266
#include <ESP8266WebServer.h>

#ifdef USE_WEBSERVER_HTTPS
#include "tasmota_support/https_feasibility.h"

class TasmotaHttpWebServer : public ESP8266WebServer
{
public:
  TasmotaHttpWebServer(int port) : ESP8266WebServer(port) {}
  bool isChunked(void) const { return _chunked; }
  // Reference to the live request client (no copy / no slicing).
  WiFiClient &activeClient(void) { return _currentClient; }
};

class TasmotaHttpsWebServer : public HttpsFeasibilityWebServer
{
public:
  TasmotaHttpsWebServer(int port) : HttpsFeasibilityWebServer(port) {}
  bool isChunked(void) const { return _chunked; }
  // WiFiClientSecure is-a WiFiClient; returning a base reference preserves vtable.
  WiFiClient &activeClient(void) { return _currentClient; }
  BearSSL::WiFiClientSecure activeClientSecureCopy(void) {
    return _currentClient;  // WiFiClientSecure copy ctor keeps TLS shared state
  }
};

enum TasmotaWebRouteTarget : uint8_t {
  TASMOTA_WEB_ROUTE_HTTP = 0,   // register on HTTP only
  TASMOTA_WEB_ROUTE_HTTPS = 1,  // register on HTTPS only
  TASMOTA_WEB_ROUTE_BOTH = 2,   // register on whichever listeners exist
};

/*
  M5-01B facade: HTTP + optional HTTPS.
  client() returns WiFiClient& to the live request client so virtual write/flush/stop
  use BearSSL when serving HTTPS. Callers must not assign into a WiFiClient value
  object while httpsServing() — that slices TLS state; use client() reference or
  clientSecureCopy() instead.
*/
class TasmotaWebServer
{
public:
  explicit TasmotaWebServer(int port = 80) {
    _http = new TasmotaHttpWebServer(port);
    _owns_http = true;
  }
  ~TasmotaWebServer(void) {
    if (_owns_http) {
      delete _http;
      _http = nullptr;
    }
  }

  void attachHttp(TasmotaHttpWebServer *server) {
    if (_owns_http) {
      delete _http;
      _owns_http = false;
    }
    _http = server;
  }
  void attachHttps(TasmotaHttpsWebServer *server) { _https = server; }
  TasmotaHttpWebServer *httpServer(void) const { return _http; }
  TasmotaHttpsWebServer *httpsServer(void) const { return _https; }
  void setHttpsServing(bool on) { _https_serving = on && (_https != nullptr); }
  bool httpsServing(void) const { return _https_serving; }
  void setRouteTarget(TasmotaWebRouteTarget target) { _route_target = target; }
  TasmotaWebRouteTarget routeTarget(void) const { return _route_target; }

  void begin(void) { if (_http) { _http->begin(); } }
  void close(void) { if (_http) { _http->close(); } }

  void handleClient(void) {
    if (_https_serving) {
      if (_https) { _https->handleClient(); }
    } else if (_http) {
      _http->handleClient();
    }
  }

  void collectHeaders(const char *headerKeys[], const size_t headerKeysCount) {
    if (_http) { _http->collectHeaders(headerKeys, headerKeysCount); }
    if (_https) { _https->collectHeaders(headerKeys, headerKeysCount); }
  }

  void onNotFound(ESP8266WebServer::THandlerFunction fn) {
    if (_route_http()) { _http->onNotFound(fn); }
    if (_route_https()) { _https->onNotFound(fn); }
  }

  void on(const Uri &uri, ESP8266WebServer::THandlerFunction fn) {
    on(uri, HTTP_ANY, fn);
  }
  void on(const Uri &uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn) {
    if (_route_http()) { _http->on(uri, method, fn); }
    if (_route_https()) { _https->on(uri, method, fn); }
  }
  void on(const Uri &uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn, ESP8266WebServer::THandlerFunction ufn) {
    if (_route_http()) { _http->on(uri, method, fn, ufn); }
    if (_route_https()) { _https->on(uri, method, fn, ufn); }
  }
  void on(const char *uri, ESP8266WebServer::THandlerFunction fn) { on(Uri(uri), fn); }
  void on(const char *uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn) { on(Uri(uri), method, fn); }
  void on(const char *uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn, ESP8266WebServer::THandlerFunction ufn) {
    on(Uri(uri), method, fn, ufn);
  }
  void on(const String &uri, ESP8266WebServer::THandlerFunction fn) { on(Uri(uri), fn); }
  void on(const String &uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn) { on(Uri(uri), method, fn); }
  void on(const String &uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn, ESP8266WebServer::THandlerFunction ufn) {
    on(Uri(uri), method, fn, ufn);
  }
  void on(const __FlashStringHelper *uri, ESP8266WebServer::THandlerFunction fn) { on(String(uri), fn); }
  void on(const __FlashStringHelper *uri, HTTPMethod method, ESP8266WebServer::THandlerFunction fn) {
    on(String(uri), method, fn);
  }

  // RequestHandler<ServerType> is not shareable across HTTP/HTTPS templates.
  // Skip when targeting HTTPS-only so FUNC_WEB_ADD_HANDLER rebind does not
  // duplicate HTTP addHandler registrations.
  void addHandler(RequestHandler *handler) {
    if (_route_target == TASMOTA_WEB_ROUTE_HTTPS) { return; }
    if (_http) { _http->addHandler(handler); }
  }
  void enableCORS(bool enable) {
    if (_http) { _http->enableCORS(enable); }
    if (_https) { _https->enableCORS(enable); }
  }
  void serveStatic(const char *uri, fs::FS &fs, const char *path) {
    if (_http) { _http->serveStatic(uri, fs, path); }
    if (_https) { _https->serveStatic(uri, fs, path); }
  }

  bool hasArg(const String &name) const {
    return _https_serving ? _https->hasArg(name) : _http->hasArg(name);
  }
  bool hasArg(const __FlashStringHelper *name) const {
    return _https_serving ? _https->hasArg(name) : _http->hasArg(name);
  }
  String arg(const String &name) const {
    return _https_serving ? _https->arg(name) : _http->arg(name);
  }
  String arg(int i) const {
    return _https_serving ? _https->arg(i) : _http->arg(i);
  }
  String arg(const __FlashStringHelper *name) const {
    return _https_serving ? _https->arg(name) : _http->arg(name);
  }
  String argName(int i) const {
    return _https_serving ? _https->argName(i) : _http->argName(i);
  }
  int args(void) const {
    return _https_serving ? _https->args() : _http->args();
  }
  String header(const String &name) const {
    return _https_serving ? _https->header(name) : _http->header(name);
  }
  String hostHeader(void) const {
    return _https_serving ? _https->hostHeader() : _http->hostHeader();
  }
  String uri(void) const {
    return _https_serving ? _https->uri() : _http->uri();
  }
  HTTPMethod method(void) const {
    return _https_serving ? _https->method() : _http->method();
  }

  // Live client reference — preserves WiFiClientSecure vtable when HTTPS.
  WiFiClient &client(void) {
    if (_https_serving) { return _https->activeClient(); }
    return _http->activeClient();
  }

  // Proper TLS-preserving copy for long-lived streaming (filesystem download, etc.).
  BearSSL::WiFiClientSecure clientSecureCopy(void) {
    return _https->activeClientSecureCopy();
  }

  size_t clientWrite(const uint8_t *buf, size_t size) {
    return client().write(buf, size);
  }
  void clientFlush(void) { client().flush(); }
  void clientStop(void) { client().stop(); }

  HTTPUpload &upload(void) {
    if (_https_serving) { return _https->upload(); }
    return _http->upload();
  }

  bool authenticate(const char *username, const char *password) {
    if (_https_serving) { return _https->authenticate(username, password); }
    return _http->authenticate(username, password);
  }
  void requestAuthentication(void) {
    if (_https_serving) { _https->requestAuthentication(); }
    else { _http->requestAuthentication(); }
  }

  void send(int code, const char *content_type = nullptr, const String &content = String("")) {
    if (_https_serving) { _https->send(code, content_type, content); }
    else { _http->send(code, content_type, content); }
  }
  void send(int code, char *content_type, const String &content) {
    if (_https_serving) { _https->send(code, content_type, content); }
    else { _http->send(code, content_type, content); }
  }
  void send(int code, const String &content_type, const String &content) {
    if (_https_serving) { _https->send(code, content_type, content); }
    else { _http->send(code, content_type, content); }
  }
  void send_P(int code, PGM_P content_type, PGM_P content) {
    if (_https_serving) { _https->send_P(code, content_type, content); }
    else { _http->send_P(code, content_type, content); }
  }
  void sendContent(const String &content) {
    if (_https_serving) { _https->sendContent(content); }
    else { _http->sendContent(content); }
  }
  void sendContent(const char *content, size_t size) {
    if (_https_serving) { _https->sendContent(content, size); }
    else { _http->sendContent(content, size); }
  }
  void sendContent_P(PGM_P content) {
    if (_https_serving) { _https->sendContent_P(content); }
    else { _http->sendContent_P(content); }
  }
  void sendHeader(const String &name, const String &value, bool first = false) {
    if (_https_serving) { _https->sendHeader(name, value, first); }
    else { _http->sendHeader(name, value, first); }
  }
  void setContentLength(const size_t contentLength) {
    if (_https_serving) { _https->setContentLength(contentLength); }
    else { _http->setContentLength(contentLength); }
  }

  bool isChunked(void) const {
    if (_https_serving) { return _https->isChunked(); }
    return _http ? _http->isChunked() : false;
  }

private:
  bool _route_http(void) const {
    return _http && (_route_target == TASMOTA_WEB_ROUTE_HTTP || _route_target == TASMOTA_WEB_ROUTE_BOTH);
  }
  bool _route_https(void) const {
    return _https && (_route_target == TASMOTA_WEB_ROUTE_HTTPS || _route_target == TASMOTA_WEB_ROUTE_BOTH);
  }

  TasmotaHttpWebServer *_http = nullptr;
  TasmotaHttpsWebServer *_https = nullptr;
  bool _https_serving = false;
  bool _owns_http = false;
  TasmotaWebRouteTarget _route_target = TASMOTA_WEB_ROUTE_BOTH;
};

#else  // !USE_WEBSERVER_HTTPS

class TasmotaWebServer : public ESP8266WebServer
{
public:
  TasmotaWebServer(int port) : ESP8266WebServer(port) {}
  bool isChunked(void) const { return _chunked; }
  // Match facade semantics: reference to live client (no temporary copy).
  WiFiClient &client(void) { return _currentClient; }
};

#endif  // USE_WEBSERVER_HTTPS
#endif  // ESP8266

#ifdef ESP32
#include <WebServer.h>
#include "libb64/cencode.h"

class TasmotaWebServer : public WebServer
{
public:
  TasmotaWebServer(int port) :WebServer(port)
  {
  }

  bool isChunked(void) const { return _chunked; }

  bool authenticate(const char *username, const char *password) {
    String auth = header(F("Authorization"));
    if (!auth.startsWith(F("Basic "))) { return false; }
    auth.remove(0, 6);
    auth.trim();

    String credentials = username;
    credentials += ':';
    credentials += password;
    char *encoded = (char*)malloc(base64_encode_expected_len(credentials.length()) + 1);
    if (encoded == nullptr) { return false; }
    base64_encode_chars(credentials.c_str(), credentials.length(), encoded);
    bool ok = auth.equalsConstantTime(encoded);
    free(encoded);
    return ok;
  }

  void requestAuthentication(void) {
    sendHeader(F("WWW-Authenticate"), F("Basic realm=\"Login Required\""));
    send(401, "text/html", "");
  }
};
#endif // ESP32

#endif // __TASMOTA_WEBSERVER__
