#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
inline int closesocket(int s) { return ::close(s); }
#endif

#include "../src/actions.hpp"
#include "../src/api/api_router.hpp"
#include "../src/core/json_lite.hpp"
#include "../src/geo_dns.hpp"
#include "../src/history_store.hpp"
#include "../src/mmdb_reader.hpp"
#include "../src/net_monitor.hpp"
#include "../src/network/interface_monitor.hpp"
#include "../src/quality/network_quality_engine.hpp"
#include "../src/security/audit_log.hpp"
#include "../src/security/auth_manager.hpp"
#include "../src/security/rate_limiter.hpp"
#include "../src/security/tls_context.hpp"
#include "../src/serializer.hpp"
#include "../src/service_monitor.hpp"
#include "../src/settings_store.hpp"
#include "../src/storage/sqlite_db.hpp"
#include "../src/traceroute.hpp"
#include <chrono>
#include "../src/updater.hpp"
#include "../src/ws_server.hpp"

#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace netpulse;

#define CHECK(cond)                                                              \
  do {                                                                           \
    if (!(cond)) {                                                               \
      std::cerr << "FAIL at line " << __LINE__ << ": " << #cond << "\n";         \
      return 1;                                                                  \
    }                                                                            \
  } while (0)

namespace {

std::string sendRawHttp(uint16_t port, const std::string& rawReq) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return {};
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    closesocket(s);
    return {};
  }
  size_t off = 0;
  while (off < rawReq.size()) {
    int n = send(s, rawReq.data() + off, static_cast<int>(rawReq.size() - off), 0);
    if (n <= 0) break;
    off += static_cast<size_t>(n);
  }
  std::string resp;
  char buf[4096];
  while (true) {
    int n = recv(s, buf, sizeof(buf), 0);
    if (n <= 0) break;
    resp.append(buf, static_cast<size_t>(n));
  }
  closesocket(s);
  return resp;
}

std::string extractCookieSession(const std::string& httpResp) {
  size_t pos = httpResp.find("Set-Cookie: np_session=");
  if (pos == std::string::npos) return {};
  pos += 23;
  size_t end = httpResp.find(';', pos);
  if (end == std::string::npos) end = httpResp.find("\r\n", pos);
  return httpResp.substr(pos, end - pos);
}

std::string extractJsonBody(const std::string& httpResp) {
  size_t pos = httpResp.find("\r\n\r\n");
  return (pos == std::string::npos) ? std::string{} : httpResp.substr(pos + 4);
}

} // namespace

int testIpClassification() {
  CHECK(classifyIpString("127.0.0.1") == IpScope::Loopback);
  CHECK(classifyIpString("192.168.15.2") == IpScope::Lan);
  CHECK(classifyIpString("10.20.30.40") == IpScope::Lan);
  CHECK(classifyIpString("172.16.5.1") == IpScope::Lan);
  CHECK(classifyIpString("172.31.255.254") == IpScope::Lan);
  CHECK(classifyIpString("172.32.0.1") == IpScope::Public);
  CHECK(classifyIpString("8.8.8.8") == IpScope::Public);
  CHECK(classifyIpString("0.0.0.0") == IpScope::Unknown);

  CHECK(classifyIpString("::1") == IpScope::Loopback);
  CHECK(classifyIpString("::") == IpScope::Unknown);
  CHECK(classifyIpString("fe80::1") == IpScope::Lan);
  CHECK(classifyIpString("fc00::dead:beef") == IpScope::Lan);
  CHECK(classifyIpString("2606:4700:4700::1111") == IpScope::Public);
  CHECK(classifyIpString("::ffff:192.168.1.5") == IpScope::Lan);
  CHECK(classifyIpString("::ffff:8.8.4.4") == IpScope::Public);
  CHECK(normalizeIpForGeo("::ffff:8.8.4.4") == "8.8.4.4");
  std::cout << "[PASS] testIpClassification\n";
  return 0;
}

int testGeoJsonAndCache() {
  const std::string batch = R"([
    {"status":"success","country":"Brazil","countryCode":"BR","regionName":"Sao Paulo","city":"Sao Paulo","lat":-23.5505,"lon":-46.6333,"isp":"Vivo \"Fibra\"","org":"Telefonica","as":"AS27699","query":"177.10.20.30"},
    {"status":"fail","query":"127.0.0.1"}
  ])";
  auto res = parseIpApiBatchJson(batch);
  CHECK(res.size() == 2);
  CHECK(res[0].first == "177.10.20.30");
  CHECK(res[0].second.resolved);
  CHECK(res[0].second.countryCode == "BR");
  CHECK(res[0].second.isp == "Vivo \"Fibra\"");
  CHECK(std::abs(res[0].second.lat - (-23.5505)) < 1e-4);
  CHECK(std::abs(res[0].second.lon - (-46.6333)) < 1e-4);
  CHECK(!res[1].second.resolved && res[1].second.failed);

  const std::string selfBody = R"({"status":"success","country":"Brazil","countryCode":"BR","regionName":"SP","city":"Campinas","lat":-22.90,"lon":-47.06,"isp":"Claro","query":"200.1.2.3"})";
  HostGeo hg = parseIpApiSelfJson(selfBody);
  CHECK(hg.resolved);
  CHECK(hg.city == "Campinas");
  CHECK(hg.publicIp == "200.1.2.3");

  auto tempCache = std::filesystem::temp_directory_path() / "netpulse_test_geo_cache.tsv";
  std::error_code ec;
  std::filesystem::remove(tempCache, ec);
  {
    std::ofstream out(tempCache);
    out << "8.8.8.8\tUnited States\tUS\tVirginia\tAshburn\t39.03\t-77.5\tGoogle LLC\tGoogle Public DNS\tAS15169\n";
  }
  GeoDnsService svc(tempCache);
  auto g = svc.getGeo("8.8.8.8");
  CHECK(g.has_value());
  CHECK(g->city == "Ashburn");
  CHECK(std::abs(g->lon - (-77.5)) < 1e-4);
  std::filesystem::remove(tempCache, ec);

  std::cout << "[PASS] testGeoJsonAndCache\n";
  return 0;
}

int testWebSocketRfc6455() {
  std::string accept = computeWebSocketAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
  CHECK(accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

  auto smallFrame = encodeWebSocketFrame(0x1, "hello");
  CHECK(smallFrame.size() == 7);
  CHECK(smallFrame[0] == 0x81);
  CHECK(smallFrame[1] == 5);

  std::string big(300, 'A');
  auto medFrame = encodeWebSocketFrame(0x1, big);
  CHECK(medFrame.size() == 4 + 300);
  CHECK(medFrame[0] == 0x81);
  CHECK(medFrame[1] == 126);
  CHECK(((static_cast<uint16_t>(medFrame[2]) << 8) | medFrame[3]) == 300);

  CHECK(!isSafeRelativeSubpath("../secret"));
  CHECK(!isSafeRelativeSubpath("%2e%2e/secret"));
  CHECK(!isSafeRelativeSubpath("foo\\bar"));
  CHECK(!isSafeRelativeSubpath("foo%00bar"));
  CHECK(isSafeRelativeSubpath("index.html"));
  CHECK(isSafeRelativeSubpath("countries-110m.json"));

  std::cout << "[PASS] testWebSocketRfc6455\n";
  return 0;
}

int testJsonLiteParser() {
  JsonValue v;
  std::string err;
  const std::string validJson = R"({"name":"Api \"1\"","port":8443,"ok":true,"lat":-23.5,"arr":[1,2]})";
  CHECK(JsonValue::parse(validJson, v, err));
  CHECK(v.isObject());
  CHECK(v.getString("name") == "Api \"1\"");
  CHECK(v.getInt("port") == 8443);
  CHECK(v.getBool("ok") == true);
  CHECK(std::abs(v.getDouble("lat") - (-23.5)) < 1e-6);
  CHECK(v.get("arr") && v.get("arr")->asArray().size() == 2);

  // Reject malformed / trailing / too-deep JSON
  const std::string trailingJson = R"({"a":1} trailing)";
  CHECK(!JsonValue::parse(trailingJson, v, err));
  CHECK(!JsonValue::parse("{\"a\":\"\x01\"}", v, err));
  std::string deep(40, '[');
  deep += std::string(40, ']');
  CHECK(!JsonValue::parse(deep, v, err));

  std::cout << "[PASS] testJsonLiteParser\n";
  return 0;
}

int testAuthManagerAndRbac() {
  auto dir = std::filesystem::temp_directory_path() / "netpulse_auth_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);

  AuthManager auth(dir, "np_adm_test_master_secret_123456");
  CHECK(AuthManager::constantTimeEquals("abc123", "abc123"));
  CHECK(!AuthManager::constantTimeEquals("abc123", "abc124"));
  CHECK(!AuthManager::constantTimeEquals("abc", "abcd"));

  // Login with admin token
  auto admSess = auth.loginWithToken("np_adm_test_master_secret_123456", "127.0.0.1");
  CHECK(admSess.has_value());
  CHECK(admSess->role == Role::Administrator);

  // Create Viewer & Operator tokens
  std::string vwrTok, oprTok;
  ApiTokenRecord vwrRec, oprRec;
  CHECK(auth.createApiToken("tv-monitor", Role::Viewer, 0, vwrTok, vwrRec));
  CHECK(auth.createApiToken("ops-user", Role::Operator, 0, oprTok, oprRec));

  auto vwrCtx = auth.authenticateHttp("Bearer " + vwrTok, "", "", true);
  CHECK(vwrCtx.authenticated && vwrCtx.role == Role::Viewer && vwrCtx.csrfValid);
  CHECK(hasRole(vwrCtx.role, Role::Viewer));
  CHECK(!hasRole(vwrCtx.role, Role::Operator));
  CHECK(!hasRole(vwrCtx.role, Role::Administrator));

  auto oprCtx = auth.authenticateHttp("Bearer " + oprTok, "", "", true);
  CHECK(oprCtx.authenticated && oprCtx.role == Role::Operator);
  CHECK(hasRole(oprCtx.role, Role::Operator));
  CHECK(!hasRole(oprCtx.role, Role::Administrator));

  // Cookie CSRF check
  auto badCsrf = auth.authenticateHttp("", "np_session=" + admSess->sessionId, "wrong-csrf", true);
  CHECK(badCsrf.authenticated && !badCsrf.csrfValid);
  auto goodCsrf = auth.authenticateHttp("", "np_session=" + admSess->sessionId, admSess->csrfToken, true);
  CHECK(goodCsrf.authenticated && goodCsrf.csrfValid);

  // Single-use launch nonce (loopback only)
  std::string nonce = auth.issueLocalLaunchNonce();
  CHECK(!auth.exchangeLaunchNonce(nonce, "192.168.1.50").has_value());
  // Nonce rejected on remote IP, still check fresh nonce on loopback
  std::string nonce2 = auth.issueLocalLaunchNonce();
  CHECK(auth.exchangeLaunchNonce(nonce2, "127.0.0.1").has_value());
  CHECK(!auth.exchangeLaunchNonce(nonce2, "127.0.0.1").has_value()); // single-use

  // Revoke viewer token -> sessions/tokens rejected
  CHECK(auth.revokeApiToken(vwrRec.id));
  CHECK(!auth.authenticateHttp("Bearer " + vwrTok, "", "", false).authenticated);

  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testAuthManagerAndRbac\n";
  return 0;
}

int testRateLimiterAndAuditLog() {
  RateLimiter rl(3, 10000, 30000);
  CHECK(rl.check("10.0.0.5", 1000).allowed);
  CHECK(rl.check("10.0.0.5", 1001).allowed);
  CHECK(rl.check("10.0.0.5", 1002).allowed);
  auto blocked = rl.check("10.0.0.5", 1003);
  CHECK(!blocked.allowed && blocked.retryAfterSec >= 1);
  rl.reset("10.0.0.5");
  CHECK(rl.check("10.0.0.5", 1004).allowed);

  auto dir = std::filesystem::temp_directory_path() / "netpulse_audit_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  {
    AuditLog log(dir / "audit.tsv");
    uint64_t id = log.record("admin", "administrator", "127.0.0.1", "firewall.block_ip", "1.2.3.4",
                             "allowed", "Regra aplicada", true);
    CHECK(id > 0);
    CHECK(log.markTargetReverted("firewall.block_ip", "1.2.3.4"));
  }
  {
    AuditLog log2(dir / "audit.tsv");
    auto list = log2.recent(10);
    CHECK(list.size() == 1);
    CHECK(list[0].target == "1.2.3.4");
    CHECK(list[0].reverted == true);
  }
  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testRateLimiterAndAuditLog\n";
  return 0;
}

int testLiveSecurityHttpAndWsIntegration() {
  auto tempRoot = std::filesystem::temp_directory_path() / "netpulse_sec_int_test";
  std::error_code ec;
  std::filesystem::remove_all(tempRoot, ec);
  std::filesystem::create_directories(tempRoot / "static", ec);
  std::filesystem::create_directories(tempRoot / "assets", ec);
  std::filesystem::create_directories(tempRoot / "data", ec);
  {
    std::ofstream idx(tempRoot / "static" / "index.html");
    idx << "<html><body>NetPulse</body></html>";
  }

  NetMonitor mon;
  auto snap = mon.poll(1700000000000ULL);
  CHECK(snap.pollLatencyUs < 500000);

  AuthManager auth(tempRoot / "data", "np_adm_integration_secret_987654");
  std::string viewerTok;
  ApiTokenRecord vRec;
  CHECK(auth.createApiToken("viewer-1", Role::Viewer, 0, viewerTok, vRec));

  AuditLog audit(tempRoot / "data" / "audit.tsv");
  RateLimiter authLimiter(10, 60000, 60000);
  GeoDnsService geoDns(tempRoot / "data" / "geo.tsv");
  ServiceMonitor svcMon(tempRoot / "data" / "svc.tsv");
  SettingsStore settings(tempRoot / "data" / "settings.tsv");
  HistoryStore history(tempRoot / "data");
  TracerouteService tracer(geoDns, &history);
  NetworkQualityEngine quality(history);
  InterfaceMonitor ifMon(&history);
  UpdateManager updater("1.3.0", nullptr);

  std::string snapJson = serializeSnapshotJson(snap, geoDns, 1000, 0, &svcMon);
  ApiRouter router(ApiDependencies{
      auth, audit, authLimiter, svcMon, tracer, settings, history, updater,
      tempRoot / "data", false, false,
      [&]() { return snapJson; },
      nullptr, nullptr, &quality, &ifMon,
  });

  WsServer server(0, tempRoot / "static", tempRoot / "assets");
  server.setLatestSnapshotJson(snapJson);
  server.setHealthCallback([]() { return std::string("{\"status\":\"ok\",\"authRequired\":true}"); });
  server.setWsAuthCallback([&](const HttpRequest& r) { return router.handleWsAuth(r); });
  server.setApiCallback([&](const HttpRequest& r) { return router.handleHttp(r); });
  CHECK(server.start());
  const uint16_t port = server.port();
  const std::string hostHdr = "127.0.0.1:" + std::to_string(port);

  // 1. Public health check works and has no wildcard CORS
  std::string healthResp = sendRawHttp(port, "GET /api/health HTTP/1.1\r\nHost: " + hostHdr + "\r\n\r\n");
  CHECK(healthResp.find("200 OK") != std::string::npos);
  CHECK(healthResp.find("Access-Control-Allow-Origin: *") == std::string::npos);
  CHECK(healthResp.find("X-Content-Type-Options: nosniff") != std::string::npos);

  // 2. Unauthenticated API & destructive calls rejected with 401
  CHECK(sendRawHttp(port, "GET /api/snapshot HTTP/1.1\r\nHost: " + hostHdr + "\r\n\r\n")
            .find("401 Unauthorized") != std::string::npos);
  CHECK(sendRawHttp(port, "POST /api/action/kill-process HTTP/1.1\r\nHost: " + hostHdr + "\r\nContent-Length: 2\r\n\r\n{}")
            .find("401 Unauthorized") != std::string::npos);

  // 3. Path traversal blocked
  CHECK(sendRawHttp(port, "GET /%2e%2e/data/audit.tsv HTTP/1.1\r\nHost: " + hostHdr + "\r\n\r\n")
            .find("403 Forbidden") != std::string::npos);

  // 4. Cross-origin & DNS rebinding Host rejected
  CHECK(sendRawHttp(port, "GET /api/health HTTP/1.1\r\nHost: evil.attacker.local\r\n\r\n")
            .find("403 Forbidden") != std::string::npos);
  CHECK(sendRawHttp(port, "POST /api/auth/login HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nOrigin: https://evil.example\r\nContent-Length: 2\r\n\r\n{}")
            .find("403 Forbidden") != std::string::npos);

  // 5. Login as Viewer -> Cookie + CSRF token
  std::string loginBody = "{\"token\":\"" + viewerTok + "\"}";
  std::string loginResp = sendRawHttp(
      port,
      "POST /api/auth/login HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nContent-Type: application/json\r\nContent-Length: " +
          std::to_string(loginBody.size()) + "\r\n\r\n" + loginBody);
  CHECK(loginResp.find("200 OK") != std::string::npos);
  std::string viewerCookie = extractCookieSession(loginResp);
  CHECK(!viewerCookie.empty());
  JsonValue loginJson;
  std::string jerr;
  CHECK(JsonValue::parse(extractJsonBody(loginResp), loginJson, jerr));
  std::string viewerCsrf = loginJson.getString("csrfToken");
  CHECK(!viewerCsrf.empty());

  // 6. Viewer can read snapshot, but CANNOT add service (403 RBAC)
  CHECK(sendRawHttp(port, "GET /api/snapshot HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nCookie: np_session=" + viewerCookie + "\r\n\r\n")
            .find("200 OK") != std::string::npos);

  std::string addSvc = R"({"name":"Test","host":"1.1.1.1","port":443})";
  CHECK(sendRawHttp(port, "POST /api/services/add HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nCookie: np_session=" + viewerCookie +
                              "\r\nX-CSRF-Token: " + viewerCsrf +
                              "\r\nContent-Length: " + std::to_string(addSvc.size()) + "\r\n\r\n" + addSvc)
            .find("403 Forbidden") != std::string::npos);

  // 7. Cookie-based Admin request WITHOUT CSRF header -> 403
  std::string admLoginBody = R"({"token":"np_adm_integration_secret_987654"})";
  std::string admLoginResp = sendRawHttp(
      port,
      "POST /api/auth/login HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nContent-Length: " + std::to_string(admLoginBody.size()) + "\r\n\r\n" + admLoginBody);
  CHECK(admLoginResp.find("200 OK") != std::string::npos);
  std::string admCookie = extractCookieSession(admLoginResp);
  JsonValue admJson;
  CHECK(JsonValue::parse(extractJsonBody(admLoginResp), admJson, jerr));
  std::string admCsrf = admJson.getString("csrfToken");

  std::string killNoConfirm = R"({"pid":4,"proc":"System"})";
  CHECK(sendRawHttp(port, "POST /api/action/kill-process HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nCookie: np_session=" + admCookie +
                              "\r\nContent-Length: " + std::to_string(killNoConfirm.size()) + "\r\n\r\n" + killNoConfirm)
            .find("403 Forbidden") != std::string::npos);

  // 8. Admin destructive call WITHOUT confirm:true -> 400 confirmation_required
  CHECK(sendRawHttp(port, "POST /api/action/kill-process HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nCookie: np_session=" + admCookie +
                              "\r\nX-CSRF-Token: " + admCsrf +
                              "\r\nContent-Length: " + std::to_string(killNoConfirm.size()) + "\r\n\r\n" + killNoConfirm)
            .find("confirmation_required") != std::string::npos);

  // 9. Admin killing protected PID 4 WITH confirm:true -> 400 protected + audited
  std::string killConfirm = R"({"pid":4,"proc":"System","confirm":true})";
  CHECK(sendRawHttp(port, "POST /api/action/kill-process HTTP/1.1\r\nHost: " + hostHdr +
                              "\r\nCookie: np_session=" + admCookie +
                              "\r\nX-CSRF-Token: " + admCsrf +
                              "\r\nContent-Length: " + std::to_string(killConfirm.size()) + "\r\n\r\n" + killConfirm)
            .find("terminate_failed") != std::string::npos);

  std::string auditResp = sendRawHttp(port, "GET /api/v1/security/audit HTTP/1.1\r\nHost: " + hostHdr +
                                                "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(auditResp.find("200 OK") != std::string::npos);
  CHECK(auditResp.find("process.terminate") != std::string::npos);

  // 10. Unauthenticated WebSocket rejected with 401
  std::string unauthWs = sendRawHttp(
      port,
      "GET /ws HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
  CHECK(unauthWs.find("401 Unauthorized") != std::string::npos);

  // 11. Authenticated WebSocket via single-use ticket -> 101 + snapshot frame
  std::string ticketResp = sendRawHttp(
      port,
      "POST /api/auth/ws-ticket HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf + "\r\nContent-Length: 0\r\n\r\n");
  JsonValue ticketJson;
  CHECK(JsonValue::parse(extractJsonBody(ticketResp), ticketJson, jerr));
  std::string ticket = ticketJson.getString("ticket");
  CHECK(!ticket.empty());

  SOCKET ws = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(ws != INVALID_SOCKET);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  CHECK(connect(ws, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
  const std::string wsReq =
      "GET /ws?ticket=" + ticket + " HTTP/1.1\r\n"
      "Host: " + hostHdr + "\r\n"
      "Origin: http://" + hostHdr + "\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n";
  send(ws, wsReq.data(), static_cast<int>(wsReq.size()), 0);
  std::string wsResp;
  char wbuf[4096];
  for (int attempt = 0; attempt < 10; ++attempt) {
    int r = recv(ws, wbuf, sizeof(wbuf), 0);
    if (r <= 0) break;
    wsResp.append(wbuf, static_cast<size_t>(r));
    if (wsResp.find("\r\n\r\n") != std::string::npos && wsResp.size() > wsResp.find("\r\n\r\n") + 6) {
      break;
    }
  }
  CHECK(wsResp.find("101 Switching Protocols") != std::string::npos);
  size_t hdrEnd = wsResp.find("\r\n\r\n") + 4;
  CHECK(wsResp.size() > hdrEnd + 2);
  CHECK(static_cast<uint8_t>(wsResp[hdrEnd]) == 0x81);
  closesocket(ws);

  // 12. Fase 1 History & Analytics API + RBAC + confirm guard
  std::string storResp = sendRawHttp(
      port,
      "GET /api/v1/history/storage HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(storResp.find("200 OK") != std::string::npos);
  CHECK(storResp.find("\"engine\":\"sqlite3\"") != std::string::npos);

  std::string anaResp = sendRawHttp(
      port,
      "GET /api/v1/history/analytics?range=7d HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(anaResp.find("200 OK") != std::string::npos);
  CHECK(anaResp.find("\"topProcesses\":") != std::string::npos);

  std::string connHistResp = sendRawHttp(
      port,
      "GET /api/v1/history/connections?limit=5 HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(connHistResp.find("200 OK") != std::string::npos);
  CHECK(connHistResp.find("\"items\":") != std::string::npos);

  std::string procHistResp = sendRawHttp(
      port,
      "GET /api/v1/history/processes?range=24h HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(procHistResp.find("200 OK") != std::string::npos);

  const std::string emptyJson = "{}";
  std::string viewerPrune = sendRawHttp(
      port,
      "POST /api/v1/history/prune HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf +
          "\r\nContent-Length: " + std::to_string(emptyJson.size()) + "\r\n\r\n" + emptyJson);
  CHECK(viewerPrune.find("403 Forbidden") != std::string::npos);

  std::string admPruneNoConfirm = sendRawHttp(
      port,
      "POST /api/v1/history/prune HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(emptyJson.size()) + "\r\n\r\n" + emptyJson);
  CHECK(admPruneNoConfirm.find("confirmation_required") != std::string::npos);

  const std::string confirmJson = R"({"confirm":true})";
  std::string admPruneOk = sendRawHttp(
      port,
      "POST /api/v1/history/prune HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(confirmJson.size()) + "\r\n\r\n" + confirmJson);
  CHECK(admPruneOk.find("200 OK") != std::string::npos);

  // 13. Fase 2 Network Quality Engine endpoints + RBAC + confirm guard
  std::string qStatResp = sendRawHttp(
      port,
      "GET /api/v1/quality/status HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(qStatResp.find("200 OK") != std::string::npos);
  CHECK(qStatResp.find("\"overallHealth\":") != std::string::npos);

  const std::string addTargetBody = R"({"name":"Custom DNS","host":"1.1.1.1","probeMode":"dns","port":53,"intervalSec":15})";
  std::string viewerAddTarget = sendRawHttp(
      port,
      "POST /api/v1/quality/targets HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf +
          "\r\nContent-Length: " + std::to_string(addTargetBody.size()) + "\r\n\r\n" + addTargetBody);
  CHECK(viewerAddTarget.find("403 Forbidden") != std::string::npos);

  std::string admAddTarget = sendRawHttp(
      port,
      "POST /api/v1/quality/targets HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(addTargetBody.size()) + "\r\n\r\n" + addTargetBody);
  CHECK(admAddTarget.find("201 Created") != std::string::npos);
  CHECK(admAddTarget.find("Custom DNS") != std::string::npos);

  std::string qHistResp = sendRawHttp(
      port,
      "GET /api/v1/quality/history?targetId=pub-dns-cf&range=15m HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(qHistResp.find("200 OK") != std::string::npos);
  CHECK(qHistResp.find("\"summary\":") != std::string::npos);

  const std::string delNoConfBody = R"({"id":"pub-dns-cf"})";
  std::string delNoConfResp = sendRawHttp(
      port,
      "POST /api/v1/quality/targets/delete HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(delNoConfBody.size()) + "\r\n\r\n" + delNoConfBody);
  CHECK(delNoConfResp.find("confirmation_required") != std::string::npos);

  // 14. Fase 3 Advanced Traceroute history, diff & monitor endpoints + RBAC + confirm guard
  std::string thResp = sendRawHttp(
      port,
      "GET /api/v1/trace/history?limit=10 HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(thResp.find("200 OK") != std::string::npos);
  CHECK(thResp.find("\"runs\":") != std::string::npos);

  const std::string monBody = R"({"targetIp":"1.1.1.1","label":"Cloudflare","intervalSec":120,"enabled":true})";
  std::string viewerAddMon = sendRawHttp(
      port,
      "POST /api/v1/trace/monitors HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf +
          "\r\nContent-Length: " + std::to_string(monBody.size()) + "\r\n\r\n" + monBody);
  CHECK(viewerAddMon.find("403 Forbidden") != std::string::npos);

  std::string admAddMon = sendRawHttp(
      port,
      "POST /api/v1/trace/monitors HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(monBody.size()) + "\r\n\r\n" + monBody);
  CHECK(admAddMon.find("200 OK") != std::string::npos);
  CHECK(admAddMon.find("1.1.1.1") != std::string::npos);

  const std::string monDelNoConf = R"({"targetIp":"1.1.1.1"})";
  std::string monDelNoConfResp = sendRawHttp(
      port,
      "POST /api/v1/trace/monitors/delete HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(monDelNoConf.size()) + "\r\n\r\n" + monDelNoConf);
  CHECK(monDelNoConfResp.find("confirmation_required") != std::string::npos);

  std::string tDiffNoRuns = sendRawHttp(
      port,
      "GET /api/v1/trace/diff?targetIp=1.1.1.1 HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(tDiffNoRuns.find("200 OK") != std::string::npos);

  // 15. Fase 4 Multi-WAN & Interfaces endpoints + RBAC
  std::string viewerIfRefresh = sendRawHttp(
      port,
      "POST /api/v1/interfaces/refresh HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf + "\r\nContent-Length: 0\r\n\r\n");
  CHECK(viewerIfRefresh.find("403 Forbidden") != std::string::npos);

  std::string admIfRefresh = sendRawHttp(
      port,
      "POST /api/v1/interfaces/refresh HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf + "\r\nContent-Length: 0\r\n\r\n");
  CHECK(admIfRefresh.find("200 OK") != std::string::npos);
  CHECK(admIfRefresh.find("\"interfaces\":") != std::string::npos);

  std::string ifGet = sendRawHttp(
      port,
      "GET /api/v1/interfaces HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(ifGet.find("200 OK") != std::string::npos);

  std::string ifHist = sendRawHttp(
      port,
      "GET /api/v1/interfaces/history?id=if-1&range=15m HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(ifHist.find("200 OK") != std::string::npos);
  CHECK(ifHist.find("\"series\":") != std::string::npos);

  server.stop();
  std::filesystem::remove_all(tempRoot, ec);
  std::cout << "[PASS] testLiveSecurityHttpAndWsIntegration\n";
  return 0;
}

int testTlsContextInit() {
  auto dir = std::filesystem::temp_directory_path() / "netpulse_tls_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);

  TlsContext tls;
  TlsConfig cfg;
  cfg.enabled = true;
  cfg.autoCertDir = dir;
  cfg.commonName = "localhost";
  std::string err;
  bool ok = tls.init(cfg, err);
  if (!ok) {
    std::cerr << "TLS init failed: " << err << "\n";
  }
  CHECK(ok);
  CHECK(tls.isReady());

  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testTlsContextInit\n";
  return 0;
}

int testSemVerAndReleaseParsing() {
  CHECK(isNewerVersion("1.0.0", "1.0.1"));
  CHECK(isNewerVersion("1.9.0", "1.10.0"));
  CHECK(isNewerVersion("1.0.0-beta.1", "1.0.0"));
  CHECK(!isNewerVersion("1.0.0", "1.0.0"));
  CHECK(!isNewerVersion("1.0.2", "1.0.1"));
  CHECK(!isNewerVersion("2.0.0", "1.9.9"));

  const std::string ghJson = R"({
    "tag_name": "v1.0.1",
    "html_url": "https://github.com/djcristianosgp/netpulse-map/releases/tag/v1.0.1",
    "published_at": "2026-11-17T18:00:00Z",
    "assets": [
      {"name": "checksums.txt", "size": 180, "browser_download_url": "https://github.com/djcristianosgp/netpulse-map/releases/download/v1.0.1/checksums.txt"},
      {"name": "NetPulse2D-Setup-x64.exe", "size": 2331922, "browser_download_url": "https://github.com/djcristianosgp/netpulse-map/releases/download/v1.0.1/NetPulse2D-Setup-x64.exe"}
    ]
  })";
  auto rel = parseGitHubReleaseJson(ghJson);
  CHECK(rel.valid);
  CHECK(rel.version == "1.0.1");
  CHECK(rel.installerSize == 2331922);
  CHECK(rel.installerUrl.find("NetPulse2D-Setup-x64.exe") != std::string::npos);
  CHECK(rel.checksumsUrl.find("checksums.txt") != std::string::npos);

  const std::string csText =
      "\xEF\xBB\xBF"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  NetPulse2D-Portable-x64.zip\n"
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  NetPulse2D-Setup-x64.exe\n";
  CHECK(parseSha256FromChecksums(csText, "NetPulse2D-Setup-x64.exe") ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  auto tmpFile = std::filesystem::temp_directory_path() / "netpulse_sha256_test.bin";
  {
    std::ofstream out(tmpFile, std::ios::binary | std::ios::trunc);
    out << "abc";
  }
  CHECK(computeFileSha256Hex(tmpFile) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  std::error_code ec;
  std::filesystem::remove(tmpFile, ec);

  std::cout << "[PASS] testSemVerAndReleaseParsing\n";
  return 0;
}

int testServiceMonitorParsing() {
  ServiceTarget t;
  CHECK(parseCustomServiceLine("custom-1\tMeu API\tapi.example.com\t8443\tEU\t50.11\t8.68", t));
  CHECK(t.id == "custom-1");
  CHECK(t.name == "Meu API");
  CHECK(t.host == "api.example.com");
  CHECK(t.port == 8443);
  CHECK(t.continent == "EU");
  CHECK(t.custom);
  CHECK(!parseCustomServiceLine("# comment", t));
  CHECK(!parseCustomServiceLine("bad\tline", t));

  auto tempSvc = std::filesystem::temp_directory_path() / "netpulse_svc_test.tsv";
  std::error_code ec;
  std::filesystem::remove(tempSvc, ec);
  {
    ServiceMonitor mon(tempSvc);
    auto snap = mon.getSnapshot();
    CHECK(snap.size() >= 17);
    CHECK(mon.addCustomService("Local Echo", "127.0.0.1", 80, "SA", -23.5, -46.6));
    auto snap2 = mon.getSnapshot();
    CHECK(snap2.size() == snap.size() + 1);
    std::string customId = snap2.back().target.id;
    CHECK(mon.removeCustomService(customId));
    CHECK(mon.getSnapshot().size() == snap.size());
  }
  std::filesystem::remove(tempSvc, ec);
  std::cout << "[PASS] testServiceMonitorParsing\n";
  return 0;
}

int testMmdbAndHistorySecurity() {
  auto encStr = [](std::vector<uint8_t>& buf, const std::string& s) {
    buf.push_back(static_cast<uint8_t>((2 << 5) | s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
  };
  auto encUint = [](std::vector<uint8_t>& buf, uint32_t v) {
    if (v <= 0xFF) {
      buf.push_back((5 << 5) | 1);
      buf.push_back(static_cast<uint8_t>(v));
    } else {
      buf.push_back((5 << 5) | 2);
      buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
      buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }
  };
  auto encDouble = [](std::vector<uint8_t>& buf, double d) {
    buf.push_back((3 << 5) | 8);
    uint64_t raw = 0;
    std::memcpy(&raw, &d, sizeof(d));
    for (int sh = 56; sh >= 0; sh -= 8) buf.push_back(static_cast<uint8_t>((raw >> sh) & 0xFF));
  };

  std::vector<uint8_t> mmdb;
  mmdb.insert(mmdb.end(), {0x00, 0x00, 0x11, 0x00, 0x00, 0x01});
  mmdb.insert(mmdb.end(), 16, 0x00);

  mmdb.push_back((7 << 5) | 2);
  encStr(mmdb, "country");
  mmdb.push_back((7 << 5) | 1);
  encStr(mmdb, "iso_code");
  encStr(mmdb, "US");
  encStr(mmdb, "location");
  mmdb.push_back((7 << 5) | 2);
  encStr(mmdb, "latitude");
  encDouble(mmdb, 39.03);
  encStr(mmdb, "longitude");
  encDouble(mmdb, -77.5);

  const uint8_t marker[] = {0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};
  mmdb.insert(mmdb.end(), std::begin(marker), std::end(marker));
  mmdb.push_back((7 << 5) | 4);
  encStr(mmdb, "node_count"); encUint(mmdb, 1);
  encStr(mmdb, "record_size"); encUint(mmdb, 24);
  encStr(mmdb, "ip_version"); encUint(mmdb, 4);
  encStr(mmdb, "database_type"); encStr(mmdb, "GeoLite2-City");

  auto mmdbPath = std::filesystem::temp_directory_path() / "netpulse_test.mmdb";
  {
    std::ofstream out(mmdbPath, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(mmdb.data()), static_cast<std::streamsize>(mmdb.size()));
  }

  MmdbReader reader;
  CHECK(reader.load(mmdbPath));
  CHECK(reader.databaseType() == "GeoLite2-City");
  auto g = reader.lookup("8.8.8.8");
  CHECK(g.has_value());
  CHECK(g->countryCode == "US");
  CHECK(std::abs(g->lat - 39.03) < 1e-4);
  CHECK(std::abs(g->lon - (-77.5)) < 1e-4);
  CHECK(!reader.lookup("200.1.2.3").has_value());
  std::error_code ec;
  std::filesystem::remove(mmdbPath, ec);

  CHECK(isSensitivePort(22));
  CHECK(isSensitivePort(3389));
  CHECK(!isSensitivePort(443));
  CHECK(isValidIpAddress("8.8.8.8"));
  CHECK(isValidIpAddress("2606:4700:4700::1111"));
  CHECK(!isValidIpAddress("8.8.8.8 & calc.exe"));
  CHECK(isProtectedSystemProcess(4, "System"));
  CHECK(isProtectedSystemProcess(999, "lsass.exe"));
  CHECK(!isProtectedSystemProcess(99999, "notepad.exe"));

  auto histDir = std::filesystem::temp_directory_path() / "netpulse_hist_test";
  std::filesystem::remove_all(histDir, ec);
  {
    HistoryStore hs(histDir);
    hs.recordManualAction("warn", "Teste", "Detalhe");
    std::string j = hs.getEventsJson(10);
    CHECK(j.find("Teste") != std::string::npos);
  }
  {
    HistoryStore hs2(histDir);
    CHECK(hs2.getEventsJson(10).find("Teste") != std::string::npos);
  }
  std::filesystem::remove_all(histDir, ec);

  std::cout << "[PASS] testMmdbAndHistorySecurity\n";
  return 0;
}

int testSettingsStorePersistence() {
  std::string k, v;
  CHECK(SettingsStore::parseLine("defaultView\tglobal\r\n", k, v));
  CHECK(k == "defaultView" && v == "global");
  CHECK(!SettingsStore::parseLine("# comment", k, v));

  auto tempPath = std::filesystem::temp_directory_path() / "netpulse_settings_test.tsv";
  std::error_code ec;
  std::filesystem::remove(tempPath, ec);
  {
    std::ofstream out(tempPath);
    out << "alertsEnabled\t0\n"
        << "defaultView\tglobal\n"
        << "minimizeToTray\t0\n"
        << "notifyServiceDown\t1\n"
        << "notifyServiceDegraded\t0\n"
        << "notifySensitivePort\t1\n"
        << "notifyNewCountry\t0\n"
        << "retentionDays\t90\n"
        << "maxDbSizeMb\t512\n";
  }
  SettingsStore store(tempPath);
  auto cfg = store.get();
  CHECK(!cfg.alertsEnabled);
  CHECK(cfg.defaultView == "global");
  CHECK(!cfg.minimizeToTray);
  CHECK(cfg.notifyServiceDown);
  CHECK(!cfg.notifyServiceDegraded);
  CHECK(cfg.notifySensitivePort);
  CHECK(!cfg.notifyNewCountry);
  CHECK(cfg.retentionDays == 90);
  CHECK(cfg.maxDbSizeMb == 512);
  CHECK(store.toJson().find("\"defaultView\":\"global\"") != std::string::npos);
  CHECK(store.toJson().find("\"notifyServiceDegraded\":false") != std::string::npos);
  CHECK(store.toJson().find("\"retentionDays\":90") != std::string::npos);
  CHECK(store.toJson().find("\"maxDbSizeMb\":512") != std::string::npos);

  auto histDir = std::filesystem::temp_directory_path() / "netpulse_settings_hist_test";
  std::filesystem::remove_all(histDir, ec);
  {
    HistoryStore hist(histDir);
    hist.setAlertsEnabled(true);
    NotificationCategories cats;
    cats.serviceDown = true;
    cats.serviceDegraded = false;
    cats.sensitivePort = true;
    cats.newCountry = false;
    hist.setNotificationCategories(cats);
    CHECK(hist.shouldNotifyKind("service_down"));
    CHECK(hist.shouldNotifyKind("service_up"));
    CHECK(!hist.shouldNotifyKind("service_degraded"));
    CHECK(hist.shouldNotifyKind("sensitive_port"));
    CHECK(!hist.shouldNotifyKind("new_country"));
    hist.setAlertsEnabled(false);
    CHECK(!hist.shouldNotifyKind("service_down"));
  }
  std::filesystem::remove_all(histDir, ec);

  std::filesystem::remove(tempPath, ec);
  std::cout << "[PASS] testSettingsStorePersistence\n";
  return 0;
}

int testSqliteMigrationsAndTsvImport() {
  auto dir = std::filesystem::temp_directory_path() / "netpulse_sqlite_tsv_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  std::filesystem::create_directories(dir, ec);

  const uint64_t nowMs = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  // Seed legacy TSV files prior to opening HistoryStore (including one expired 15-day-old event)
  {
    std::ofstream evOut(dir / "events_history.tsv");
    evOut << (nowMs - 15ULL * 86400000ULL) << "\twarn\taction\tExpired Old Event\tstale-detail\n";
    evOut << (nowMs - 60000) << "\twarn\tsensitive_port\tLegacy SSH\t192.168.1.50:22\n";
    evOut << (nowMs - 30000) << "\tinfo\tservice_up\tDNS Up\t1.1.1.1 OK\n";
  }
  {
    std::ofstream metOut(dir / "service_metrics.tsv");
    metOut << (nowMs - 50000) << "\tcloudflare-dns\tok\t11.4\n";
    metOut << (nowMs - 20000) << "\tcloudflare-dns\tok\t12.8\n";
  }

  {
    HistoryStore hist(dir);
    hist.flushNow();

    CHECK(std::filesystem::exists(dir / "netpulse.db"));
    CHECK(std::filesystem::exists(dir / ".tsv_imported_v1"));

    std::string stats = hist.getStorageStatsJson();
    CHECK(stats.find("\"journalMode\":\"wal\"") != std::string::npos);
    CHECK(stats.find("\"integrityOk\":true") != std::string::npos);
    CHECK(stats.find("\"schemaVersion\":4") != std::string::npos);

    std::string evJson = hist.getEventsJson(50, 0, "warn", "");
    CHECK(evJson.find("Legacy SSH") != std::string::npos);
    CHECK(evJson.find("DNS Up") == std::string::npos);

    std::string svcJson = hist.getServiceHistoryJson("cloudflare-dns", 20);
    CHECK(svcJson.find("11.4") != std::string::npos);
    CHECK(svcJson.find("12.8") != std::string::npos);
    hist.stop();
  }

  // Re-open to verify idempotent restart, migration persistence, and retention pruning
  {
    HistoryStore hist2(dir);
    std::string evJson2 = hist2.getEventsJson(50, 0, "", "");
    CHECK(evJson2.find("Legacy SSH") != std::string::npos);

    // 15-day-old event lives in SQLite (beyond 7d hot cache) and is removed when 7d retention prunes
    std::string oldActionBefore = hist2.getEventsJson(50, 0, "", "action");
    CHECK(oldActionBefore.find("Expired Old Event") != std::string::npos);

    hist2.setRetentionConfig(7, 128);
    CHECK(hist2.pruneNow());
    std::string oldActionAfter = hist2.getEventsJson(50, 0, "", "action");
    CHECK(oldActionAfter.find("Expired Old Event") == std::string::npos);
    CHECK(hist2.getEventsJson(50, 0, "", "").find("Legacy SSH") != std::string::npos);
    hist2.stop();
  }

  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testSqliteMigrationsAndTsvImport\n";
  return 0;
}

int testHistoryAnalyticsAndRetention() {
  auto dir = std::filesystem::temp_directory_path() / "netpulse_analytics_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);

  {
    HistoryStore hist(dir);
    GeoDnsService geo(dir);

    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    TelemetrySnapshot snap;
    snap.timestampMs = nowMs;
    snap.totalConnections = 2;
    snap.publicConnections = 2;
    snap.nic.rxBytesPerSec = 200000.0;
    snap.nic.txBytesPerSec = 50000.0;

    SocketEntry s1;
    s1.key = "TCP:4000:104.16.132.229:443:1001";
    s1.processName = "chrome.exe";
    s1.processPath = "C:\\Program Files\\Google\\Chrome\\chrome.exe";
    s1.pid = 1001;
    s1.localIp = "192.168.1.10";
    s1.remoteIp = "104.16.132.229";
    s1.localPort = 51001;
    s1.remotePort = 443;
    s1.protocol = "TCP";
    s1.ipVersion = 4;
    s1.state = "ESTABLISHED";
    s1.scope = IpScope::Public;
    s1.lifecycle = Lifecycle::New;
    s1.firstSeenMs = nowMs - 2000;
    s1.lastSeenMs = nowMs;
    s1.rxBps = 180000.0;
    s1.txBps = 40000.0;

    SocketEntry s2 = s1;
    s2.key = "UDP:4001:8.8.8.8:53:2002";
    s2.processName = "dnscrypt.exe";
    s2.processPath = "C:\\Tools\\dnscrypt.exe";
    s2.pid = 2002;
    s2.remoteIp = "8.8.8.8";
    s2.localPort = 52002;
    s2.remotePort = 53;
    s2.protocol = "UDP";
    s2.rxBps = 20000.0;
    s2.txBps = 10000.0;

    snap.connections = {s1, s2};
    snap.processStats = {
        {1001, "chrome.exe", s1.processPath, 1, 1, 180000.0, 40000.0, 220000.0},
        {2002, "dnscrypt.exe", s2.processPath, 1, 1, 20000.0, 10000.0, 30000.0},
    };

    hist.processTelemetry(snap, geo);
    hist.flushNow();

    ConnectionQuery cq;
    cq.search = "chrome";
    cq.limit = 10;
    std::string connJson = hist.queryConnectionsJson(cq);
    CHECK(connJson.find("chrome.exe") != std::string::npos);
    CHECK(connJson.find("104.16.132.229") != std::string::npos);

    std::string procJson = hist.queryProcessesJson("24h", 20, 0, "chrome");
    CHECK(procJson.find("chrome.exe") != std::string::npos);

    std::string anaJson = hist.queryAnalyticsJson("7d");
    CHECK(anaJson.find("\"totalConnections\":2") != std::string::npos);
    CHECK(anaJson.find("chrome.exe") != std::string::npos);
    CHECK(anaJson.find("104.16.132.229") != std::string::npos);

    // Benchmark 1,500 batched connection records to verify WAL write throughput.
    const auto t0 = std::chrono::steady_clock::now();
    TelemetrySnapshot bulkSnap;
    bulkSnap.timestampMs = nowMs + 1000;
    bulkSnap.totalConnections = 1500;
    bulkSnap.publicConnections = 1500;
    bulkSnap.nic.rxBytesPerSec = 1000.0;
    bulkSnap.nic.txBytesPerSec = 500.0;
    bulkSnap.connections.reserve(1500);
    for (int i = 0; i < 1500; ++i) {
      SocketEntry bs;
      bs.key = "TCP:5000:" + std::to_string(i) + ":443:9000";
      bs.processName = "bench.exe";
      bs.pid = 9000;
      bs.localIp = "10.0.0.2";
      bs.remoteIp = "93.184.216." + std::to_string((i % 200) + 1);
      bs.localPort = static_cast<uint16_t>(10000 + (i % 40000));
      bs.remotePort = 443;
      bs.protocol = "TCP";
      bs.ipVersion = 4;
      bs.state = "ESTABLISHED";
      bs.scope = IpScope::Public;
      bs.lifecycle = Lifecycle::New;
      bs.firstSeenMs = nowMs + 1000;
      bs.lastSeenMs = nowMs + 1000;
      bulkSnap.connections.push_back(std::move(bs));
    }
    hist.processTelemetry(bulkSnap, geo);
    hist.flushNow();
    const auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    std::cout << "  [BENCH] 1,500 connections ingested + flushed to SQLite WAL in " << elapsedMs << " ms\n";

    std::string postBench = hist.queryAnalyticsJson("24h");
    CHECK(postBench.find("bench.exe") != std::string::npos);

    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    hist.stop();
  }

  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testHistoryAnalyticsAndRetention\n";
  return 0;
}

int testNetworkQualityMathAndDiagnosis() {
  // 1. DNS query packet build + header validation
  auto pkt = buildDnsQueryPacket(0x1234, "one.one.one.one");
  CHECK(pkt.size() > 16);
  CHECK(pkt[0] == 0x12 && pkt[1] == 0x34);
  uint8_t rcode = 99;
  // Query packet (QR=0) must be rejected as response
  CHECK(!parseDnsResponseHeader(pkt.data(), pkt.size(), 0x1234, rcode));
  std::vector<uint8_t> respPkt = pkt;
  respPkt[2] = 0x81; // QR=1, RD=1
  respPkt[3] = 0x80; // RCODE=0
  CHECK(parseDnsResponseHeader(respPkt.data(), respPkt.size(), 0x1234, rcode));
  CHECK(rcode == 0);
  CHECK(!parseDnsResponseHeader(respPkt.data(), respPkt.size(), 0x9999, rcode));

  // 2. Percentiles, jitter, packet loss, flapping, and half-window trend
  const uint64_t tBase = 1700000000000ULL;
  std::vector<QualitySampleRecord> samples;
  const double rtts[] = {10.0, 12.0, 11.0, 14.0, 13.0, 40.0, 45.0, 50.0, 60.0, 100.0};
  for (size_t i = 0; i < 10; ++i) {
    QualitySampleRecord s;
    s.tsMs = tBase + i * 10000ULL;
    s.targetId = "test-ext";
    s.ok = (i != 2); // 1 loss out of 10 = 10% loss
    s.rttMs = s.ok ? rtts[i] : 0.0;
    s.dnsMs = 4.0;
    samples.push_back(s);
  }
  auto m = computeQualityMetrics(samples);
  CHECK(m.sampleCount == 10);
  CHECK(m.okCount == 9);
  CHECK(m.packetLossPct > 9.9 && m.packetLossPct < 10.1);
  CHECK(m.availabilityPct > 89.9 && m.availabilityPct < 90.1);
  CHECK(m.minLatencyMs == 10.0);
  CHECK(m.maxLatencyMs == 100.0);
  CHECK(m.p50Ms >= 30.0 && m.p50Ms <= 45.0);
  CHECK(m.p95Ms >= 80.0);
  CHECK(m.p99Ms >= 90.0);
  CHECK(m.jitterMs > 5.0);
  CHECK(m.recentHalfAvgMs > m.olderHalfAvgMs + 30.0);
  CHECK(m.flaps == 2);

  // 3. Deterministic diagnosis rules (gateway unreachable, dns unreachable, external patterns, nominal)
  {
    QualityTargetSnapshot gw;
    gw.target = {"gw", "Gateway", "192.168.1.1", 0, "gateway", "icmp", 10, true, true, 0};
    gw.status = "down";
    gw.metrics.sampleCount = 6;
    gw.metrics.okCount = 0;
    gw.metrics.packetLossPct = 100.0;
    gw.metrics.availabilityPct = 0.0;
    auto diagGw = diagnoseNetworkQuality({gw});
    CHECK(diagGw.overallHealth == "critical");
    CHECK(!diagGw.findings.empty());
    CHECK(diagGw.findings[0].code == "gateway_unreachable");
    CHECK(!diagGw.findings[0].observedFacts.empty());
    CHECK(!diagGw.findings[0].hypotheses.empty());

    // Gateway ICMP filtered while upstream DNS is healthy -> informative, NOT critical
    QualityTargetSnapshot upstreamOk;
    upstreamOk.target = {"dns-up", "CF", "1.1.1.1", 53, "public_dns", "dns", 10, true, false, 0};
    upstreamOk.status = "ok";
    upstreamOk.metrics.sampleCount = 6;
    upstreamOk.metrics.okCount = 6;
    upstreamOk.metrics.availabilityPct = 100.0;
    upstreamOk.metrics.p50Ms = 15.0;
    auto diagFiltered = diagnoseNetworkQuality({gw, upstreamOk});
    CHECK(diagFiltered.overallHealth == "healthy");
    CHECK(!diagFiltered.findings.empty());
    CHECK(diagFiltered.findings[0].code == "gateway_icmp_filtered");
    CHECK(diagFiltered.findings[0].severity == "info");
  }

  {
    QualityTargetSnapshot gwOk;
    gwOk.target = {"gw", "Gateway", "192.168.1.1", 0, "gateway", "icmp", 10, true, true, 0};
    gwOk.status = "ok";
    gwOk.metrics.sampleCount = 10;
    gwOk.metrics.okCount = 10;
    gwOk.metrics.p50Ms = 1.5;
    gwOk.metrics.p95Ms = 2.0;
    gwOk.metrics.availabilityPct = 100.0;

    QualityTargetSnapshot ispDnsBad;
    ispDnsBad.target = {"dns", "ISP DNS", "200.1.1.1", 53, "isp_dns", "dns", 10, true, true, 0};
    ispDnsBad.status = "down";
    ispDnsBad.metrics.sampleCount = 10;
    ispDnsBad.metrics.okCount = 3;
    ispDnsBad.metrics.packetLossPct = 70.0;
    ispDnsBad.metrics.availabilityPct = 30.0;

    QualityTargetSnapshot degradedExt;
    degradedExt.target = {"ext", "Ext Host", "github.com", 443, "known_server", "tcp", 10, true, false, 0};
    degradedExt.status = "degraded";
    degradedExt.metrics.sampleCount = 10;
    degradedExt.metrics.okCount = 9;
    degradedExt.metrics.avgLatencyMs = 150.0;
    degradedExt.metrics.p50Ms = 110.0;
    degradedExt.metrics.p95Ms = 210.0;
    degradedExt.metrics.jitterMs = 35.0;
    degradedExt.metrics.packetLossPct = 10.0;
    degradedExt.metrics.availabilityPct = 90.0;
    degradedExt.metrics.flaps = 4;
    degradedExt.metrics.olderHalfAvgMs = 40.0;
    degradedExt.metrics.recentHalfAvgMs = 180.0;
    degradedExt.metrics.olderHalfAvailPct = 100.0;
    degradedExt.metrics.recentHalfAvailPct = 80.0;

    auto rep = diagnoseNetworkQuality({gwOk, ispDnsBad, degradedExt});
    CHECK(rep.overallHealth == "critical");
    auto hasCode = [&](const std::string& code) {
      for (const auto& f : rep.findings) {
        if (f.code == code) return true;
      }
      return false;
    };
    CHECK(hasCode("dns_unreachable"));
    CHECK(hasCode("packet_loss"));
    CHECK(hasCode("high_latency"));
    CHECK(hasCode("latency_oscillation"));
    CHECK(hasCode("frequent_interruptions"));
    CHECK(hasCode("progressive_degradation"));
  }

  // 4. SQLite persistence + bucketed history query + retention prune for quality_samples
  auto qDir = std::filesystem::temp_directory_path() / "netpulse_quality_sqlite_test";
  std::error_code ec;
  std::filesystem::remove_all(qDir, ec);
  {
    HistoryStore hist(qDir);
    NetworkQualityEngine engine(hist);
    std::string newId, err;
    CHECK(engine.addTarget("Loopback Test", "127.0.0.1", 0, "custom", "icmp", 10, newId, err));

    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    hist.enqueueQualitySample({nowMs - 20ULL * 86400000ULL, newId, true, 5.0, 0.0, 0.0, "icmp", ""});
    hist.enqueueQualitySample({nowMs - 60000ULL, newId, true, 12.0, 2.5, 0.0, "icmp", ""});
    hist.enqueueQualitySample({nowMs - 30000ULL, newId, true, 18.0, 3.5, 6.0, "icmp", ""});
    hist.enqueueQualitySample({nowMs - 10000ULL, newId, false, 0.0, 0.0, 0.0, "icmp", "timeout"});
    hist.flushNow();

    std::string hist1h = hist.queryQualityHistoryJson(newId, "1h");
    CHECK(hist1h.find("\"samples\":3") != std::string::npos);
    CHECK(hist1h.find("\"okSamples\":2") != std::string::npos);
    CHECK(hist1h.find("\"p95Ms\":") != std::string::npos);

    std::string stJson = hist.getStorageStatsJson();
    CHECK(stJson.find("\"qualitySamples\":4") != std::string::npos);

    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    std::string stAfter = hist.getStorageStatsJson();
    CHECK(stAfter.find("\"qualitySamples\":3") != std::string::npos);

    auto infra = discoverNetworkInfra();
    (void)infra;
    hist.stop();
  }
  std::filesystem::remove_all(qDir, ec);

  std::cout << "[PASS] testNetworkQualityMathAndDiagnosis\n";
  return 0;
}

int testTracerouteHistoryAndRouteDiff() {
  // 1. Path fingerprint & diff computation
  TraceRunRecord run1;
  run1.id = 1;
  run1.targetIp = "8.8.8.8";
  run1.targetLabel = "Google DNS";
  run1.totalRttMs = 15.0;
  run1.hops = {
      {1, false, "192.168.1.1", 1.2, "", "", "", "", "", 0.0, 0.0},
      {2, false, "10.10.0.1", 5.5, "", "AS111", "", "", "", 0.0, 0.0},
      {3, false, "8.8.8.8", 15.0, "dns.google", "AS15169", "United States", "US", "Mountain View", 37.4, -122.0},
  };
  run1.pathHash = computeTracePathHash(run1.hops);
  CHECK(run1.pathHash.size() == 16);

  TraceRunRecord run1Clone = run1;
  run1Clone.hops[1].rttMs = 9.0; // jitter only, identical hop IPs -> identical pathHash
  CHECK(computeTracePathHash(run1Clone.hops) == run1.pathHash);

  auto sameDiff = computeTraceRouteDiff(run1, run1Clone);
  CHECK(!sameDiff.pathChanged);
  CHECK(sameDiff.changedHopsCount == 0);

  TraceRunRecord run2;
  run2.id = 2;
  run2.targetIp = "8.8.8.8";
  run2.targetLabel = "Google DNS";
  run2.totalRttMs = 24.0;
  run2.hops = {
      {1, false, "192.168.1.1", 1.1, "", "", "", "", "", 0.0, 0.0},
      {2, false, "172.16.4.1", 11.5, "", "AS222", "", "", "", 0.0, 0.0},
      {3, true, "", 0.0, "", "", "", "", "", 0.0, 0.0},
      {4, false, "8.8.8.8", 24.0, "dns.google", "AS15169", "United States", "US", "Mountain View", 37.4, -122.0},
  };
  run2.pathHash = computeTracePathHash(run2.hops);
  CHECK(run2.pathHash != run1.pathHash);

  auto changedDiff = computeTraceRouteDiff(run1, run2);
  CHECK(changedDiff.pathChanged);
  CHECK(changedDiff.changedHopsCount >= 3); // TTL 2 changed, TTL 3 timeout_change, TTL 4 added
  CHECK(changedDiff.totalRttDeltaMs > 8.5);
  std::string diffJson = serializeTraceDiffJson(changedDiff);
  CHECK(diffJson.find("\"pathChanged\":true") != std::string::npos);
  CHECK(diffJson.find("\"changed\"") != std::string::npos);
  CHECK(diffJson.find("\"added\"") != std::string::npos);

  // 2. SQLite persistence, route_changed detection, monitor CRUD & retention
  auto tDir = std::filesystem::temp_directory_path() / "netpulse_trace_sqlite_test";
  std::error_code ec;
  std::filesystem::remove_all(tDir, ec);
  {
    HistoryStore hist(tDir);
    GeoDnsService geo(tDir / "geo.tsv");
    TracerouteService tracer(geo, &hist);

    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    run1.startedAtMs = nowMs - 20ULL * 86400000ULL; // 20 days old (for retention test)
    run1.completedAtMs = run1.startedAtMs + 500;
    run1.reached = true;
    int64_t id1 = hist.saveTraceRun(run1);
    CHECK(id1 > 0);
    CHECK(!run1.changedFromPrev);

    run2.startedAtMs = nowMs - 5000;
    run2.completedAtMs = nowMs - 4000;
    run2.reached = true;
    int64_t id2 = hist.saveTraceRun(run2);
    CHECK(id2 > id1);
    CHECK(run2.changedFromPrev); // Path differed from run1!

    hist.flushNow();
    std::string evJson = hist.getEventsJson(50, 0, "", "route_changed");
    CHECK(evJson.find("Variação de rota detectada") != std::string::npos);

    std::string hJson = tracer.getHistoryJson("8.8.8.8", 10);
    CHECK(hJson.find("AS15169") != std::string::npos);
    CHECK(hJson.find("\"changedFromPrev\":true") != std::string::npos);

    std::string autoDiff = tracer.getDiffJson(0, 0, "8.8.8.8");
    CHECK(autoDiff.find("\"pathChanged\":true") != std::string::npos);

    CHECK(tracer.upsertMonitor("8.8.8.8", "Google DNS", 120, true));
    std::string mJson = tracer.getMonitorsJson();
    CHECK(mJson.find("8.8.8.8") != std::string::npos);
    CHECK(tracer.removeMonitor("8.8.8.8"));

    // Prune with 7d retention -> removes old run1 (20d old), preserves run2
    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    auto remaining = hist.loadTraceRuns("8.8.8.8", 10);
    CHECK(remaining.size() == 1);
    CHECK(remaining[0].id == id2);

    hist.stop();
  }
  std::filesystem::remove_all(tDir, ec);

  std::cout << "[PASS] testTracerouteHistoryAndRouteDiff\n";
  return 0;
}

int testMultiWanAndInterfaces() {
  // 1. Deterministic type classification
  CHECK(classifyInterfaceType(24, "Loopback Pseudo-Interface 1", "", false) == "loopback");
  CHECK(classifyInterfaceType(71, "Wi-Fi", "Intel(R) Wi-Fi 6 AX201", true) == "wifi");
  CHECK(classifyInterfaceType(6, "Ethernet", "Realtek PCIe GbE Family Controller", true) == "ethernet");
  CHECK(classifyInterfaceType(53, "wg0", "WireGuard Tunnel", false) == "vpn");
  CHECK(classifyInterfaceType(6, "vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", false) == "virtual");
  CHECK(classifyInterfaceType(131, "teredo", "Microsoft Teredo Tunneling", false) == "tunnel");

  // 2. MAC formatting
  const uint8_t mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
  CHECK(formatMacAddress(mac, 6) == "00:1A:2B:3C:4D:5E");
  const uint8_t zeroMac[6] = {0, 0, 0, 0, 0, 0};
  CHECK(formatMacAddress(zeroMac, 6).empty());

  // 3. Rate computation + counter reset resilience
  InterfaceRatePrev prev{};
  NetworkInterfaceInfo cur;
  cur.rxBytes = 10000;
  cur.txBytes = 5000;
  cur.rxPackets = 100;
  cur.txPackets = 50;
  computeInterfaceRates(prev, cur, 1000);
  CHECK(cur.rxBps == 0.0);

  cur.rxBytes = 30000;
  cur.txBytes = 15000;
  cur.rxPackets = 200;
  cur.txPackets = 100;
  computeInterfaceRates(prev, cur, 3000); // dt = 2s -> 10KB/s RX, 5KB/s TX, 50/25 pps
  CHECK(cur.rxBps > 9999.0 && cur.rxBps < 10001.0);
  CHECK(cur.txBps > 4999.0 && cur.txBps < 5001.0);
  CHECK(cur.rxPps > 49.9 && cur.rxPps < 50.1);
  CHECK(cur.txPps > 24.9 && cur.txPps < 25.1);

  // Counter reset (cur < prev) must NOT underflow into giant values
  cur.rxBytes = 100;
  computeInterfaceRates(prev, cur, 5000);
  CHECK(cur.rxBps == 0.0);

  // 4. Multi-WAN transition detection
  InterfaceInventorySnapshot s1, s2;
  s1.primaryIfId = "if-1";
  s1.primaryIfName = "Ethernet WAN1";
  s1.primaryGateway = "192.168.1.1";
  s1.interfaces.push_back({"if-1", 1, "Ethernet WAN1", "", "ethernet", "", "up", true, true, true, true});
  s1.interfaces.push_back({"if-2", 2, "LTE Failover", "", "ethernet", "", "down", false, true, false, true});

  s2.primaryIfId = "if-2";
  s2.primaryIfName = "LTE Failover";
  s2.primaryGateway = "10.0.0.1";
  s2.interfaces.push_back({"if-1", 1, "Ethernet WAN1", "", "ethernet", "", "down", false, true, false, true});
  s2.interfaces.push_back({"if-2", 2, "LTE Failover", "", "ethernet", "", "up", true, true, true, true});

  auto events = detectMultiWanTransitions(s1, s2);
  auto hasKind = [&](const std::string& k) {
    for (const auto& e : events) {
      if (e.kind == k) return true;
    }
    return false;
  };
  CHECK(hasKind("wan_primary_changed"));
  CHECK(hasKind("interface_down"));
  CHECK(hasKind("interface_up"));

  // 5. Live OS collection + SQLite history & retention
  auto ifDir = std::filesystem::temp_directory_path() / "netpulse_iface_sqlite_test";
  std::error_code ec;
  std::filesystem::remove_all(ifDir, ec);
  {
    HistoryStore hist(ifDir);
    InterfaceMonitor mon(&hist);

    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    auto liveSnap = mon.collect(nowMs);
    CHECK(!liveSnap.interfaces.empty());

    // Enqueue aged (20d old) and recent sample for retention validation
    hist.enqueueInterfaceSamples({
        {nowMs - 20ULL * 86400000ULL, "test-eth", "eth0", "ethernet", "up", true, 1000000000ULL, 1000.0, 500.0, 1000, 500, 0, 0},
        {nowMs - 5000ULL, "test-eth", "eth0", "ethernet", "up", true, 1000000000ULL, 2000.0, 1000.0, 3000, 1500, 1, 0},
    });
    hist.flushNow();

    std::string hJson = hist.queryInterfaceHistoryJson("test-eth", "1h");
    CHECK(hJson.find("2000.0") != std::string::npos);

    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    std::string allAfter = hist.queryInterfaceHistoryJson("test-eth", "30d");
    CHECK(allAfter.find("1000.0") == std::string::npos);
    CHECK(allAfter.find("2000.0") != std::string::npos);
    hist.stop();
  }
  std::filesystem::remove_all(ifDir, ec);

  std::cout << "[PASS] testMultiWanAndInterfaces\n";
  return 0;
}

int main() {
#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
#endif

  int rc = 0;
  rc |= testIpClassification();
  rc |= testGeoJsonAndCache();
  rc |= testWebSocketRfc6455();
  rc |= testJsonLiteParser();
  rc |= testAuthManagerAndRbac();
  rc |= testRateLimiterAndAuditLog();
  rc |= testLiveSecurityHttpAndWsIntegration();
  rc |= testTlsContextInit();
  rc |= testSemVerAndReleaseParsing();
  rc |= testServiceMonitorParsing();
  rc |= testMmdbAndHistorySecurity();
  rc |= testSettingsStorePersistence();
  rc |= testSqliteMigrationsAndTsvImport();
  rc |= testHistoryAnalyticsAndRetention();
  rc |= testNetworkQualityMathAndDiagnosis();
  rc |= testTracerouteHistoryAndRouteDiff();
  rc |= testMultiWanAndInterfaces();

#ifdef _WIN32
  WSACleanup();
#endif
  if (rc == 0) {
    std::cout << "ALL C++ TESTS PASSED.\n";
  }
  return rc;
}
