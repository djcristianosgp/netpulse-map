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
#include "../src/api/prometheus_openapi.hpp"
#include "../src/core/json_lite.hpp"
#include "../src/discovery/discovery_engine.hpp"
#include "../src/discovery/topology_builder.hpp"
#include "../src/geo_dns.hpp"
#include "../src/history_store.hpp"
#include "../src/intelligence/intelligence_engine.hpp"
#include "../src/mmdb_reader.hpp"
#include "../src/net_monitor.hpp"
#include "../src/network/interface_monitor.hpp"
#include "../src/notifications/notification_engine.hpp"
#include "../src/quality/network_quality_engine.hpp"
#include "../src/satellite/orbital_propagator.hpp"
#include "../src/satellite/satellite_catalog.hpp"
#include "../src/satellite/satellite_configuration.hpp"
#include "../src/satellite/satellite_manager.hpp"
#include "../src/satellite/satellite_position_service.hpp"
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
  DiscoveryEngine discovery(history, ifMon);
  IntelligenceEngine intelligence(history);
  NotificationEngine notifications(history);
  UpdateManager updater("1.3.0", nullptr);

  std::string snapJson = serializeSnapshotJson(snap, geoDns, 1000, 0, &svcMon);
  ApiRouter router(ApiDependencies{
      auth, audit, authLimiter, svcMon, tracer, settings, history, updater,
      tempRoot / "data", false, false,
      [&]() { return snapJson; },
      nullptr, nullptr, &quality, &ifMon, &discovery, nullptr, &intelligence, &notifications,
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

  // 16. Fase 5 Discovery Engine endpoints + RBAC + confirm guard
  std::string discGet = sendRawHttp(
      port,
      "GET /api/v1/discovery/devices HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(discGet.find("200 OK") != std::string::npos);
  CHECK(discGet.find("\"devices\":") != std::string::npos);

  std::string viewerScan = sendRawHttp(
      port,
      "POST /api/v1/discovery/scan HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf + "\r\nContent-Length: 0\r\n\r\n");
  CHECK(viewerScan.find("403 Forbidden") != std::string::npos);

  const std::string discDelNoConf = R"({"deviceKey":"AA:BB:CC:DD:EE:FF"})";
  std::string discDelResp = sendRawHttp(
      port,
      "POST /api/v1/discovery/devices/delete HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(discDelNoConf.size()) + "\r\n\r\n" + discDelNoConf);
  CHECK(discDelResp.find("confirmation_required") != std::string::npos);

  // 17. Fase 6 LAN Topology Graph endpoint
  std::string topoResp = sendRawHttp(
      port,
      "GET /api/v1/topology/lan HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer np_adm_integration_secret_987654\r\n\r\n");
  CHECK(topoResp.find("200 OK") != std::string::npos);
  CHECK(topoResp.find("\"nodes\":") != std::string::npos);
  CHECK(topoResp.find("\"edges\":") != std::string::npos);
  CHECK(topoResp.find("\"modelNote\":") != std::string::npos);

  // 18. Fase 7 Intelligence & Security HTTP RBAC + CSRF + confirm guards
  std::string intelOverResp = sendRawHttp(
      port,
      "GET /api/v1/intelligence/overview HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer " + viewerTok + "\r\n\r\n");
  CHECK(intelOverResp.find("200 OK") != std::string::npos);
  CHECK(intelOverResp.find("\"engineMode\":\"deterministic\"") != std::string::npos);
  CHECK(intelOverResp.find("\"aiUsed\":false") != std::string::npos);

  // Viewer CANNOT create rule (403)
  std::string ruleAddBody = R"({"name":"HTTP Rule","kind":"bandwidth_threshold","riskWeight":45,"thresholdNum":15})";
  std::string ruleViewerResp = sendRawHttp(
      port,
      "POST /api/v1/intelligence/rules HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + viewerCookie +
          "\r\nX-CSRF-Token: " + viewerCsrf +
          "\r\nContent-Length: " + std::to_string(ruleAddBody.size()) + "\r\n\r\n" + ruleAddBody);
  CHECK(ruleViewerResp.find("403 Forbidden") != std::string::npos);

  // Admin CAN create rule + Security firewall requires confirm:true
  std::string ruleAdminResp = sendRawHttp(
      port,
      "POST /api/v1/intelligence/rules HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(ruleAddBody.size()) + "\r\n\r\n" + ruleAddBody);
  CHECK(ruleAdminResp.find("200 OK") != std::string::npos);
  CHECK(ruleAdminResp.find("HTTP Rule") != std::string::npos);

  std::string listAddBody = R"({"listKind":"allowlist","targetType":"ip","targetValue":"8.8.8.8","reason":"DNS"})";
  std::string listAddResp = sendRawHttp(
      port,
      "POST /api/v1/security/lists HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(listAddBody.size()) + "\r\n\r\n" + listAddBody);
  CHECK(listAddResp.find("200 OK") != std::string::npos);
  CHECK(listAddResp.find("8.8.8.8") != std::string::npos);

  std::string fwNoConfirm = R"({"ruleName":"TestBlock","direction":"out","action":"block","protocol":"TCP","remoteIp":"203.0.113.50","remotePort":4444,"applyToOs":false})";
  std::string fwNoConfResp = sendRawHttp(
      port,
      "POST /api/v1/security/firewall HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(fwNoConfirm.size()) + "\r\n\r\n" + fwNoConfirm);
  CHECK(fwNoConfResp.find("confirmation_required") != std::string::npos);

  std::string fwConfirmBody = R"({"ruleName":"TestBlock","direction":"out","action":"block","protocol":"TCP","remoteIp":"203.0.113.50","remotePort":4444,"applyToOs":false,"confirm":true})";
  std::string fwOkResp = sendRawHttp(
      port,
      "POST /api/v1/security/firewall HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(fwConfirmBody.size()) + "\r\n\r\n" + fwConfirmBody);
  CHECK(fwOkResp.find("200 OK") != std::string::npos);
  CHECK(fwOkResp.find("NetPulse_TestBlock") != std::string::npos);

  // 19. Fase 8 NOC consolidated read-only endpoint (unauth -> 401, Viewer -> 200 valid JSON)
  std::string nocUnauth = sendRawHttp(
      port,
      "GET /api/v1/noc/overview HTTP/1.1\r\nHost: " + hostHdr + "\r\n\r\n");
  CHECK(nocUnauth.find("401 Unauthorized") != std::string::npos);

  std::string nocResp = sendRawHttp(
      port,
      "GET /api/v1/noc/overview?range=24h HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer " + viewerTok + "\r\n\r\n");
  CHECK(nocResp.find("200 OK") != std::string::npos);
  const std::string nocBody = extractJsonBody(nocResp);
  JsonValue nocJson;
  std::string nocErr;
  CHECK(JsonValue::parse(nocBody, nocJson, nocErr, 524288));
  CHECK(nocJson.getString("mode") == "noc_readonly");
  CHECK(nocJson.getBool("readOnly", false));
  CHECK(!nocJson.getBool("aiUsed", true));
  CHECK(nocJson.get("snapshot") != nullptr);
  CHECK(nocJson.get("quality") != nullptr);
  CHECK(nocJson.get("interfaces") != nullptr);
  CHECK(nocJson.get("discovery") != nullptr);
  CHECK(nocJson.get("intelligence") != nullptr);
  CHECK(nocJson.get("services") != nullptr);
  CHECK(nocJson.get("analytics") != nullptr);
  CHECK(nocJson.get("storage") != nullptr);
  CHECK(nocJson.get("traceHistory") != nullptr);

  // 20. Fase 9 Prometheus /metrics, OpenAPI v1 JSON & Notifications HTTP/RBAC
  std::string metricsUnauth = sendRawHttp(
      port,
      "GET /metrics HTTP/1.1\r\nHost: " + hostHdr + "\r\n\r\n");
  CHECK(metricsUnauth.find("401 Unauthorized") != std::string::npos);

  std::string metricsResp = sendRawHttp(
      port,
      "GET /metrics HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer " + viewerTok + "\r\n\r\n");
  CHECK(metricsResp.find("200 OK") != std::string::npos);
  CHECK(metricsResp.find("netpulse_info{version=") != std::string::npos);
  CHECK(metricsResp.find("netpulse_connections_active") != std::string::npos);

  std::string openApiResp = sendRawHttp(
      port,
      "GET /api/v1/openapi.json HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nAuthorization: Bearer " + viewerTok + "\r\n\r\n");
  CHECK(openApiResp.find("200 OK") != std::string::npos);
  const std::string openApiBody = extractJsonBody(openApiResp);
  JsonValue openApiJson;
  std::string oaErr;
  CHECK(JsonValue::parse(openApiBody, openApiJson, oaErr, 524288));
  CHECK(openApiJson.getString("openapi") == "3.0.3");
  CHECK(openApiBody.find("/api/v1/noc/overview") != std::string::npos);
  CHECK(openApiBody.find("/metrics") != std::string::npos);

  // Viewer cannot save notification channel (403); remote HTTP non-HTTPS rejected (400); valid HTTPS saved & secret masked
  std::string chAdd = R"({"name":"SOC Webhook","kind":"webhook","endpointUrl":"https://hooks.example.com/np","secretOrToken":"super_secret_key_9999","minSeverity":"warn","cooldownSec":60})";
  CHECK(sendRawHttp(
            port,
            "POST /api/v1/notifications/channels HTTP/1.1\r\nHost: " + hostHdr +
                "\r\nCookie: np_session=" + viewerCookie +
                "\r\nX-CSRF-Token: " + viewerCsrf +
                "\r\nContent-Length: " + std::to_string(chAdd.size()) + "\r\n\r\n" + chAdd)
            .find("403 Forbidden") != std::string::npos);

  std::string chHttpRemote = R"({"name":"Insecure","kind":"webhook","endpointUrl":"http://evil.example.com/hook"})";
  CHECK(sendRawHttp(
            port,
            "POST /api/v1/notifications/channels HTTP/1.1\r\nHost: " + hostHdr +
                "\r\nCookie: np_session=" + admCookie +
                "\r\nX-CSRF-Token: " + admCsrf +
                "\r\nContent-Length: " + std::to_string(chHttpRemote.size()) + "\r\n\r\n" + chHttpRemote)
            .find("invalid_notification_channel") != std::string::npos);

  std::string chOkResp = sendRawHttp(
      port,
      "POST /api/v1/notifications/channels HTTP/1.1\r\nHost: " + hostHdr +
          "\r\nCookie: np_session=" + admCookie +
          "\r\nX-CSRF-Token: " + admCsrf +
          "\r\nContent-Length: " + std::to_string(chAdd.size()) + "\r\n\r\n" + chAdd);
  CHECK(chOkResp.find("200 OK") != std::string::npos);
  CHECK(chOkResp.find("SOC Webhook") != std::string::npos);
  CHECK(chOkResp.find("super_secret_key_9999") == std::string::npos);
  CHECK(chOkResp.find("***9999") != std::string::npos);

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
    CHECK(stats.find("\"schemaVersion\":7") != std::string::npos);

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
  s1.interfaces.push_back({1, "if-1", "Ethernet WAN1", "", "ethernet", "", "up", true, true, true, true});
  s1.interfaces.push_back({2, "if-2", "LTE Failover", "", "ethernet", "", "down", false, true, false, true});

  s2.primaryIfId = "if-2";
  s2.primaryIfName = "LTE Failover";
  s2.primaryGateway = "10.0.0.1";
  s2.interfaces.push_back({1, "if-1", "Ethernet WAN1", "", "ethernet", "", "down", false, true, false, true});
  s2.interfaces.push_back({2, "if-2", "LTE Failover", "", "ethernet", "", "up", true, true, true, true});

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
        {nowMs - 20ULL * 86400000ULL, "test-eth", "eth0", "ethernet", "up", true, 1000000000ULL, 1234.0, 567.0, 1000, 500, 0, 0},
        {nowMs - 5000ULL, "test-eth", "eth0", "ethernet", "up", true, 1000000000ULL, 2345.0, 890.0, 3000, 1500, 1, 0},
    });
    hist.flushNow();

    std::string hJson = hist.queryInterfaceHistoryJson("test-eth", "1h");
    CHECK(hJson.find("2345.0") != std::string::npos);

    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    std::string allAfter = hist.queryInterfaceHistoryJson("test-eth", "30d");
    CHECK(allAfter.find("1234.0") == std::string::npos);
    CHECK(allAfter.find("2345.0") != std::string::npos);
    hist.stop();
  }
  std::filesystem::remove_all(ifDir, ec);

  std::cout << "[PASS] testMultiWanAndInterfaces\n";
  return 0;
}

int testDiscoveryEngineAndOui() {
  // 1. MAC normalization, LAA randomized bit detection & OUI lookup
  CHECK(normalizeMacUpper("b8-69-f4-11-22-33") == "B8:69:F4:11:22:33");
  CHECK(lookupOuiVendor("b8:69:f4:01:02:03") == "MikroTik");
  CHECK(lookupOuiVendor("18-e8-29-aa-bb-cc") == "Ubiquiti");
  CHECK(lookupOuiVendor("24:0a:c4:99:88:77") == "Espressif IoT");
  CHECK(isLocallyAdministeredMac("02:11:22:33:44:55"));
  CHECK(!isLocallyAdministeredMac("B8:69:F4:01:02:03"));
  CHECK(lookupOuiVendor("02:AA:BB:CC:DD:EE") == "MAC Privado / Randomizado");

  // 2. Deterministic device type inference
  CHECK(inferDeviceType(true, false, "", "", {}) == "Estação Local");
  CHECK(inferDeviceType(false, true, "MikroTik", "", {}) == "Roteador / Gateway");
  CHECK(inferDeviceType(false, false, "", "", {9100}) == "Impressora");
  CHECK(inferDeviceType(false, false, "Intelbras", "", {554}) == "Câmera / NVR");
  CHECK(inferDeviceType(false, false, "VMware", "", {}) == "Máquina Virtual");
  CHECK(inferDeviceType(false, false, "Synology", "", {22, 445}) == "Servidor / NAS");

  // 3. Subnet enumeration (.1 .. .254, capped cleanly)
  auto hosts = enumerateSubnetHosts("192.168.10.55/24");
  CHECK(hosts.size() == 254);
  CHECK(hosts.front() == "192.168.10.1");
  CHECK(hosts.back() == "192.168.10.254");

  // 4. SQLite persistence, labeling, passive harvest & retention pruning
  auto dDir = std::filesystem::temp_directory_path() / "netpulse_discovery_sqlite_test";
  std::error_code ec;
  std::filesystem::remove_all(dDir, ec);
  {
    HistoryStore hist(dDir);
    InterfaceMonitor ifMon(&hist);
    DiscoveryEngine eng(hist, ifMon);

    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    LanDeviceRecord devOld;
    devOld.deviceKey = "AA:BB:CC:11:22:33";
    devOld.ip = "192.168.2.99";
    devOld.mac = "AA:BB:CC:11:22:33";
    devOld.vendor = "Apple";
    devOld.deviceType = "Dispositivo Móvel";
    devOld.online = false;
    devOld.firstSeenMs = nowMs - 20ULL * 86400000ULL;
    devOld.lastSeenMs = nowMs - 20ULL * 86400000ULL;

    LanDeviceRecord devNew;
    devNew.deviceKey = "B8:69:F4:AA:BB:CC";
    devNew.ip = "192.168.2.1";
    devNew.mac = "B8:69:F4:AA:BB:CC";
    devNew.vendor = "MikroTik";
    devNew.deviceType = "Roteador / Gateway";
    devNew.isGateway = true;
    devNew.online = true;
    devNew.openPorts = "53,80,443";
    devNew.firstSeenMs = nowMs - 1000;
    devNew.lastSeenMs = nowMs;

    CHECK(hist.upsertLanDevices({devOld, devNew}, false));
    CHECK(hist.setLanDeviceLabel("B8:69:F4:AA:BB:CC", "Core Router"));

    CHECK(eng.runPassiveRefresh());
    std::string j = eng.getDevicesJson();
    CHECK(j.find("Core Router") != std::string::npos);
    CHECK(j.find("MikroTik") != std::string::npos);

    hist.setRetentionConfig(7, 128);
    CHECK(hist.pruneNow());
    auto loaded = hist.loadLanDevices();
    bool hasOld = false, hasNew = false;
    for (const auto& d : loaded) {
      if (d.deviceKey == "AA:BB:CC:11:22:33") hasOld = true;
      if (d.deviceKey == "B8:69:F4:AA:BB:CC") hasNew = true;
    }
    CHECK(!hasOld);
    CHECK(hasNew);
    eng.stop();
    hist.stop();
  }
  std::filesystem::remove_all(dDir, ec);

  std::cout << "[PASS] testDiscoveryEngineAndOui\n";
  return 0;
}

int testLanTopologyBuilder() {
  InterfaceInventorySnapshot ifSnap;
  ifSnap.primaryIfId = "if-1";
  ifSnap.primaryIfName = "Ethernet0";
  ifSnap.primaryGateway = "192.168.10.1";
  ifSnap.totalRxBps = 50000.0;
  ifSnap.totalTxBps = 12000.0;

  NetworkInterfaceInfo eth;
  eth.id = "if-1";
  eth.ifIndex = 1;
  eth.name = "Ethernet0";
  eth.description = "Intel PCIe GbE";
  eth.type = "ethernet";
  eth.operStatus = "up";
  eth.hardwareInterface = true;
  eth.isDefaultRoute = true;
  eth.isWanCandidate = true;
  eth.linkSpeedBps = 1000000000ULL;
  eth.ipv4 = {"192.168.10.25"};
  eth.gateways = {"192.168.10.1"};
  eth.dnsServers = {"1.1.1.1"};
  eth.rxBps = 50000.0;
  eth.txBps = 12000.0;

  NetworkInterfaceInfo lo;
  lo.id = "if-2";
  lo.ifIndex = 2;
  lo.name = "Loopback";
  lo.type = "loopback";
  lo.operStatus = "up";
  ifSnap.interfaces = {eth, lo};

  LanDeviceRecord gwDev;
  gwDev.deviceKey = "B8:69:F4:01:02:03";
  gwDev.ip = "192.168.10.1";
  gwDev.mac = "B8:69:F4:01:02:03";
  gwDev.vendor = "MikroTik";
  gwDev.deviceType = "Roteador / Gateway";
  gwDev.interfaceName = "Ethernet0";
  gwDev.subnet = "192.168.10.0/24";
  gwDev.isGateway = true;
  gwDev.online = true;
  gwDev.openPorts = "53,80";

  LanDeviceRecord nasDev;
  nasDev.deviceKey = "00:11:32:AA:BB:CC";
  nasDev.ip = "192.168.10.50";
  nasDev.mac = "00:11:32:AA:BB:CC";
  nasDev.vendor = "Synology";
  nasDev.hostname = "nas-matriz";
  nasDev.deviceType = "Servidor / NAS";
  nasDev.interfaceName = "Ethernet0";
  nasDev.subnet = "192.168.10.0/24";
  nasDev.online = true;
  nasDev.latencyMs = 1.4;
  nasDev.openPorts = "22,445";

  QualityTargetSnapshot qDns;
  qDns.target.host = "1.1.1.1";
  qDns.status = "ok";
  qDns.metrics.okCount = 5;
  qDns.metrics.p50Ms = 14.2;
  qDns.metrics.avgDnsMs = 13.5;

  TelemetrySnapshot tel;
  tel.totalConnections = 12;
  tel.publicConnections = 10;
  SocketEntry sock;
  sock.key = "TCP:50001:192.168.10.50:445:1234";
  sock.protocol = "TCP";
  sock.localIp = "192.168.10.25";
  sock.remoteIp = "192.168.10.50";
  sock.remotePort = 445;
  sock.processName = "explorer.exe";
  sock.scope = IpScope::Lan;
  tel.connections = {sock};

  auto topo = buildLanTopology(1700000000000ULL, "WORKSTATION-01", ifSnap, {gwDev, nasDev}, {qDns}, &tel);
  CHECK(topo.totalDevices == 1);
  CHECK(topo.onlineDevices == 1);
  CHECK(topo.activeSockets == 12);

  std::unordered_set<std::string> nodeIds;
  for (const auto& n : topo.nodes) nodeIds.insert(n.id);
  CHECK(nodeIds.count("host:local") == 1);
  CHECK(nodeIds.count("iface:if-1") == 1);
  CHECK(nodeIds.count("iface:if-2") == 0); // loopback excluded
  CHECK(nodeIds.count("gw:192.168.10.1") == 1);
  CHECK(nodeIds.count("dns:1.1.1.1") == 1);
  CHECK(nodeIds.count("upstream:internet") == 1);
  CHECK(nodeIds.count("dev:00:11:32:AA:BB:CC") == 1);

  bool hasDefaultRoute = false, hasArpSubnet = false, hasActiveSocket = false, hasDnsEdge = false;
  for (const auto& e : topo.edges) {
    CHECK(nodeIds.count(e.source) == 1);
    CHECK(nodeIds.count(e.target) == 1);
    CHECK(!e.evidence.empty());
    if (e.kind == "default_route") hasDefaultRoute = true;
    if (e.kind == "arp_subnet") hasArpSubnet = true;
    if (e.kind == "active_socket" && e.target == "dev:00:11:32:AA:BB:CC") hasActiveSocket = true;
    if (e.kind == "dns_config") hasDnsEdge = true;
  }
  CHECK(hasDefaultRoute && hasArpSubnet && hasActiveSocket && hasDnsEdge);

  const std::string topoJson = serializeLanTopologyJson(topo);
  JsonValue parsed;
  std::string jerr;
  CHECK(JsonValue::parse(topoJson, parsed, jerr));
  CHECK(topoJson.find("nas-matriz") != std::string::npos);
  CHECK(topoJson.find("explorer.exe") != std::string::npos);

  std::cout << "[PASS] testLanTopologyBuilder\n";
  return 0;
}

int testIntelligenceAndSecurityEngine() {
  // 1. Pure helpers: risk scale & unusual paths
  CHECK(riskLevelFromScore(0) == "informative");
  CHECK(riskLevelFromScore(19) == "informative");
  CHECK(riskLevelFromScore(20) == "low");
  CHECK(riskLevelFromScore(40) == "moderate");
  CHECK(riskLevelFromScore(60) == "high");
  CHECK(riskLevelFromScore(80) == "critical");
  CHECK(riskLevelFromScore(100) == "critical");

  CHECK(isUnusualExecutablePath("C:\\Users\\Alice\\AppData\\Local\\Temp\\dropper.exe"));
  CHECK(isUnusualExecutablePath("C:\\Users\\Public\\tool.exe"));
  CHECK(isUnusualExecutablePath("/tmp/payload"));
  CHECK(!isUnusualExecutablePath("C:\\Program Files\\Mozilla Firefox\\firefox.exe"));

  std::filesystem::path dir = std::filesystem::temp_directory_path() / "netpulse_fase7_intel_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);

  HistoryStore history(dir);
  IntelligenceEngine intel(history);
  GeoDnsService geoDns(dir / "geo.tsv");

  // 2. Verify seeded deterministic rules + CRUD for user custom rule
  const std::string initJson = intel.getOverviewJson();
  CHECK(initJson.find("\"engineMode\":\"deterministic\"") != std::string::npos);
  CHECK(initJson.find("\"aiUsed\":false") != std::string::npos);
  CHECK(initJson.find("builtin-sensitive-port") != std::string::npos);
  CHECK(!intel.deleteRule("builtin-sensitive-port")); // builtin protected

  SecurityRuleRecord customRule;
  customRule.name = "Watcher New Proc";
  customRule.kind = "new_external_process";
  customRule.enabled = true;
  customRule.riskWeight = 45;
  CHECK(intel.upsertRule(customRule));
  CHECK(!customRule.id.empty());

  // 3. Evaluate telemetry: unusual path + sensitive port (4444) + SYN_SENT flood + persistent conn
  const uint64_t t0 = 1700001000000ULL;
  TelemetrySnapshot snap;
  snap.timestampMs = t0;
  snap.nic.rxBytesPerSec = 100000.0;
  snap.nic.txBytesPerSec = 50000.0;
  snap.nic.activeInterfaces = 1;
  snap.publicConnections = 5;

  SocketEntry s1;
  s1.key = "TCP:51000:198.51.100.77:4444:9001";
  s1.protocol = "TCP";
  s1.localIp = "192.168.1.20";
  s1.remoteIp = "198.51.100.77";
  s1.localPort = 51000;
  s1.remotePort = 4444; // sensitive port
  s1.state = "ESTABLISHED";
  s1.pid = 9001;
  s1.processName = "sketchy.exe";
  s1.processPath = "C:\\Users\\Alice\\Downloads\\sketchy.exe";
  s1.scope = IpScope::Public;
  s1.firstSeenMs = t0 - 3600000ULL; // 1h persistent

  snap.connections.push_back(s1);
  for (int i = 0; i < 4; ++i) {
    SocketEntry sf = s1;
    sf.key = "TCP:" + std::to_string(51001 + i) + ":198.51.100." + std::to_string(80 + i) + ":443:9001";
    sf.remoteIp = "198.51.100." + std::to_string(80 + i);
    sf.remotePort = 443;
    sf.state = "SYN_SENT";
    snap.connections.push_back(sf);
  }
  ProcessBandwidth pb;
  pb.pid = 9001;
  pb.processName = "sketchy.exe";
  pb.processPath = s1.processPath;
  pb.connections = 5;
  pb.publicConnections = 5;
  pb.rxBps = 200000.0;
  pb.txBps = 200000.0;
  snap.processStats.push_back(pb);

  intel.processTelemetry(snap, geoDns);
  auto alerts = intel.getRecentAlertsSnapshot(50);
  bool sawUnusualPath = false, sawSensPort = false, sawPersistent = false, sawSynSent = false, sawNewProc = false;
  int64_t ackTargetId = 0;
  for (const auto& a : alerts) {
    if (ackTargetId == 0 && a.id > 0) ackTargetId = a.id;
    if (a.ruleId == "builtin-unusual-path") sawUnusualPath = true;
    if (a.ruleId == "builtin-sensitive-port") sawSensPort = true;
    if (a.ruleId == "builtin-persistent-conn") sawPersistent = true;
    if (a.ruleId == "builtin-failed-conns") sawSynSent = true;
    if (a.ruleId == customRule.id) sawNewProc = true;
  }
  CHECK(sawUnusualPath);
  CHECK(sawSensPort);
  CHECK(sawPersistent);
  CHECK(sawSynSent);
  CHECK(sawNewProc);
  CHECK(ackTargetId > 0);
  CHECK(intel.acknowledgeAlert(ackTargetId));

  // 4. Blocklist & Allowlist enforcement
  SecurityListEntry blkEntry;
  std::string listErr;
  CHECK(intel.addListEntry("blocklist", "ip", "203.0.113.99", "C2 block test", "tester", blkEntry, listErr));

  TelemetrySnapshot snap2;
  snap2.timestampMs = t0 + 60000ULL;
  snap2.publicConnections = 1;
  SocketEntry sBlk;
  sBlk.key = "TCP:52000:203.0.113.99:8443:9002";
  sBlk.protocol = "TCP";
  sBlk.remoteIp = "203.0.113.99";
  sBlk.remotePort = 8443;
  sBlk.state = "ESTABLISHED";
  sBlk.pid = 9002;
  sBlk.processName = "curl.exe";
  sBlk.scope = IpScope::Public;
  snap2.connections.push_back(sBlk);
  intel.processTelemetry(snap2, geoDns);

  alerts = intel.getRecentAlertsSnapshot(50);
  bool sawBlockHit = false;
  for (const auto& a : alerts) {
    if (a.ruleId == "sys-blocklist-hit") {
      sawBlockHit = true;
      CHECK(a.riskLevel == "critical");
      CHECK(a.riskScore == 90);
    }
  }
  CHECK(sawBlockHit);

  // 5. Granular firewall policy persistence & deletion + custom rule cleanup
  FirewallRuleRecord fw;
  std::string fwErr;
  CHECK(!intel.createFirewallRule("BadRule", "out", "block", "ANY", "127.0.0.1", 0, "", false, false, "tester", fw, fwErr));
  CHECK(intel.createFirewallRule("BlockTest203", "out", "block", "TCP", "203.0.113.99", 8443, "", false, false, "tester", fw, fwErr));
  const std::string fullOverview = intel.getOverviewJson();
  JsonValue parsedOverview;
  std::string overviewErr;
  CHECK(JsonValue::parse(fullOverview, parsedOverview, overviewErr, 262144));
  CHECK(parsedOverview.isObject());
  CHECK(fullOverview.find("NetPulse_BlockTest203") != std::string::npos);
  CHECK(intel.removeFirewallRuleById(fw.id, false, fwErr));
  CHECK(intel.removeListEntry(blkEntry.id));
  CHECK(intel.deleteRule(customRule.id));

  history.stop();
  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testIntelligenceAndSecurityEngine\n";
  return 0;
}

int testNotificationsPrometheusAndOpenApi() {
  // 1. Verify RFC 4231 HMAC-SHA256 test vector
  CHECK(hmacSha256Hex("Jefe", "what do ya want for nothing?") ==
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  // 2. Validate SSRF / scheme enforcement & Telegram builder
  std::string effUrl, uerr;
  CHECK(!validateNotificationTargetUrl("webhook", "http://example.com/hook", "", "", effUrl, uerr));
  CHECK(validateNotificationTargetUrl("webhook", "http://127.0.0.1:9999/hook", "", "", effUrl, uerr));
  CHECK(validateNotificationTargetUrl("webhook", "https://hooks.example.com/abc", "", "", effUrl, uerr));
  CHECK(validateNotificationTargetUrl("telegram", "", "123456:BOT_TOK", "-100998877", effUrl, uerr));
  CHECK(effUrl == "https://api.telegram.org/bot123456:BOT_TOK/sendMessage");

  // 3. Dispatch filter + cooldown logic
  NotificationChannelRecord ch;
  ch.id = "ch-1";
  ch.name = "Alert Discord";
  ch.kind = "discord";
  ch.enabled = true;
  ch.minSeverity = "warn";
  ch.cooldownSec = 60;

  NotificationEvent evInfo{1700000000000ULL, "service_up", "info", "Recovered", "DNS up", "netpulse"};
  NotificationEvent evCrit{1700000100000ULL, "security_alert", "critical", "Blocklist Hit", "1.2.3.4", "intelligence"};
  CHECK(!shouldDispatchToChannel(ch, evInfo, 0, evInfo.tsMs));
  CHECK(shouldDispatchToChannel(ch, evCrit, 1700000000000ULL, evCrit.tsMs));
  CHECK(!shouldDispatchToChannel(ch, evCrit, evCrit.tsMs - 15000ULL, evCrit.tsMs)); // inside cooldown

  const std::string discPayload = buildNotificationPayloadJson(ch, evCrit);
  JsonValue parsedDisc;
  std::string derr;
  CHECK(JsonValue::parse(discPayload, parsedDisc, derr));
  CHECK(discPayload.find("embeds") != std::string::npos);

  ch.kind = "telegram";
  ch.chatId = "-100998877";
  const std::string tgPayload = buildNotificationPayloadJson(ch, evCrit);
  CHECK(JsonValue::parse(tgPayload, parsedDisc, derr));
  CHECK(tgPayload.find("-100998877") != std::string::npos);

  // 4. SQLite Migration v7 persistence + secret masking & update preservation
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "netpulse_fase9_notif_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  HistoryStore history(dir);
  NotificationEngine engine(history);

  NotificationChannelRecord in;
  in.name = "Webhook Secreto";
  in.kind = "webhook";
  in.endpointUrl = "https://hooks.example.com/np";
  in.secretOrToken = "my_top_secret_token_abcd";
  in.minSeverity = "warn";
  in.cooldownSec = 30;
  NotificationChannelRecord saved;
  std::string serr;
  CHECK(engine.upsertChannel(in, saved, serr));
  CHECK(saved.secretOrToken == "***abcd");

  // Updating without resending secret must preserve existing secret
  in.id = saved.id;
  in.secretOrToken = "";
  in.cooldownSec = 120;
  CHECK(engine.upsertChannel(in, saved, serr));
  CHECK(saved.secretOrToken == "***abcd");
  CHECK(engine.getChannelsJson().find("my_top_secret_token_abcd") == std::string::npos);
  CHECK(engine.deleteChannel(saved.id));

  // 5. OpenAPI JSON parser check
  const std::string oa = buildOpenApiV1SpecJson("1.12.0");
  JsonValue oaVal;
  CHECK(JsonValue::parse(oa, oaVal, derr, 524288));
  CHECK(oaVal.getString("openapi") == "3.0.3");

  history.stop();
  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testNotificationsPrometheusAndOpenApi\n";
  return 0;
}

int testPlatformBenchmarksAndStabilization() {
  // 1. Kernel telemetry read latency benchmark across 5 cycles
  NetMonitor mon;
  uint64_t worstPollUs = 0;
  for (int i = 0; i < 5; ++i) {
    auto snap = mon.poll(1700005000000ULL + static_cast<uint64_t>(i) * 1000ULL);
    if (snap.pollLatencyUs > worstPollUs) worstPollUs = snap.pollLatencyUs;
  }
  CHECK(worstPollUs < 250000ULL);

  // 2. Large LAN topology build + serialize benchmark (128 LAN hosts + 50 active sockets)
  InterfaceInventorySnapshot ifSnap;
  NetworkInterfaceInfo nic;
  nic.id = "if-bench";
  nic.name = "eth0";
  nic.type = "ethernet";
  nic.operStatus = "up";
  nic.isDefaultRoute = true;
  nic.ipv4 = {"10.10.0.10"};
  nic.gateways = {"10.10.0.1"};
  nic.dnsServers = {"1.1.1.1"};
  ifSnap.interfaces = {nic};
  ifSnap.primaryIfId = "if-bench";
  ifSnap.primaryIfName = "eth0";
  ifSnap.primaryGateway = "10.10.0.1";

  std::vector<LanDeviceRecord> devs;
  devs.reserve(128);
  for (int i = 2; i <= 129; ++i) {
    LanDeviceRecord d;
    d.deviceKey = "mac:" + std::to_string(i);
    d.ip = "10.10.0." + std::to_string(i);
    d.mac = "00:11:22:33:44:" + std::to_string(10 + (i % 80));
    d.vendor = "BenchVendor";
    d.online = true;
    devs.push_back(std::move(d));
  }

  TelemetrySnapshot tel;
  tel.timestampMs = 1700005010000ULL;
  for (int i = 0; i < 50; ++i) {
    SocketEntry s;
    s.key = "TCP:" + std::to_string(40000 + i);
    s.protocol = "TCP";
    s.localIp = "10.10.0.10";
    s.remoteIp = "198.51.100." + std::to_string(1 + i);
    s.remotePort = 443;
    s.state = "ESTABLISHED";
    s.pid = static_cast<uint32_t>(1000 + i);
    s.processName = "worker.exe";
    s.scope = IpScope::Public;
    tel.connections.push_back(std::move(s));
  }

  const auto tStart = std::chrono::steady_clock::now();
  auto topo = buildLanTopology(tel.timestampMs, "BENCH-HOST", ifSnap, devs, {}, &tel);
  const std::string topoJson = serializeLanTopologyJson(topo);
  const auto topoUs = std::chrono::duration_cast<std::chrono::microseconds>(
                          std::chrono::steady_clock::now() - tStart).count();
  CHECK(topo.totalDevices == 128);
  CHECK(!topoJson.empty());
  CHECK(topoUs < 100000);

  // 3. Intelligence burst stabilization (20 consecutive ticks -> cooldown stops alert storm)
  std::filesystem::path dir = std::filesystem::temp_directory_path() / "netpulse_fase10_bench_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  HistoryStore history(dir);
  IntelligenceEngine intel(history);
  GeoDnsService geoDns(dir / "geo.tsv");

  TelemetrySnapshot burstSnap;
  burstSnap.nic.activeInterfaces = 1;
  burstSnap.publicConnections = 5;
  SocketEntry bs;
  bs.key = "TCP:60001:198.51.100.200:4444:777";
  bs.protocol = "TCP";
  bs.remoteIp = "198.51.100.200";
  bs.remotePort = 4444;
  bs.state = "ESTABLISHED";
  bs.pid = 777;
  bs.processName = "burst.exe";
  bs.scope = IpScope::Public;
  burstSnap.connections.push_back(bs);

  for (int t = 0; t < 20; ++t) {
    burstSnap.timestampMs = 1700005100000ULL + static_cast<uint64_t>(t) * 1000ULL;
    intel.processTelemetry(burstSnap, geoDns);
  }
  const auto alertsAfterBurst = intel.getRecentAlertsSnapshot(100);
  CHECK(alertsAfterBurst.size() <= 4); // Cooldown prevents repeated duplicate alert storm

  // 4. OpenAPI & JSON throughput benchmark
  const auto oaStart = std::chrono::steady_clock::now();
  for (int i = 0; i < 10; ++i) {
    volatile size_t sz = buildOpenApiV1SpecJson("2.0.0").size();
    CHECK(sz > 1000);
  }
  const auto oaMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - oaStart).count();
  CHECK(oaMs < 500);

  std::cout << "  [BENCH] poll_worst=" << worstPollUs << "us, topo128=" << topoUs
            << "us, openapi10x=" << oaMs << "ms, burstAlerts=" << alertsAfterBurst.size() << "\n";

  history.stop();
  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testPlatformBenchmarksAndStabilization\n";
  return 0;
}

int testSatelliteTrackingV1() {
  using namespace netpulse::satellite;

  std::filesystem::path dir = std::filesystem::temp_directory_path() / "netpulse_satellite_v1_test";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  std::filesystem::create_directories(dir, ec);

  // 1. OMM JSON parsing (ISS 25544 & Tiangong 48274)
  const std::string ommSample = R"JSON([
    {
      "OBJECT_NAME": "ISS (ZARYA)",
      "OBJECT_ID": "1998-067A",
      "EPOCH": "2026-11-18T12:00:00.000000",
      "MEAN_MOTION": 15.49501234,
      "ECCENTRICITY": 0.0006234,
      "INCLINATION": 51.6416,
      "RA_OF_ASC_NODE": 120.4567,
      "ARG_OF_PERICENTER": 45.1234,
      "MEAN_ANOMALY": 314.8765,
      "EPHEMERIS_TYPE": 0,
      "CLASSIFICATION_TYPE": "U",
      "NORAD_CAT_ID": 25544,
      "ELEMENT_SET_NO": 999,
      "REV_AT_EPOCH": 48123,
      "BSTAR": 0.00012345,
      "MEAN_MOTION_DOT": 0.00015000,
      "MEAN_MOTION_DDOT": 0
    },
    {
      "OBJECT_NAME": "CSS (TIANHE)",
      "OBJECT_ID": "2021-035A",
      "EPOCH": "2026-11-18T12:00:00.000000",
      "MEAN_MOTION": "15.61204567",
      "ECCENTRICITY": "0.0005120",
      "INCLINATION": "41.4742",
      "RA_OF_ASC_NODE": "210.1234",
      "ARG_OF_PERICENTER": "92.3456",
      "MEAN_ANOMALY": "267.6543",
      "EPHEMERIS_TYPE": 0,
      "CLASSIFICATION_TYPE": "U",
      "NORAD_CAT_ID": 48274,
      "ELEMENT_SET_NO": 512,
      "REV_AT_EPOCH": 21500,
      "BSTAR": "0.00011000"
    }
  ])JSON";

  std::vector<OrbitalElements> ommEls;
  std::string err;
  CHECK(SatelliteCatalog::parseOmmJson(ommSample, ommEls, err));
  CHECK(ommEls.size() == 2);
  CHECK(ommEls[0].noradId == kNoradIss);
  CHECK(ommEls[0].intlDesignator == "1998-067A");
  CHECK(std::abs(ommEls[0].inclinationDeg - 51.6416) < 1e-4);
  CHECK(ommEls[1].noradId == kNoradTiangong);
  CHECK(ommEls[1].intlDesignator == "2021-035A");
  CHECK(std::abs(ommEls[1].inclinationDeg - 41.4742) < 1e-4);

  // 2. TLE parsing & Vallado AIAA 2006-6753 SGP4 Reference Vector (Sat #00005)
  const std::string valladoTle =
      "VANGUARD 1\n"
      "1 00005U 58002B   00179.78495062  .00000023  00000-0  28098-4 0  4753\n"
      "2 00005  34.2682 348.7242 1859667 331.7664  19.3264 10.82419157413667\n";
  std::vector<OrbitalElements> tleEls;
  CHECK(SatelliteCatalog::parseTleText(valladoTle, tleEls, err));
  CHECK(tleEls.size() == 1);
  CHECK(tleEls[0].noradId == 5);
  CHECK(std::abs(tleEls[0].eccentricity - 0.1859667) < 1e-7);
  CHECK(std::abs(tleEls[0].bstar - 0.28098e-4) < 1e-9);

  Vec3 r0{}, v0{};
  CHECK(OrbitalPropagator::propagateTemeAtTsince(tleEls[0], 0.0, r0, v0, err));
  // Vallado AIAA-2006-6753 Sat #00005 at t=0: r=[7022.46529266, -1400.08296755, 0.03995155] km
  CHECK(std::abs(r0.x - 7022.46529) < 0.01);
  CHECK(std::abs(r0.y - (-1400.08297)) < 0.01);
  CHECK(std::abs(r0.z - 0.03995) < 0.01);
  CHECK(std::abs(v0.x - 1.89384) < 0.001);
  CHECK(std::abs(v0.y - 6.40589) < 0.001);
  CHECK(std::abs(v0.z - 4.53481) < 0.001);

  Vec3 r360{}, v360{};
  CHECK(OrbitalPropagator::propagateTemeAtTsince(tleEls[0], 360.0, r360, v360, err));
  // Vallado AIAA-2006-6753 Sat #00005 at t=360: r=[-7154.03120202, -3783.17682504, -3536.19412294] km
  CHECK(std::abs(r360.x - (-7154.03120)) < 0.05);
  CHECK(std::abs(r360.y - (-3783.17683)) < 0.05);
  CHECK(std::abs(r360.z - (-3536.19412)) < 0.05);

  // 3. Geodetic conversion, GMST, ISS/Tiangong lat/lon/alt/vel & antimeridian track split
  const double gmstJ2000 = OrbitalPropagator::computeGmstRadians(2451545.0, 0.0);
  // At J2000.0, GMST = 280.46061837 deg = 4.89496121 rad
  CHECK(std::abs(gmstJ2000 - 4.89496121) < 1e-4);

  // Test equatorial TEME point rotated by GMST -> lon ~ 0, lat ~ 0, alt ~ 420 km
  const Vec3 eqTeme{6798.137 * std::cos(gmstJ2000), 6798.137 * std::sin(gmstJ2000), 0.0};
  const GeodeticState eqGeo = OrbitalPropagator::temeToGeodetic(eqTeme, 2451545.0, 0.0);
  CHECK(std::abs(eqGeo.latitudeDeg) < 1e-4);
  CHECK(std::abs(eqGeo.longitudeDeg) < 1e-4);
  CHECK(std::abs(eqGeo.altitudeKm - 420.0) < 0.1);

  SatellitePosition issPos;
  CHECK(OrbitalPropagator::propagate(ommEls[0], ommEls[0].epochMs + 15ULL * 60000ULL, issPos, err));
  CHECK(issPos.valid);
  CHECK(issPos.latitudeDeg >= -52.5 && issPos.latitudeDeg <= 52.5);
  CHECK(issPos.longitudeDeg >= -180.0 && issPos.longitudeDeg <= 180.0);
  CHECK(issPos.altitudeKm > 350.0 && issPos.altitudeKm < 480.0);
  CHECK(issPos.velocityKmS > 7.4 && issPos.velocityKmS < 7.9);

  SatelliteTrack issTrack;
  CHECK(OrbitalPropagator::propagateTrack(ommEls[0], ommEls[0].epochMs, 45, 90, 60, issTrack, err));
  CHECK(!issTrack.pastSegments.empty());
  CHECK(!issTrack.futureSegments.empty());
  for (const auto& seg : issTrack.futureSegments) {
    for (size_t i = 1; i < seg.size(); ++i) {
      CHECK(std::abs(seg[i].lon - seg[i - 1].lon) <= 180.001);
    }
  }

  // Explicit antimeridian split test (+179 -> -179)
  std::vector<TrackPoint> crossPts{
      {178.0, 10.0, 420.0, 0},
      {179.5, 11.0, 420.0, 60},
      {-179.0, 12.0, 420.0, 120},
      {-177.0, 13.0, 420.0, 180},
  };
  auto splitCross = OrbitalPropagator::splitAntimeridianSegments(crossPts);
  CHECK(splitCross.size() == 2);
  CHECK(std::abs(splitCross[0].back().lon - 180.0) < 1e-6);
  CHECK(std::abs(splitCross[1].front().lon - (-180.0)) < 1e-6);
  CHECK(std::abs(splitCross[0].back().lat - splitCross[1].front().lat) < 1e-6);

  // 4. Invalid data handling (bad TLE checksum, mismatched NORAD, out-of-range OMM)
  std::vector<OrbitalElements> badOut;
  const std::string badChecksumTle =
      "1 25544U 98067A   26322.50000000  .00015000  00000-0  12345-3 0  9990\n"
      "2 25544  51.6416 120.4567 0006234  45.1234 314.8765 15.49501234481239\n";
  CHECK(!SatelliteCatalog::parseTleText(badChecksumTle, badOut, err));

  const std::string badOmmEcc = R"([{"NORAD_CAT_ID":25544,"EPOCH":"2026-11-18T12:00:00Z","MEAN_MOTION":15.5,"ECCENTRICITY":1.2,"INCLINATION":51.6,"RA_OF_ASC_NODE":0,"ARG_OF_PERICENTER":0,"MEAN_ANOMALY":0}])";
  CHECK(!SatelliteCatalog::parseOmmJson(badOmmEcc, badOut, err));

  // 5. Catalog cache + connection failure resilience (must NOT discard valid cache)
  const auto cachePath = dir / "satellite_catalog_cache.json";
  int fetchCalls = 0;
  {
    SatelliteCatalog cat(cachePath);
    cat.setHttpFetcher([&](const std::string& url) -> HttpFetchResult {
      ++fetchCalls;
      if (url.find("GROUP=stations") != std::string::npos) {
        return HttpFetchResult{true, 200, ommSample, ""};
      }
      return HttpFetchResult{false, 404, "", "not_found"};
    });
    const uint64_t t0 = ommEls[0].epochMs;
    CHECK(cat.refreshFromSource(t0, true, err));
    CHECK(fetchCalls == 1);
    CHECK(!cat.shouldAutoRefresh(t0 + 60000ULL, 21600)); // Avoid repeated downloads within TTL
  }

  {
    // New catalog instance loads cache from disk offline, then survives connection failure
    SatelliteCatalog cat2(cachePath);
    CHECK(cat2.loadCache());
    auto issEntry = cat2.getEntry(kNoradIss);
    auto tgEntry = cat2.getEntry(kNoradTiangong);
    CHECK(issEntry.has_value() && issEntry->elements.valid && issEntry->dataState == CatalogDataState::Cached);
    CHECK(tgEntry.has_value() && tgEntry->elements.valid && tgEntry->dataState == CatalogDataState::Cached);

    cat2.setHttpFetcher([](const std::string&) -> HttpFetchResult {
      return HttpFetchResult{false, 0, "", "simulated_network_down"};
    });
    CHECK(!cat2.refreshFromSource(ommEls[0].epochMs + 100000ULL, true, err));
    auto issAfterFail = cat2.getEntry(kNoradIss);
    CHECK(issAfterFail.has_value());
    CHECK(issAfterFail->elements.valid); // Never discarded!
    CHECK(issAfterFail->dataState == CatalogDataState::CachedFallback);
    CHECK(!issAfterFail->lastError.empty());
  }

  // 6. Configuration persistence, activation/deactivation, suspension & live HTTP API integration
  const auto cfgPath = dir / "satellite_settings.tsv";
  SatelliteConfiguration satCfg(cfgPath);
  SatelliteCatalog cat3(cachePath);
  CHECK(cat3.loadCache());
  SatelliteManager satMgr(cat3, satCfg);
  SatellitePositionService satSvc(satMgr);

  // Both active initially
  CHECK(satMgr.hasActiveTargets());
  CHECK(!satSvc.isSuspended());
  const std::string snapAll = satSvc.getSnapshotJson();
  CHECK(snapAll.find("\"noradId\":25544") != std::string::npos);
  CHECK(snapAll.find("\"noradId\":48274") != std::string::npos);
  CHECK(snapAll.find("\"active\":true") != std::string::npos);

  // Wire ApiRouter and verify HTTP GET/POST endpoints
  AuthManager auth(dir, "np_adm_sat_test_token_123456");
  AuditLog audit(dir / "audit.tsv");
  RateLimiter authLim(10, 60000, 60000);
  ServiceMonitor svcMon(dir / "svc.tsv");
  GeoDnsService geoDns(dir / "geo.tsv");
  HistoryStore history(dir);
  TracerouteService tracer(geoDns, &history);
  SettingsStore settings(dir / "settings.tsv");
  UpdateManager updater("2.0.0", nullptr);
  ApiRouter router(ApiDependencies{
      auth, audit, authLim, svcMon, tracer, settings, history, updater, dir, false, false,
      []() { return "{}"; }, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
      &satMgr, &satSvc});

  HttpRequest getSatReq;
  getSatReq.method = "GET";
  getSatReq.path = "/api/v1/satellites";
  getSatReq.remoteIp = "127.0.0.1";
  getSatReq.headers["authorization"] = "Bearer np_adm_sat_test_token_123456";
  HttpResponse rGet = router.handleHttp(getSatReq);
  CHECK(rGet.statusCode == 200);
  CHECK(rGet.body.find("\"ISS") != std::string::npos);
  CHECK(rGet.body.find("\"Tiangong") != std::string::npos);

  // Disable Tiangong individually via API
  HttpRequest postCfgReq;
  postCfgReq.method = "POST";
  postCfgReq.path = "/api/v1/satellites/config";
  postCfgReq.remoteIp = "127.0.0.1";
  postCfgReq.headers["authorization"] = "Bearer np_adm_sat_test_token_123456";
  postCfgReq.body = "{\"toggleNoradId\":48274,\"visible\":false,\"futureTrackMinutes\":120}";
  HttpResponse rPost = router.handleHttp(postCfgReq);
  CHECK(rPost.statusCode == 200);
  CHECK(!satCfg.isObjectVisible(kNoradTiangong));
  CHECK(satCfg.isObjectVisible(kNoradIss));
  CHECK(satCfg.get().futureTrackMinutes == 120);

  // Disable module layer -> suspends propagation calculations
  postCfgReq.body = "{\"enabled\":false}";
  HttpResponse rOff = router.handleHttp(postCfgReq);
  CHECK(rOff.statusCode == 200);
  CHECK(satSvc.isSuspended());

  // Re-enable module & verify persistence in new SatelliteConfiguration instance
  postCfgReq.body = "{\"enabled\":true,\"selectAll\":true}";
  HttpResponse rOn = router.handleHttp(postCfgReq);
  CHECK(rOn.statusCode == 200);
  CHECK(!satSvc.isSuspended());

  SatelliteConfiguration reloadedCfg(cfgPath);
  CHECK(reloadedCfg.get().enabled);
  CHECK(reloadedCfg.get().futureTrackMinutes == 120);
  CHECK(reloadedCfg.isObjectVisible(kNoradIss));
  CHECK(reloadedCfg.isObjectVisible(kNoradTiangong));

  // Verify Prometheus & OpenAPI include Satellite Tracking
  const std::string openApi = buildOpenApiV1SpecJson("2.0.0");
  CHECK(openApi.find("/api/v1/satellites") != std::string::npos);
  const std::string prom = formatPrometheusMetrics(ApiDependencies{
      auth, audit, authLim, svcMon, tracer, settings, history, updater, dir, false, false,
      []() { return "{}"; }, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
      &satMgr, &satSvc});
  CHECK(prom.find("netpulse_satellite_module_enabled 1") != std::string::npos);

  history.stop();
  std::filesystem::remove_all(dir, ec);
  std::cout << "[PASS] testSatelliteTrackingV1\n";
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
  rc |= testDiscoveryEngineAndOui();
  rc |= testLanTopologyBuilder();
  rc |= testIntelligenceAndSecurityEngine();
  rc |= testNotificationsPrometheusAndOpenApi();
  rc |= testPlatformBenchmarksAndStabilization();
  rc |= testSatelliteTrackingV1();

#ifdef _WIN32
  WSACleanup();
#endif
  if (rc == 0) {
    std::cout << "ALL C++ TESTS PASSED.\n";
  }
  return rc;
}
