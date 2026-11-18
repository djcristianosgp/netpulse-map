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
#include "../src/security/audit_log.hpp"
#include "../src/security/auth_manager.hpp"
#include "../src/security/rate_limiter.hpp"
#include "../src/security/tls_context.hpp"
#include "../src/serializer.hpp"
#include "../src/service_monitor.hpp"
#include "../src/settings_store.hpp"
#include "../src/traceroute.hpp"
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
  TracerouteService tracer(geoDns);
  SettingsStore settings(tempRoot / "data" / "settings.tsv");
  HistoryStore history(tempRoot / "data");
  UpdateManager updater("1.3.0", nullptr);

  std::string snapJson = serializeSnapshotJson(snap, geoDns, 1000, 0, &svcMon);
  ApiRouter router(ApiDependencies{
      auth, audit, authLimiter, svcMon, tracer, settings, history, updater,
      tempRoot / "data", false, false,
      [&]() { return snapJson; },
      nullptr, nullptr,
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
        << "notifyNewCountry\t0\n";
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
  CHECK(store.toJson().find("\"defaultView\":\"global\"") != std::string::npos);
  CHECK(store.toJson().find("\"notifyServiceDegraded\":false") != std::string::npos);

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

#ifdef _WIN32
  WSACleanup();
#endif
  if (rc == 0) {
    std::cout << "ALL C++ TESTS PASSED.\n";
  }
  return rc;
}
