#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "../src/geo_dns.hpp"
#include "../src/net_monitor.hpp"
#include "../src/serializer.hpp"
#include "../src/updater.hpp"
#include "../src/ws_server.hpp"

#include <cassert>
#include <chrono>
#include <cmath>
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

  // TSV cache roundtrip
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
  // Official RFC 6455 Section 1.3 vector
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

  std::cout << "[PASS] testWebSocketRfc6455\n";
  return 0;
}

int testLiveMonitorAndWsLoopback() {
  NetMonitor mon;
  uint64_t now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  auto snap = mon.poll(now);
  CHECK(snap.timestampMs == now);
  CHECK(snap.pollLatencyUs < 500000); // should be sub-millisecond or a few ms

  auto tempRoot = std::filesystem::temp_directory_path() / "netpulse_ws_test";
  std::error_code ec;
  std::filesystem::create_directories(tempRoot / "static", ec);
  std::filesystem::create_directories(tempRoot / "assets", ec);

  GeoDnsService geoDns(tempRoot / "cache.tsv");
  WsServer server(0, tempRoot / "static", tempRoot / "assets");
  server.setLatestSnapshotJson(serializeSnapshotJson(snap, geoDns, 300, 0));
  server.setHealthCallback([]() { return std::string("{\"status\":\"ok\"}"); });
  CHECK(server.start());
  CHECK(server.port() > 0);

  // Connect via TCP and perform HTTP GET /api/health
  SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(c != INVALID_SOCKET);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server.port());
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  CHECK(connect(c, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);

  const std::string httpReq = "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  send(c, httpReq.data(), static_cast<int>(httpReq.size()), 0);
  char buf[1024] = {};
  int n = recv(c, buf, sizeof(buf) - 1, 0);
  CHECK(n > 0);
  std::string httpResp(buf, static_cast<size_t>(n));
  CHECK(httpResp.find("200 OK") != std::string::npos);
  CHECK(httpResp.find("{\"status\":\"ok\"}") != std::string::npos);
  closesocket(c);

  // Connect via WebSocket handshake and receive initial snapshot frame
  SOCKET ws = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHECK(ws != INVALID_SOCKET);
  CHECK(connect(ws, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
  const std::string wsReq =
      "GET /ws HTTP/1.1\r\n"
      "Host: 127.0.0.1\r\n"
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
  CHECK(wsResp.find("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos);
  size_t hdrEnd = wsResp.find("\r\n\r\n") + 4;
  CHECK(wsResp.size() > hdrEnd + 2);
  CHECK(static_cast<uint8_t>(wsResp[hdrEnd]) == 0x81); // initial snapshot text frame
  closesocket(ws);

  server.stop();
  std::filesystem::remove_all(tempRoot, ec);
  std::cout << "[PASS] testLiveMonitorAndWsLoopback (poll=" << snap.pollLatencyUs << " us, conns=" << snap.totalConnections << ")\n";
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
  // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  CHECK(computeFileSha256Hex(tmpFile) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  std::error_code ec;
  std::filesystem::remove(tmpFile, ec);

  std::cout << "[PASS] testSemVerAndReleaseParsing\n";
  return 0;
}

int main() {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

  int rc = 0;
  rc |= testIpClassification();
  rc |= testGeoJsonAndCache();
  rc |= testWebSocketRfc6455();
  rc |= testLiveMonitorAndWsLoopback();
  rc |= testSemVerAndReleaseParsing();

  WSACleanup();
  if (rc == 0) {
    std::cout << "ALL C++ TESTS PASSED.\n";
  }
  return rc;
}
