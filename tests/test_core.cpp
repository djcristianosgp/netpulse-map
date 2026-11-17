#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "../src/actions.hpp"
#include "../src/geo_dns.hpp"
#include "../src/history_store.hpp"
#include "../src/mmdb_reader.hpp"
#include "../src/net_monitor.hpp"
#include "../src/serializer.hpp"
#include "../src/service_monitor.hpp"
#include "../src/settings_store.hpp"
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
    CHECK(snap.size() >= 17); // 6 continents + 11 global services
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
  // Build a minimal valid MaxMind DB (.mmdb) v2.0 file (IPv4, 24-bit record, 1 node: 0.0.0.0/1 -> record 16)
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

  // Search tree: 1 node (6 bytes for 24-bit left/right records).
  // Bit 0 = 0 (IPs 0.0.0.0..127.255.255.255) -> value node_count + 16 = 17 -> offset 0 in data section!
  // Bit 1 = 1 -> node_count = 1 (not found)
  std::vector<uint8_t> mmdb;
  // Left record = 17 (0x000011), Right record = 1 (0x000001)
  mmdb.insert(mmdb.end(), {0x00, 0x00, 0x11, 0x00, 0x00, 0x01});
  // 16-byte separator
  mmdb.insert(mmdb.end(), 16, 0x00);

  // Data section at offset 0: Map{ "country": Map{"iso_code":"US"}, "location": Map{"latitude":39.03,"longitude":-77.5} }
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

  // Metadata marker + Map{ "node_count":1, "record_size":24, "ip_version":4, "database_type":"GeoLite2-City" }
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

  // Security & History checks
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
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

  int rc = 0;
  rc |= testIpClassification();
  rc |= testGeoJsonAndCache();
  rc |= testWebSocketRfc6455();
  rc |= testLiveMonitorAndWsLoopback();
  rc |= testSemVerAndReleaseParsing();
  rc |= testServiceMonitorParsing();
  rc |= testMmdbAndHistorySecurity();
  rc |= testSettingsStorePersistence();

  WSACleanup();
  if (rc == 0) {
    std::cout << "ALL C++ TESTS PASSED.\n";
  }
  return rc;
}
