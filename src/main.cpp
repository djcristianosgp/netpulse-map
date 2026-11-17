#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>

#include "actions.hpp"
#include "geo_dns.hpp"
#include "history_store.hpp"
#include "net_monitor.hpp"
#include "serializer.hpp"
#include "service_monitor.hpp"
#include "traceroute.hpp"
#include "tray_host.hpp"
#include "updater.hpp"
#include "version.hpp"
#include "ws_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> gRunning{true};

BOOL WINAPI consoleCtrlHandler(DWORD ctrlType) {
  switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      gRunning.store(false);
      return TRUE;
    default:
      return FALSE;
  }
}

uint64_t nowMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::filesystem::path findProjectRoot() {
  wchar_t exeBuf[MAX_PATH * 2] = {};
  GetModuleFileNameW(nullptr, exeBuf, static_cast<DWORD>(std::size(exeBuf)));
  std::filesystem::path exeDir = std::filesystem::path(exeBuf).parent_path();

  std::error_code ec;
  if (std::filesystem::exists(exeDir / "static" / "index.html", ec)) {
    return exeDir;
  }
  if (std::filesystem::exists(exeDir.parent_path() / "static" / "index.html", ec)) {
    return exeDir.parent_path();
  }
  return std::filesystem::current_path();
}

std::filesystem::path resolveDataDir(const std::filesystem::path& rootDir) {
  std::error_code ec;
  const auto localData = rootDir / "data";
  if (std::filesystem::exists(rootDir / "src", ec)) {
    return localData;
  }
  // When installed under Program Files or read-only directory, store runtime cache in %LOCALAPPDATA%.
  std::filesystem::create_directories(localData, ec);
  if (!ec) {
    const auto probe = localData / ".write_probe";
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
      return localData;
    }
  }

  wchar_t appDataBuf[MAX_PATH * 2] = {};
  DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", appDataBuf, static_cast<DWORD>(std::size(appDataBuf)));
  if (len > 0 && len < std::size(appDataBuf)) {
    return std::filesystem::path(appDataBuf) / "NetPulse2D" / "data";
  }
  return localData;
}

bool focusExistingMapWindow() {
  HWND found = nullptr;
  EnumWindows(
      [](HWND hwnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, static_cast<int>(std::size(title))) <= 0) return TRUE;
        if (wcsncmp(title, L"NetPulse 2D", 11) != 0) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return TRUE;
        wchar_t exe[MAX_PATH] = {};
        DWORD sz = static_cast<DWORD>(std::size(exe));
        bool isBrowser = false;
        if (QueryFullProcessImageNameW(hProc, 0, exe, &sz)) {
          std::wstring p(exe, sz);
          for (auto& ch : p) ch = static_cast<wchar_t>(towlower(ch));
          isBrowser = (p.find(L"msedge.exe") != std::wstring::npos ||
                       p.find(L"chrome.exe") != std::wstring::npos);
        }
        CloseHandle(hProc);
        if (isBrowser) {
          *reinterpret_cast<HWND*>(lParam) = hwnd;
          return FALSE;
        }
        return TRUE;
      },
      reinterpret_cast<LPARAM>(&found));

  if (found) {
    if (IsIconic(found)) ShowWindow(found, SW_RESTORE);
    SetForegroundWindow(found);
    return true;
  }
  return false;
}

void launchAppWindow(const std::string& url, bool useAppMode) {
  if (useAppMode && focusExistingMapWindow()) {
    return;
  }
  if (useAppMode) {
    const wchar_t* candidates[] = {
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    };
    std::wstring wUrl(url.begin(), url.end());
    std::wstring args = L"--app=" + wUrl + L" --window-size=1480,900";
    std::error_code ec;
    for (const wchar_t* browser : candidates) {
      if (std::filesystem::exists(browser, ec)) {
        HINSTANCE r = ShellExecuteW(nullptr, L"open", browser, args.c_str(), nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(r) > 32) {
          return;
        }
      }
    }
  }

  std::wstring wUrl(url.begin(), url.end());
  ShellExecuteW(nullptr, L"open", wUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

std::string extractSimpleJsonField(const std::string& body, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = body.find(needle);
  if (pos == std::string::npos) return {};
  pos = body.find(':', pos + needle.size());
  if (pos == std::string::npos) return {};
  ++pos;
  while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
  if (pos >= body.size()) return {};
  if (body[pos] == '"') {
    ++pos;
    std::string out;
    while (pos < body.size() && body[pos] != '"') {
      if (body[pos] == '\\' && pos + 1 < body.size()) ++pos;
      out.push_back(body[pos++]);
    }
    return out;
  }
  size_t end = pos;
  while (end < body.size() && body[end] != ',' && body[end] != '}' && body[end] != ' ') ++end;
  return body.substr(pos, end - pos);
}

} // namespace

int main(int argc, char** argv) {
  uint16_t port = 8740;
  std::atomic<uint32_t> intervalMs{1000};
  bool openBrowser = true;
  bool useAppMode = true;
  bool waitSlot = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::clamp(std::atoi(argv[++i]), 1024, 65535));
    } else if (arg == "--interval" && i + 1 < argc) {
      intervalMs.store(static_cast<uint32_t>(std::clamp(std::atoi(argv[++i]), 100, 5000)));
    } else if (arg == "--no-browser") {
      openBrowser = false;
    } else if (arg == "--browser-tab") {
      useAppMode = false;
    } else if (arg == "--wait-slot") {
      waitSlot = true;
    }
  }

  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return 1;
  }

  const bool trayMode = (openBrowser || waitSlot) && (port == 8740);
  void* instanceMutex = nullptr;
  if (trayMode) {
    int attempts = waitSlot ? 25 : 1;
    bool acquired = false;
    for (int i = 0; i < attempts; ++i) {
      if (netpulse::acquireSingleInstanceOrFocusExisting(&instanceMutex)) {
        acquired = true;
        break;
      }
      if (i + 1 < attempts) std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    if (!acquired) {
      WSACleanup();
      return 0;
    }
  }

  SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);

  const std::filesystem::path rootDir = findProjectRoot();
  const std::filesystem::path staticDir = rootDir / "static";
  const std::filesystem::path assetsDir = rootDir / "assets";
  const std::filesystem::path dataDir = resolveDataDir(rootDir);

  netpulse::GeoDnsService geoDns(dataDir / "geoip_cache.tsv");
  geoDns.tryLoadMmdbFromDir(dataDir);
  geoDns.tryLoadMmdbFromDir(assetsDir);
  geoDns.start();

  netpulse::ServiceMonitor serviceMon(dataDir / "custom_services.tsv");
  serviceMon.start();

  netpulse::TracerouteService tracer(geoDns);
  netpulse::HistoryStore history(dataDir);
  history.setAlertCallback([](const std::string& title, const std::string& body, bool isWarning) {
    netpulse::showTrayBalloon(title, body, isWarning);
  });

  netpulse::UpdateManager updater(netpulse::kAppVersion, []() {
    gRunning.store(false);
    netpulse::requestTrayQuit();
  });
  updater.startAutoCheck();

  netpulse::NetMonitor monitor;
  netpulse::WsServer server(port, staticDir, assetsDir);

  const uint64_t startMs = nowMs();
  std::atomic<uint64_t> lastPollUs{0};

  server.setHealthCallback([&]() {
    uint64_t uptime = nowMs() - startMs;
    return std::string("{\"status\":\"ok\",\"version\":\"") + netpulse::kAppVersion +
           "\",\"engine\":\"C++20 Native Win32\",\"elevated\":" +
           (netpulse::isProcessElevated() ? "true" : "false") +
           ",\"mmdb\":" + (geoDns.hasOfflineMmdb() ? "true" : "false") +
           ",\"uptimeMs\":" + std::to_string(uptime) +
           ",\"pollUs\":" + std::to_string(lastPollUs.load()) +
           ",\"geoCached\":" + std::to_string(geoDns.cachedGeoCount()) +
           ",\"dnsCached\":" + std::to_string(geoDns.cachedDnsCount()) +
           ",\"wsClients\":" + std::to_string(server.clientCount()) + "}";
  });

  server.setApiCallback([&](const std::string& method,
                            const std::string& path,
                            const std::string& body) -> std::pair<int, std::string> {
    if (path == "/api/update/status" && method == "GET") {
      return {200, updater.getStatusJson()};
    }
    if (path == "/api/update/check" && method == "POST") {
      updater.checkNowAsync();
      return {202, updater.getStatusJson()};
    }
    if (path == "/api/update/apply" && method == "POST") {
      bool started = updater.startInstallAsync();
      return {started ? 202 : 409, updater.getStatusJson()};
    }
    if (path == "/api/services" && method == "GET") {
      return {200, serviceMon.getServicesJson()};
    }
    if (path == "/api/services/probe" && method == "POST") {
      serviceMon.probeNowAsync();
      return {202, serviceMon.getServicesJson()};
    }
    if (path == "/api/services/add" && method == "POST") {
      std::string name = extractSimpleJsonField(body, "name");
      std::string host = extractSimpleJsonField(body, "host");
      int portNum = std::atoi(extractSimpleJsonField(body, "port").c_str());
      if (portNum <= 0 || portNum > 65535) portNum = 443;
      std::string cont = extractSimpleJsonField(body, "continent");
      double lat = std::strtod(extractSimpleJsonField(body, "lat").c_str(), nullptr);
      double lon = std::strtod(extractSimpleJsonField(body, "lon").c_str(), nullptr);
      if (!serviceMon.addCustomService(name, host, static_cast<uint16_t>(portNum), cont, lat, lon)) {
        return {400, "{\"error\":\"invalid_service\"}"};
      }
      return {201, serviceMon.getServicesJson()};
    }
    if (path == "/api/services/remove" && method == "POST") {
      std::string id = extractSimpleJsonField(body, "id");
      if (!serviceMon.removeCustomService(id)) {
        return {404, "{\"error\":\"not_found\"}"};
      }
      return {200, serviceMon.getServicesJson()};
    }
    if (path == "/api/trace/start" && method == "POST") {
      std::string ip = extractSimpleJsonField(body, "ip");
      if (!tracer.startTrace(ip)) {
        return {400, "{\"error\":\"invalid_ip\"}"};
      }
      return {202, tracer.getStatusJson()};
    }
    if (path == "/api/trace/status" && method == "GET") {
      return {200, tracer.getStatusJson()};
    }
    if (path == "/api/history/events" && method == "GET") {
      return {200, history.getEventsJson(150)};
    }
    if (path == "/api/history/service" && method == "POST") {
      std::string id = extractSimpleJsonField(body, "id");
      return {200, history.getServiceHistoryJson(id, 60)};
    }
    if (path == "/api/alerts/toggle" && method == "POST") {
      std::string en = extractSimpleJsonField(body, "enabled");
      bool next = (en == "true" || en == "1");
      history.setAlertsEnabled(next);
      return {200, std::string("{\"alertsEnabled\":") + (next ? "true" : "false") + "}"};
    }
    if (path == "/api/action/kill-process" && method == "POST") {
      uint32_t pid = static_cast<uint32_t>(std::strtoul(extractSimpleJsonField(body, "pid").c_str(), nullptr, 10));
      std::string proc = extractSimpleJsonField(body, "proc");
      std::string err;
      if (!netpulse::terminateTargetProcess(pid, proc, err)) {
        std::string resp = "{\"ok\":false,\"error\":";
        netpulse::appendJsonEscaped(resp, err);
        resp.push_back('}');
        return {400, resp};
      }
      history.recordManualAction("warn", "Processo encerrado", proc + " (PID " + std::to_string(pid) + ")");
      return {200, "{\"ok\":true}"};
    }
    if (path == "/api/action/block-ip" && method == "POST") {
      std::string ip = extractSimpleJsonField(body, "ip");
      std::string err;
      if (!netpulse::blockIpInWindowsFirewall(ip, netpulse::isProcessElevated(), err)) {
        std::string resp = "{\"ok\":false,\"error\":";
        netpulse::appendJsonEscaped(resp, err);
        resp.push_back('}');
        return {400, resp};
      }
      history.recordManualAction("warn", "IP bloqueado no Firewall", ip);
      return {200, "{\"ok\":true}"};
    }
    if (path == "/api/elevate" && method == "POST") {
      if (netpulse::isProcessElevated()) {
        return {200, "{\"ok\":true,\"alreadyElevated\":true}"};
      }
      if (!netpulse::relaunchAsAdministrator()) {
        return {400, "{\"ok\":false,\"error\":\"Elevacao UAC cancelada\"}"};
      }
      std::thread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        gRunning.store(false);
        netpulse::requestTrayQuit();
      }).detach();
      return {202, "{\"ok\":true,\"restarting\":true}"};
    }
    return {404, "{\"error\":\"not_found\"}"};
  });

  server.setCommandCallback([&](const std::string& cmd) {
    if (cmd.find("refreshGeo") != std::string::npos) {
      geoDns.requestHostGeoRefresh();
    } else if (auto pos = cmd.find("interval:"); pos != std::string::npos) {
      int val = std::atoi(cmd.c_str() + pos + 9);
      intervalMs.store(static_cast<uint32_t>(std::clamp(val, 100, 5000)));
    }
  });

  // Prime initial snapshot before accepting connections.
  {
    auto snap = monitor.poll(nowMs());
    snap.hostGeo = geoDns.getHostGeo();
    lastPollUs.store(snap.pollLatencyUs);
    std::vector<std::string> pubs;
    for (const auto& c : snap.connections) {
      if (c.scope == netpulse::IpScope::Public) pubs.push_back(c.remoteIp);
    }
    geoDns.enqueueLookups(pubs);
    server.setLatestSnapshotJson(
        netpulse::serializeSnapshotJson(snap, geoDns, intervalMs.load(), 0, &serviceMon));
  }

  if (!server.start()) {
    tracer.stop();
    serviceMon.stop();
    updater.stop();
    geoDns.stop();
    netpulse::releaseSingleInstance(instanceMutex);
    WSACleanup();
    return 1;
  }

  const std::string url = "http://127.0.0.1:" + std::to_string(server.port());

  if (openBrowser) {
    launchAppWindow(url, useAppMode);
  }

  std::jthread pollThread([&](std::stop_token st) {
    uint64_t lastIdleSerializeMs = nowMs();
    while (gRunning.load() && !st.stop_requested()) {
      const uint64_t tickStart = nowMs();
      auto snap = monitor.poll(tickStart);
      snap.hostGeo = geoDns.getHostGeo();
      lastPollUs.store(snap.pollLatencyUs);

      std::vector<std::string> pubs;
      pubs.reserve(snap.publicConnections);
      for (const auto& c : snap.connections) {
        if (c.scope == netpulse::IpScope::Public) {
          pubs.push_back(c.remoteIp);
        }
      }
      if (!pubs.empty()) {
        geoDns.enqueueLookups(pubs);
      }

      history.processTelemetry(snap, geoDns);
      history.processServices(serviceMon.getSnapshot());

      const size_t clients = server.clientCount();
      if (clients > 0 || (tickStart - lastIdleSerializeMs) >= 1500) {
        std::string json =
            netpulse::serializeSnapshotJson(snap, geoDns, intervalMs.load(), clients, &serviceMon);
        server.setLatestSnapshotJson(json);
        if (clients > 0) {
          server.broadcastText(json);
        }
        lastIdleSerializeMs = tickStart;
      }

      const uint32_t targetMs = intervalMs.load();
      const uint64_t elapsed = nowMs() - tickStart;
      if (elapsed < targetMs) {
        std::this_thread::sleep_for(std::chrono::milliseconds(targetMs - elapsed));
      }
    }
  });

  if (trayMode) {
    netpulse::TrayCallbacks cb;
    cb.onOpenApp = [url, useAppMode]() { launchAppWindow(url, useAppMode); };
    cb.onOpenBrowser = [url]() { launchAppWindow(url, false); };
    cb.onCheckUpdates = [&updater]() { updater.checkNowAsync(); };
    cb.onQuit = []() { gRunning.store(false); };
    netpulse::runTrayMessageLoop(url, gRunning, std::move(cb));
  } else {
    while (gRunning.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
  }

  gRunning.store(false);
  pollThread.request_stop();
  pollThread.join();
  tracer.stop();
  serviceMon.stop();
  updater.stop();
  server.stop();
  geoDns.stop();
  netpulse::releaseSingleInstance(instanceMutex);
  WSACleanup();
  return 0;
}
