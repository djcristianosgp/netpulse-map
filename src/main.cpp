#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#else
#include <csignal>
#include <limits.h>
#include <unistd.h>
#endif

#include "actions.hpp"
#include "api/api_router.hpp"
#include "geo_dns.hpp"
#include "history_store.hpp"
#include "net_monitor.hpp"
#include "security/audit_log.hpp"
#include "security/auth_manager.hpp"
#include "security/rate_limiter.hpp"
#include "security/tls_context.hpp"
#include "serializer.hpp"
#include "service_monitor.hpp"
#include "settings_store.hpp"
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
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> gRunning{true};

#ifdef _WIN32
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
#else
void posixSignalHandler(int) {
  gRunning.store(false);
}
#endif

std::string getEnvString(const char* name) {
#ifdef _WIN32
  char* buf = nullptr;
  size_t len = 0;
  if (_dupenv_s(&buf, &len, name) == 0 && buf) {
    std::string out(buf);
    free(buf);
    return out;
  }
  return {};
#else
  if (const char* v = std::getenv(name)) {
    return std::string(v);
  }
  return {};
#endif
}

bool isLoopbackBindHost(const std::string& host) {
  return host == "127.0.0.1" || host == "::1" || host == "localhost";
}

uint64_t nowMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::filesystem::path findProjectRoot() {
#ifdef _WIN32
  wchar_t exeBuf[MAX_PATH * 2] = {};
  GetModuleFileNameW(nullptr, exeBuf, static_cast<DWORD>(std::size(exeBuf)));
  std::filesystem::path exeDir = std::filesystem::path(exeBuf).parent_path();
#else
  char exeBuf[PATH_MAX] = {};
  ssize_t len = readlink("/proc/self/exe", exeBuf, sizeof(exeBuf) - 1);
  std::filesystem::path exeDir = (len > 0)
      ? std::filesystem::path(std::string(exeBuf, static_cast<size_t>(len))).parent_path()
      : std::filesystem::current_path();
#endif

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
#ifdef _WIN32
  if (std::filesystem::exists(rootDir / "src", ec)) {
    return localData;
  }
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
#else
  std::filesystem::create_directories(localData, ec);
#endif
  return localData;
}

void launchAppWindow(const std::string& url, bool useAppMode) {
#ifdef _WIN32
  if (useAppMode && netpulse::focusExistingMapWindow()) {
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
#else
  (void)url;
  (void)useAppMode;
#endif
}

std::vector<std::string> splitCommaList(const std::string& raw) {
  std::vector<std::string> out;
  std::istringstream ss(raw);
  std::string item;
  while (std::getline(ss, item, ',')) {
    if (!item.empty()) out.push_back(item);
  }
  return out;
}

} // namespace

int main(int argc, char** argv) {
  uint16_t port = 8740;
  std::string bindHost = "127.0.0.1";
  std::atomic<uint32_t> intervalMs{1000};
#ifdef _WIN32
  bool openBrowser = true;
#else
  bool openBrowser = false;
#endif
  bool useAppMode = true;
  bool waitSlot = false;
  bool allowRemote = (getEnvString("NETPULSE_ALLOW_REMOTE") == "1" ||
                      getEnvString("NETPULSE_ALLOW_REMOTE") == "true");
  bool forceTls = (getEnvString("NETPULSE_TLS") == "1");
  bool behindTlsProxy = (getEnvString("NETPULSE_BEHIND_TLS_PROXY") == "1");
  bool insecureHttp = (getEnvString("NETPULSE_INSECURE_HTTP") == "1");
  std::string tlsCertPath = getEnvString("NETPULSE_TLS_CERT");
  std::string tlsKeyPath = getEnvString("NETPULSE_TLS_KEY");
  std::string allowedHostsRaw = getEnvString("NETPULSE_ALLOWED_HOSTS");
  std::string envAdminToken = getEnvString("NETPULSE_ADMIN_TOKEN");

  if (const std::string envHost = getEnvString("NETPULSE_HOST"); !envHost.empty()) {
    bindHost = envHost;
  }
  if (const std::string envPort = getEnvString("NETPULSE_PORT"); !envPort.empty()) {
    port = static_cast<uint16_t>(std::clamp(std::atoi(envPort.c_str()), 1024, 65535));
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::clamp(std::atoi(argv[++i]), 1024, 65535));
    } else if (arg == "--host" && i + 1 < argc) {
      bindHost = argv[++i];
    } else if (arg == "--interval" && i + 1 < argc) {
      intervalMs.store(static_cast<uint32_t>(std::clamp(std::atoi(argv[++i]), 100, 5000)));
    } else if (arg == "--no-browser") {
      openBrowser = false;
    } else if (arg == "--browser-tab") {
      useAppMode = false;
    } else if (arg == "--wait-slot") {
      waitSlot = true;
    } else if (arg == "--allow-remote") {
      allowRemote = true;
    } else if (arg == "--tls") {
      forceTls = true;
    } else if (arg == "--tls-cert" && i + 1 < argc) {
      tlsCertPath = argv[++i];
      forceTls = true;
    } else if (arg == "--tls-key" && i + 1 < argc) {
      tlsKeyPath = argv[++i];
      forceTls = true;
    } else if (arg == "--behind-tls-proxy") {
      behindTlsProxy = true;
    } else if (arg == "--insecure-http") {
      insecureHttp = true;
    } else if (arg == "--allowed-hosts" && i + 1 < argc) {
      allowedHostsRaw = argv[++i];
    }
  }

  const bool isRemoteBind = !isLoopbackBindHost(bindHost);
  if (isRemoteBind && !allowRemote) {
    std::cerr << "[SECURITY] Recusando bind remoto em '" << bindHost
              << "' sem --allow-remote ou NETPULSE_ALLOW_REMOTE=1.\n";
    return 2;
  }

#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return 1;
  }
#endif

  const bool trayMode = (openBrowser || waitSlot) && (port == 8740) && !isRemoteBind;
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
#ifdef _WIN32
      WSACleanup();
#endif
      return 0;
    }
  }

#ifdef _WIN32
  SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
#else
  std::signal(SIGINT, posixSignalHandler);
  std::signal(SIGTERM, posixSignalHandler);
  std::signal(SIGPIPE, SIG_IGN);
#endif

  const std::filesystem::path rootDir = findProjectRoot();
  const std::filesystem::path staticDir = rootDir / "static";
  const std::filesystem::path assetsDir = rootDir / "assets";
  const std::filesystem::path dataDir = resolveDataDir(rootDir);

  netpulse::AuthManager auth(dataDir, envAdminToken);
  netpulse::AuditLog audit(dataDir / "security_audit.tsv");
  netpulse::RateLimiter apiLimiter(240, 10000);
  netpulse::RateLimiter authLimiter(10, 60000, 60000);

  const bool enableTls = forceTls || (isRemoteBind && !behindTlsProxy && !insecureHttp);
  netpulse::TlsContext tlsCtx;
  if (enableTls) {
    netpulse::TlsConfig tlsCfg;
    tlsCfg.enabled = true;
    tlsCfg.certPath = tlsCertPath;
    tlsCfg.keyPath = tlsKeyPath;
    tlsCfg.autoCertDir = dataDir / "tls";
    tlsCfg.commonName = isRemoteBind ? bindHost : "localhost";
    std::string tlsErr;
    if (!tlsCtx.init(tlsCfg, tlsErr)) {
      std::cerr << "[SECURITY] Falha ao inicializar TLS: " << tlsErr << "\n";
      netpulse::releaseSingleInstance(instanceMutex);
#ifdef _WIN32
      WSACleanup();
#endif
      return 3;
    }
  }

  netpulse::GeoDnsService geoDns(dataDir / "geoip_cache.tsv");
  geoDns.tryLoadMmdbFromDir(dataDir);
  geoDns.tryLoadMmdbFromDir(assetsDir);
  geoDns.start();

  netpulse::ServiceMonitor serviceMon(dataDir / "custom_services.tsv");
  serviceMon.start();

  netpulse::SettingsStore settingsStore(dataDir / "settings.tsv");
  const auto initCfg = settingsStore.get();
  netpulse::setMinimizeToTrayEnabled(initCfg.minimizeToTray);

  netpulse::HistoryStore history(dataDir);
  netpulse::TracerouteService tracer(geoDns, &history);
  tracer.startScheduler();
  netpulse::NetworkQualityEngine qualityEngine(history);
  qualityEngine.start();
  netpulse::InterfaceMonitor ifaceMonitor(&history);
  ifaceMonitor.collect(nowMs());
  auto syncHistoryNotifications = [&](const netpulse::AppSettings& cfg) {
    history.setAlertsEnabled(cfg.alertsEnabled);
    history.setNotificationCategories(netpulse::NotificationCategories{
        cfg.notifyServiceDown,
        cfg.notifyServiceDegraded,
        cfg.notifySensitivePort,
        cfg.notifyNewCountry,
    });
    history.setRetentionConfig(cfg.retentionDays, cfg.maxDbSizeMb);
  };
  syncHistoryNotifications(initCfg);
  history.setAlertCallback([](const std::string& title, const std::string& body, bool isWarning) {
    netpulse::showTrayBalloon(title, body, isWarning);
  });

  netpulse::UpdateManager updater(netpulse::kAppVersion, []() {
    gRunning.store(false);
    netpulse::requestTrayQuit();
  });
  updater.startAutoCheck();

  netpulse::NetMonitor monitor;
  netpulse::WsServer server(port, staticDir, assetsDir, bindHost);
  if (tlsCtx.isReady()) {
    server.setTlsContext(&tlsCtx);
  }
  server.setTrustProxyTls(behindTlsProxy);
  if (!allowedHostsRaw.empty()) {
    server.setAllowedHosts(splitCommaList(allowedHostsRaw));
  }

  std::mutex latestSnapCopyMutex;
  std::string latestSnapCopy;

  netpulse::ApiRouter apiRouter(netpulse::ApiDependencies{
      auth,
      audit,
      authLimiter,
      serviceMon,
      tracer,
      settingsStore,
      history,
      updater,
      dataDir,
      isRemoteBind,
      tlsCtx.isReady() || behindTlsProxy,
      [&]() {
        std::lock_guard lock(latestSnapCopyMutex);
        return latestSnapCopy;
      },
      [&](const netpulse::AppSettings& nextCfg) {
        syncHistoryNotifications(nextCfg);
        netpulse::setMinimizeToTrayEnabled(nextCfg.minimizeToTray);
      },
      []() {
        std::thread([]() {
          std::this_thread::sleep_for(std::chrono::milliseconds(250));
          gRunning.store(false);
          netpulse::requestTrayQuit();
        }).detach();
      },
      &qualityEngine,
      &ifaceMonitor,
  });

  const uint64_t startMs = nowMs();
  std::atomic<uint64_t> lastPollUs{0};

  server.setHealthCallback([&]() {
    uint64_t uptime = nowMs() - startMs;
#ifdef _WIN32
    const char* engineName = "C++20 Native Win32";
#else
    const char* engineName = "C++20 Native Linux";
#endif
    return std::string("{\"status\":\"ok\",\"version\":\"") + netpulse::kAppVersion +
           "\",\"engine\":\"" + engineName + "\",\"authRequired\":true,\"tls\":" +
           (tlsCtx.isReady() ? "true" : "false") +
           ",\"remoteAccess\":" + (isRemoteBind ? "true" : "false") +
           ",\"uptimeMs\":" + std::to_string(uptime) +
           ",\"pollUs\":" + std::to_string(lastPollUs.load()) +
           ",\"wsClients\":" + std::to_string(server.clientCount()) + "}";
  });

  server.setRateLimitCallback([&](const std::string& remoteIp) -> std::pair<bool, uint32_t> {
    auto dec = apiLimiter.check(remoteIp);
    return {dec.allowed, dec.retryAfterSec};
  });

  server.setWsAuthCallback([&](const netpulse::HttpRequest& req) {
    return apiRouter.handleWsAuth(req);
  });

  server.setApiCallback([&](const netpulse::HttpRequest& req) {
    return apiRouter.handleHttp(req);
  });

  server.setCommandCallback([&](const std::string& cmd,
                                const netpulse::AuthContext& authCtx,
                                const std::string& remoteIp) {
    if (!netpulse::hasRole(authCtx.role, netpulse::Role::Operator)) {
      audit.record(authCtx.actor, netpulse::roleToString(authCtx.role), remoteIp,
                   "ws.command", cmd, "denied", "Comando WebSocket requer nivel Operator");
      return;
    }
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
    std::string initialJson =
        netpulse::serializeSnapshotJson(snap, geoDns, intervalMs.load(), 0, &serviceMon);
    {
      std::lock_guard lock(latestSnapCopyMutex);
      latestSnapCopy = initialJson;
    }
    server.setLatestSnapshotJson(std::move(initialJson));
  }

  if (!server.start()) {
    std::cerr << "[ERROR] Falha ao iniciar servidor em " << bindHost << ":" << port << "\n";
    tracer.stop();
    serviceMon.stop();
    updater.stop();
    geoDns.stop();
    netpulse::releaseSingleInstance(instanceMutex);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  const std::string scheme = tlsCtx.isReady() ? "https" : "http";
  const std::string baseUrl = scheme + "://127.0.0.1:" + std::to_string(server.port());

  auto makeLaunchUrl = [&]() {
    if (!isRemoteBind) {
      return baseUrl + "/?boot=" + auth.issueLocalLaunchNonce();
    }
    return baseUrl + "/";
  };

  if (openBrowser) {
    launchAppWindow(makeLaunchUrl(), useAppMode);
  }

  std::jthread pollThread([&](std::stop_token st) {
    uint64_t lastIdleSerializeMs = nowMs();
    uint64_t lastIfaceCollectMs = lastIdleSerializeMs;
    while (gRunning.load() && !st.stop_requested()) {
      const uint64_t tickStart = nowMs();
      auto snap = monitor.poll(tickStart);
      snap.hostGeo = geoDns.getHostGeo();
      lastPollUs.store(snap.pollLatencyUs);

      if (tickStart - lastIfaceCollectMs >= 2000) {
        ifaceMonitor.collect(tickStart);
        lastIfaceCollectMs = tickStart;
      }

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
        {
          std::lock_guard lock(latestSnapCopyMutex);
          latestSnapCopy = json;
        }
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
    cb.onOpenApp = [makeLaunchUrl, useAppMode]() { launchAppWindow(makeLaunchUrl(), useAppMode); };
    cb.onOpenBrowser = [makeLaunchUrl]() { launchAppWindow(makeLaunchUrl(), false); };
    cb.onCheckUpdates = [&updater]() { updater.checkNowAsync(); };
    cb.onQuit = []() { gRunning.store(false); };
    netpulse::runTrayMessageLoop(baseUrl, gRunning, std::move(cb));
  } else {
    while (gRunning.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
  }

  gRunning.store(false);
  pollThread.request_stop();
  pollThread.join();
  tracer.stop();
  qualityEngine.stop();
  serviceMon.stop();
  updater.stop();
  server.stop();
  history.stop();
  geoDns.stop();
  netpulse::releaseSingleInstance(instanceMutex);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
