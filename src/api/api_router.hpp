#pragma once

#include "../core/json_lite.hpp"
#include "../discovery/discovery_engine.hpp"
#include "../history_store.hpp"
#include "../network/interface_monitor.hpp"
#include "../quality/network_quality_engine.hpp"
#include "../security/audit_log.hpp"
#include "../security/auth_manager.hpp"
#include "../security/rate_limiter.hpp"
#include "../service_monitor.hpp"
#include "../settings_store.hpp"
#include "../traceroute.hpp"
#include "../updater.hpp"
#include "../ws_server.hpp"

#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace netpulse {

struct BlockedIpEntry {
  std::string ip;
  uint64_t blockedAtMs = 0;
  std::string actor;
  uint64_t auditId = 0;
};

struct ApiDependencies {
  AuthManager& auth;
  AuditLog& audit;
  RateLimiter& authRateLimiter;
  ServiceMonitor& services;
  TracerouteService& tracer;
  SettingsStore& settings;
  HistoryStore& history;
  UpdateManager& updater;
  std::filesystem::path dataDir;
  bool remoteAccess = false;
  bool tlsEnabled = false;
  std::function<std::string()> getLatestSnapshotJson;
  std::function<void(const AppSettings&)> onSettingsApplied;
  std::function<void()> onRequestRestart;
  NetworkQualityEngine* quality = nullptr;
  InterfaceMonitor* interfaces = nullptr;
  DiscoveryEngine* discovery = nullptr;
};

class ApiRouter {
public:
  explicit ApiRouter(ApiDependencies deps);

  HttpResponse handleHttp(const HttpRequest& req);
  WsAuthDecision handleWsAuth(const HttpRequest& req);
  std::string listBlockedIpsJson() const;

private:
  HttpResponse jsonError(int status, const std::string& code, const std::string& message = {});
  HttpResponse requireAuth(const HttpRequest& req, Role requiredRole, AuthContext& outAuth, const std::string& auditAction = {});
  std::string normalizeApiPath(const std::string& rawPath) const;

  void loadBlockedIps();
  void saveBlockedIps();

  ApiDependencies deps_;
  std::filesystem::path blocksPath_;
  mutable std::mutex blocksMutex_;
  std::vector<BlockedIpEntry> blockedIps_;
};

} // namespace netpulse
