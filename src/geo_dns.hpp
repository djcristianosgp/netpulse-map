#pragma once

#include "models.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace netpulse {

// Parses a JSON array response from ip-api.com/batch (or single object).
std::vector<std::pair<std::string, GeoInfo>> parseIpApiBatchJson(const std::string& jsonBody);
HostGeo parseIpApiSelfJson(const std::string& jsonBody);

class GeoDnsService {
public:
  explicit GeoDnsService(std::filesystem::path cacheFilePath);
  ~GeoDnsService();

  GeoDnsService(const GeoDnsService&) = delete;
  GeoDnsService& operator=(const GeoDnsService&) = delete;

  void start();
  void stop();
  void requestHostGeoRefresh();

  // Enqueues public IPs not yet resolved/queued for GeoIP + rDNS lookup.
  void enqueueLookups(const std::vector<std::string>& publicIps);

  // Thread-safe snapshots for telemetry serialization.
  std::optional<GeoInfo> getGeo(const std::string& ip) const;
  std::optional<std::string> getHostname(const std::string& ip) const;
  HostGeo getHostGeo() const;

  size_t cachedGeoCount() const;
  size_t cachedDnsCount() const;

  // Exposed for unit testing TSV persistence.
  void loadCache();

private:
  void appendCacheRow(const std::string& ip, const GeoInfo& info);
  void geoWorkerLoop(std::stop_token stopToken);
  void dnsWorkerLoop(std::stop_token stopToken);
  void fetchHostGeo();
  void fetchGeoBatch(const std::vector<std::string>& ips);

  std::filesystem::path cachePath_;

  mutable std::shared_mutex geoMutex_;
  std::unordered_map<std::string, GeoInfo> geoCache_;

  mutable std::shared_mutex dnsMutex_;
  std::unordered_map<std::string, std::string> dnsCache_;

  mutable std::mutex hostMutex_;
  HostGeo hostGeo_;

  std::mutex geoQueueMutex_;
  std::condition_variable_any geoCv_;
  std::deque<std::string> geoQueue_;
  std::unordered_set<std::string> geoQueuedSet_;
  std::atomic<bool> refreshHostGeo_{true};

  std::mutex dnsQueueMutex_;
  std::condition_variable_any dnsCv_;
  std::deque<std::string> dnsQueue_;
  std::unordered_set<std::string> dnsQueuedSet_;

  std::mutex fileMutex_;
  std::atomic<bool> running_{false};
  uint64_t rateLimitResumeMs_ = 0;

  std::jthread geoThread_;
  std::vector<std::jthread> dnsThreads_;
};

} // namespace netpulse
