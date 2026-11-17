#pragma once

#include "geo_dns.hpp"
#include "models.hpp"
#include "service_monitor.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace netpulse {

struct HistoryEvent {
  uint64_t tsMs = 0;
  std::string severity; // "info" | "warn" | "critical"
  std::string kind;     // "new_country" | "sensitive_port" | "service_down" | "service_up" | "action"
  std::string title;
  std::string detail;
};

struct ServiceMetricPoint {
  uint64_t tsMs = 0;
  std::string serviceId;
  std::string status;
  double latencyMs = 0.0;
};

bool isSensitivePort(uint16_t port);

class HistoryStore {
public:
  using AlertCallback = std::function<void(const std::string& title, const std::string& body, bool isWarning)>;

  explicit HistoryStore(std::filesystem::path dataDir);

  void setAlertCallback(AlertCallback cb);
  void setAlertsEnabled(bool enabled) { alertsEnabled_.store(enabled); }
  bool alertsEnabled() const { return alertsEnabled_.load(); }

  void processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns);
  void processServices(const std::vector<ServiceStatus>& services);
  void recordManualAction(const std::string& severity, const std::string& title, const std::string& detail);

  std::string getEventsJson(size_t maxItems = 150) const;
  std::string getServiceHistoryJson(const std::string& serviceId, size_t maxPoints = 60) const;

private:
  void loadFromDisk();
  void appendEvent(HistoryEvent ev, bool notifyTray);
  void appendServicePoint(const ServiceMetricPoint& pt);

  std::filesystem::path eventsPath_;
  std::filesystem::path metricsPath_;

  mutable std::mutex mutex_;
  std::deque<HistoryEvent> events_;
  std::unordered_map<std::string, std::deque<ServiceMetricPoint>> serviceSeries_;
  std::unordered_map<std::string, std::string> prevServiceStatus_;
  std::unordered_map<std::string, uint64_t> prevServiceSampleMs_;

  std::unordered_set<std::string> seenCountries_;
  std::unordered_map<std::string, uint64_t> alertCooldownMs_;
  uint64_t startupWarmupEndMs_ = 0;

  std::atomic<bool> alertsEnabled_{true};
  AlertCallback alertCb_;
};

} // namespace netpulse
