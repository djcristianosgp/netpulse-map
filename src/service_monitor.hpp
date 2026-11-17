#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netpulse {

struct ServiceTarget {
  std::string id;
  std::string name;
  std::string host;
  uint16_t port = 443;
  std::string category;   // "continent" | "service" | "custom"
  std::string continent;  // "SA" | "NA" | "EU" | "AF" | "AS" | "OC" | "GLOBAL"
  std::string regionLabel;
  double lat = 0.0;
  double lon = 0.0;
  bool custom = false;
};

struct ServiceStatus {
  ServiceTarget target;
  std::string status = "pending"; // "pending" | "up" | "degraded" | "down"
  double latencyMs = 0.0;
  double avgLatencyMs = 0.0;
  double minLatencyMs = 0.0;
  uint64_t checksTotal = 0;
  uint64_t checksOk = 0;
  uint64_t lastCheckedMs = 0;
  std::string resolvedIp;
  std::string lastError;
};

// Pure helper for TSV persistence tests
bool parseCustomServiceLine(const std::string& line, ServiceTarget& out);

class ServiceMonitor {
public:
  explicit ServiceMonitor(std::filesystem::path customFilePath);
  ~ServiceMonitor();

  ServiceMonitor(const ServiceMonitor&) = delete;
  ServiceMonitor& operator=(const ServiceMonitor&) = delete;

  void start();
  void stop();
  void probeNowAsync();

  bool addCustomService(const std::string& name,
                        const std::string& host,
                        uint16_t port,
                        const std::string& continent,
                        double lat,
                        double lon);
  bool removeCustomService(const std::string& id);

  std::vector<ServiceStatus> getSnapshot() const;
  std::string getServicesJson() const;

private:
  void loadDefaultTargets();
  void loadCustomTargets();
  void saveCustomTargets();
  void workerLoop(std::stop_token st);
  void probeAll();

  std::filesystem::path customFilePath_;
  mutable std::mutex mutex_;
  std::vector<ServiceStatus> items_;

  std::mutex wakeMutex_;
  std::condition_variable_any wakeCv_;
  std::atomic<bool> probeRequested_{true};
  std::atomic<bool> running_{false};
  std::jthread workerThread_;
};

} // namespace netpulse
