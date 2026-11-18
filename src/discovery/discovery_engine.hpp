#pragma once

#include "../history_store.hpp"
#include "../network/interface_monitor.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace netpulse {

// Pure helpers exposed for deterministic unit testing
bool isLocallyAdministeredMac(const std::string& mac);
std::string normalizeMacUpper(const std::string& rawMac);
std::string lookupOuiVendor(const std::string& mac);
std::string inferDeviceType(bool isLocalHost,
                            bool isGateway,
                            const std::string& vendor,
                            const std::string& hostname,
                            const std::vector<uint16_t>& openPorts);
std::vector<std::string> enumerateSubnetHosts(const std::string& ipOrCidr, size_t maxHosts = 254);

class DiscoveryEngine {
public:
  DiscoveryEngine(HistoryStore& history, InterfaceMonitor& interfaces);
  ~DiscoveryEngine();

  DiscoveryEngine(const DiscoveryEngine&) = delete;
  DiscoveryEngine& operator=(const DiscoveryEngine&) = delete;

  void start();
  void stop();
  bool triggerScanAsync(const std::string& subnetOverride = {});
  bool runPassiveRefresh();

  bool setDeviceLabel(const std::string& deviceKey, const std::string& label);
  bool removeDevice(const std::string& deviceKey);
  std::vector<LanDeviceRecord> getDevicesSnapshot() const {
    std::lock_guard lock(mutex_);
    return devices_;
  }
  std::string getDevicesJson() const;

private:
  void workerLoop(std::stop_token st);
  void runActiveScan(std::stop_token st, const std::string& subnetOverride);
  std::vector<LanDeviceRecord> harvestLocalAndArp(uint64_t nowMs);

  HistoryStore& history_;
  InterfaceMonitor& interfaces_;

  mutable std::mutex mutex_;
  std::vector<LanDeviceRecord> devices_;
  std::unordered_set<std::string> knownKeys_;
  std::vector<std::string> activeSubnets_;
  uint64_t lastScanMs_ = 0;
  std::atomic<bool> scanRunning_{false};
  std::atomic<bool> running_{false};

  std::mutex wakeMutex_;
  std::condition_variable_any wakeCv_;
  bool scanRequested_ = false;
  std::string pendingSubnetOverride_;
  std::jthread workerThread_;
};

} // namespace netpulse
