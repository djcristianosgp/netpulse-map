#pragma once

#include "../history_store.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace netpulse {

struct NetworkInterfaceInfo {
  uint32_t ifIndex = 0;
  std::string id;
  std::string name;
  std::string description;
  std::string type = "other"; // "ethernet" | "wifi" | "vpn" | "virtual" | "loopback" | "tunnel" | "other"
  std::string macAddress;
  std::string operStatus = "unknown"; // "up" | "down" | "dormant" | "testing" | "unknown"
  bool mediaConnected = false;
  bool hardwareInterface = false;
  bool isDefaultRoute = false;
  bool isWanCandidate = false;
  uint64_t linkSpeedBps = 0;
  uint32_t mtu = 0;
  std::vector<std::string> ipv4;
  std::vector<std::string> ipv6;
  std::vector<std::string> gateways;
  std::vector<std::string> dnsServers;
  uint64_t rxBytes = 0;
  uint64_t txBytes = 0;
  uint64_t rxPackets = 0;
  uint64_t txPackets = 0;
  uint64_t rxErrors = 0;
  uint64_t txErrors = 0;
  uint64_t rxDiscards = 0;
  uint64_t txDiscards = 0;
  double rxBps = 0.0;
  double txBps = 0.0;
  double rxPps = 0.0;
  double txPps = 0.0;
};

struct InterfaceInventorySnapshot {
  uint64_t collectedAtMs = 0;
  std::string primaryIfId;
  std::string primaryIfName;
  std::string primaryGateway;
  uint32_t wanCount = 0;
  uint32_t activeWanCount = 0;
  double totalRxBps = 0.0;
  double totalTxBps = 0.0;
  std::vector<NetworkInterfaceInfo> interfaces;
};

struct MultiWanEvent {
  std::string severity; // "info" | "warn" | "critical"
  std::string kind;     // "wan_primary_changed" | "interface_down" | "interface_up"
  std::string title;
  std::string detail;
};

struct InterfaceRatePrev {
  uint64_t tsMs = 0;
  uint64_t rxBytes = 0;
  uint64_t txBytes = 0;
  uint64_t rxPackets = 0;
  uint64_t txPackets = 0;
};

// Pure helpers exposed for deterministic unit testing
std::string classifyInterfaceType(uint32_t ifType, const std::string& name, const std::string& desc, bool isHardware);
std::string formatMacAddress(const uint8_t* bytes, size_t len);
void computeInterfaceRates(InterfaceRatePrev& prev, NetworkInterfaceInfo& cur, uint64_t nowMs);
std::vector<MultiWanEvent> detectMultiWanTransitions(const InterfaceInventorySnapshot& prev,
                                                     const InterfaceInventorySnapshot& cur);
std::string serializeInterfacesJson(const InterfaceInventorySnapshot& snap);

class InterfaceMonitor {
public:
  explicit InterfaceMonitor(HistoryStore* history = nullptr);

  // Collects current interface inventory + calculates per-interface rates + periodically persists SQLite samples.
  InterfaceInventorySnapshot collect(uint64_t nowMs);
  InterfaceInventorySnapshot getSnapshot() const {
    std::lock_guard lock(mutex_);
    return lastSnapshot_;
  }
  std::string getSnapshotJson() const;

private:
  InterfaceInventorySnapshot collectOsRaw(uint64_t nowMs);

  HistoryStore* history_ = nullptr;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, InterfaceRatePrev> prevCounters_;
  InterfaceInventorySnapshot lastSnapshot_;
  bool hasPrevSnapshot_ = false;
  uint64_t lastDbSampleMs_ = 0;
};

} // namespace netpulse
