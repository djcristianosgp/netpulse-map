#pragma once

#include "models.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace netpulse {

bool isProcessElevated();
IpScope classifyIpv4(const uint8_t bytes[4]);
IpScope classifyIpv6(const uint8_t bytes[16]);
IpScope classifyIpString(const std::string& ip);
std::string normalizeIpForGeo(const std::string& ip);
const char* tcpStateToString(uint32_t state);

class NetMonitor {
public:
  NetMonitor();

  // Polls TCPv4, TCPv6, UDPv4, UDPv6, per-socket EStats (if elevated) or Process I/O, and NIC counters.
  TelemetrySnapshot poll(uint64_t nowMs);

private:
  struct ProcCacheEntry {
    std::string name;
    std::string path;
    uint64_t lastCheckedMs = 0;
    uint64_t prevIoBytes = 0;
    uint64_t prevIoTimeMs = 0;
    double ioBps = 0.0;
  };

  struct TrackedSocket {
    SocketEntry entry;
    uint64_t closedAtMs = 0;
    uint64_t prevBytesIn = 0;
    uint64_t prevBytesOut = 0;
    uint64_t prevStatsMs = 0;
    bool estatsEnabled = false;
  };

  void pollTcp4(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs);
  void pollTcp6(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs);
  void pollUdp4(std::vector<SocketEntry>& out, uint32_t& listeningCount);
  void pollUdp6(std::vector<SocketEntry>& out, uint32_t& listeningCount);
  NicThroughput pollNicThroughput(uint64_t nowMs);

  void resolveProcessInfo(uint32_t pid,
                          uint64_t nowMs,
                          const std::unordered_map<uint32_t, std::string>& snapshotMap,
                          std::string& outName,
                          std::string& outPath,
                          double& outIoBps);

  std::unordered_map<uint32_t, std::string> buildProcessSnapshotMap();

  bool elevated_ = false;
  std::unordered_map<uint32_t, ProcCacheEntry> procCache_;
  std::unordered_map<std::string, TrackedSocket> activeTracked_;
  std::unordered_map<std::string, TrackedSocket> recentlyClosed_;

  uint64_t prevNicSampleMs_ = 0;
  uint64_t prevNicRxBytes_ = 0;
  uint64_t prevNicTxBytes_ = 0;
};

} // namespace netpulse
