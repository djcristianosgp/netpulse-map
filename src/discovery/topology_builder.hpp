#pragma once

#include "../models.hpp"
#include "../network/interface_monitor.hpp"
#include "../quality/network_quality_engine.hpp"
#include "discovery_engine.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace netpulse {

struct TopoNode {
  std::string id;
  std::string kind;   // "host" | "interface" | "gateway" | "dns" | "lan_device" | "upstream"
  std::string label;
  std::string sublabel;
  std::string ip;
  std::string mac;
  std::string vendor;
  std::string deviceType;
  std::string status = "unknown"; // "up" | "down" | "online" | "offline" | "degraded"
  std::string subnet;
  std::string openPorts;
  int layer = 0;
  bool isPrimary = false;
  uint64_t linkSpeedBps = 0;
  double rxBps = 0.0;
  double txBps = 0.0;
  double latencyMs = 0.0;
  uint32_t activeConns = 0;
};

struct TopoEdge {
  std::string id;
  std::string source;
  std::string target;
  std::string kind;     // "local_nic" | "default_route" | "arp_subnet" | "dns_config" | "active_socket" | "quality_probe"
  std::string label;
  std::string evidence; // Technical basis (ARP, routing table, active socket, DNS config, ICMP/TCP/DNS probe)
  double rttMs = 0.0;
  uint32_t activeSessions = 0;
};

struct LanTopologySnapshot {
  uint64_t generatedAtMs = 0;
  std::string localHostname;
  std::string modelNote;
  uint32_t onlineDevices = 0;
  uint32_t totalDevices = 0;
  uint32_t activeSockets = 0;
  std::vector<TopoNode> nodes;
  std::vector<TopoEdge> edges;
};

LanTopologySnapshot buildLanTopology(uint64_t nowMs,
                                     const std::string& localHostname,
                                     const InterfaceInventorySnapshot& ifSnap,
                                     const std::vector<LanDeviceRecord>& devices,
                                     const std::vector<QualityTargetSnapshot>& qualityTargets,
                                     const TelemetrySnapshot* telemetry);

std::string serializeLanTopologyJson(const LanTopologySnapshot& snap);

} // namespace netpulse
