#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace netpulse {

enum class IpScope : uint8_t {
  Unknown = 0,
  Loopback = 1,
  Lan = 2,
  Public = 3,
};

enum class Lifecycle : uint8_t {
  Active = 0,
  New = 1,
  Closed = 2,
};

struct GeoInfo {
  bool resolved = false;
  bool failed = false;
  std::string country;
  std::string countryCode;
  std::string region;
  std::string city;
  std::string isp;
  std::string org;
  std::string asn;
  double lat = 0.0;
  double lon = 0.0;
  int attempts = 0;
  uint64_t nextRetryMs = 0;
};

struct HostGeo {
  bool resolved = false;
  std::string publicIp;
  std::string country = "Local";
  std::string countryCode = "--";
  std::string region;
  std::string city = "Local Host";
  std::string isp;
  double lat = 0.0;
  double lon = 0.0;
};

struct SocketEntry {
  std::string key;
  std::string protocol;  // "TCP" | "UDP"
  uint8_t ipVersion = 4; // 4 | 6
  std::string localIp;
  std::string remoteIp;
  uint16_t localPort = 0;
  uint16_t remotePort = 0;
  std::string state;
  uint32_t pid = 0;
  std::string processName;
  std::string processPath;
  IpScope scope = IpScope::Unknown;
  Lifecycle lifecycle = Lifecycle::Active;
  uint64_t firstSeenMs = 0;
  uint64_t lastSeenMs = 0;
};

struct NicThroughput {
  double rxBytesPerSec = 0.0;
  double txBytesPerSec = 0.0;
  uint64_t totalRxBytes = 0;
  uint64_t totalTxBytes = 0;
  uint32_t activeInterfaces = 0;
};

struct TelemetrySnapshot {
  uint64_t timestampMs = 0;
  uint64_t pollLatencyUs = 0;
  uint32_t totalConnections = 0;
  uint32_t publicConnections = 0;
  uint32_t lanConnections = 0;
  uint32_t listeningSockets = 0;
  NicThroughput nic;
  HostGeo hostGeo;
  std::vector<SocketEntry> connections;
};

inline const char* scopeToString(IpScope s) {
  switch (s) {
    case IpScope::Loopback:
      return "loopback";
    case IpScope::Lan:
      return "lan";
    case IpScope::Public:
      return "public";
    default:
      return "unknown";
  }
}

inline const char* lifecycleToString(Lifecycle l) {
  switch (l) {
    case Lifecycle::New:
      return "new";
    case Lifecycle::Closed:
      return "closed";
    default:
      return "active";
  }
}

inline void appendJsonEscaped(std::string& out, const std::string& s) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  out.push_back('"');
}

} // namespace netpulse
