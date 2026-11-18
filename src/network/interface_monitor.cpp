#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#endif

#include "interface_monitor.hpp"
#include "../models.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <unordered_set>

namespace netpulse {

namespace {

std::string toLowerCopy(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

bool containsAny(const std::string& hay, std::initializer_list<const char*> needles) {
  for (const char* n : needles) {
    if (hay.find(n) != std::string::npos) return true;
  }
  return false;
}

#ifdef _WIN32
std::string wideToUtf8Local(const wchar_t* wstr) {
  if (!wstr || !*wstr) return {};
  int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
  if (needed <= 1) return {};
  std::string out(static_cast<size_t>(needed - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, out.data(), needed, nullptr, nullptr);
  return out;
}

std::string sockaddrToIpString(const sockaddr* sa) {
  if (!sa) return {};
  char buf[INET6_ADDRSTRLEN] = {};
  if (sa->sa_family == AF_INET) {
    const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) return buf;
  } else if (sa->sa_family == AF_INET6) {
    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) return buf;
  }
  return {};
}

std::string winOperStatusString(IF_OPER_STATUS st) {
  switch (st) {
    case IfOperStatusUp: return "up";
    case IfOperStatusDown: return "down";
    case IfOperStatusTesting: return "testing";
    case IfOperStatusDormant: return "dormant";
    case IfOperStatusNotPresent: return "not_present";
    case IfOperStatusLowerLayerDown: return "down";
    default: return "unknown";
  }
}
#endif

void pushUnique(std::vector<std::string>& vec, const std::string& val) {
  if (val.empty()) return;
  if (std::find(vec.begin(), vec.end(), val) == vec.end()) {
    vec.push_back(val);
  }
}

void appendStrArray(std::string& out, const std::vector<std::string>& arr) {
  out.push_back('[');
  for (size_t i = 0; i < arr.size(); ++i) {
    if (i > 0) out.push_back(',');
    appendJsonEscaped(out, arr[i]);
  }
  out.push_back(']');
}

} // namespace

std::string classifyInterfaceType(uint32_t ifType,
                                  const std::string& name,
                                  const std::string& desc,
                                  bool isHardware) {
  const std::string combo = toLowerCopy(name + " " + desc);

  if (ifType == 24 || ifType == 772 || containsAny(combo, {"loopback", "lo0"})) {
    return "loopback";
  }
  if (containsAny(combo, {"wireguard", "openvpn", "wintun", "tailscale", "zerotier",
                          "nordlynx", "anyconnect", "fortinet", "ppp adapter", "vpn", "tun0", "wg0"})) {
    return "vpn";
  }
  if (containsAny(combo, {"hyper-v", "vethernet", "vmware", "virtualbox", "vbox", "docker",
                          "br-", "veth", "wsl", "bridge", "virtio", "virtual", "km-test", "microsoft wi-fi direct"})) {
    return "virtual";
  }
  if (ifType == 71 || containsAny(combo, {"wi-fi", "wifi", "wlan", "802.11", "wireless"})) {
    return "wifi";
  }
  if (ifType == 131 || ifType == 23 || ifType == 65534) {
    return "tunnel";
  }
  if (ifType == 6 || isHardware || containsAny(combo, {"ethernet", "gigabit", "realtek", "intel(r)", "eth", "enp", "eno"})) {
    return "ethernet";
  }
  return "other";
}

std::string formatMacAddress(const uint8_t* bytes, size_t len) {
  if (!bytes || len == 0) return {};
  bool allZero = true;
  for (size_t i = 0; i < len; ++i) {
    if (bytes[i] != 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) return {};

  std::string out;
  out.reserve(len * 3);
  char hex[4];
  for (size_t i = 0; i < len; ++i) {
    if (i > 0) out.push_back(':');
    std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
    out += hex;
  }
  return out;
}

void computeInterfaceRates(InterfaceRatePrev& prev, NetworkInterfaceInfo& cur, uint64_t nowMs) {
  if (prev.tsMs > 0 && nowMs > prev.tsMs) {
    const double dtSec = static_cast<double>(nowMs - prev.tsMs) / 1000.0;
    if (dtSec > 0.05) {
      if (cur.rxBytes >= prev.rxBytes) {
        cur.rxBps = static_cast<double>(cur.rxBytes - prev.rxBytes) / dtSec;
      }
      if (cur.txBytes >= prev.txBytes) {
        cur.txBps = static_cast<double>(cur.txBytes - prev.txBytes) / dtSec;
      }
      if (cur.rxPackets >= prev.rxPackets) {
        cur.rxPps = static_cast<double>(cur.rxPackets - prev.rxPackets) / dtSec;
      }
      if (cur.txPackets >= prev.txPackets) {
        cur.txPps = static_cast<double>(cur.txPackets - prev.txPackets) / dtSec;
      }
    }
  }
  prev.tsMs = nowMs;
  prev.rxBytes = cur.rxBytes;
  prev.txBytes = cur.txBytes;
  prev.rxPackets = cur.rxPackets;
  prev.txPackets = cur.txPackets;
}

std::vector<MultiWanEvent> detectMultiWanTransitions(const InterfaceInventorySnapshot& prev,
                                                     const InterfaceInventorySnapshot& cur) {
  std::vector<MultiWanEvent> events;

  if (!prev.primaryIfId.empty() && !cur.primaryIfId.empty() && prev.primaryIfId != cur.primaryIfId) {
    events.push_back(MultiWanEvent{
        "warn",
        "wan_primary_changed",
        "Rota padrão (WAN primária) alternada",
        prev.primaryIfName + " (" + prev.primaryGateway + ") → " + cur.primaryIfName + " (" + cur.primaryGateway + ")",
    });
  }

  std::unordered_map<std::string, const NetworkInterfaceInfo*> prevMap;
  for (const auto& p : prev.interfaces) {
    prevMap[p.id] = &p;
  }

  for (const auto& c : cur.interfaces) {
    if (!c.isWanCandidate && c.type != "vpn") continue;
    auto it = prevMap.find(c.id);
    if (it == prevMap.end()) continue;
    const auto* p = it->second;
    if (p->operStatus == "up" && c.operStatus == "down") {
      events.push_back(MultiWanEvent{
          "critical",
          "interface_down",
          "Interface WAN/Uplink desconectada: " + c.name,
          c.description + (c.gateways.empty() ? "" : " · gw " + c.gateways.front()),
      });
    } else if (p->operStatus == "down" && c.operStatus == "up") {
      events.push_back(MultiWanEvent{
          "info",
          "interface_up",
          "Interface WAN/Uplink restabelecida: " + c.name,
          c.description + (c.gateways.empty() ? "" : " · gw " + c.gateways.front()),
      });
    }
  }
  return events;
}

std::string serializeInterfacesJson(const InterfaceInventorySnapshot& snap) {
  char num[32];
  auto appendNum = [&](std::string& dst, double v) {
    std::snprintf(num, sizeof(num), "%.1f", v);
    dst += num;
  };

  std::string out = "{\"collectedAt\":";
  out += std::to_string(snap.collectedAtMs);
  out += ",\"primaryIfId\":";
  appendJsonEscaped(out, snap.primaryIfId);
  out += ",\"primaryIfName\":";
  appendJsonEscaped(out, snap.primaryIfName);
  out += ",\"primaryGateway\":";
  appendJsonEscaped(out, snap.primaryGateway);
  out += ",\"wanCount\":";
  out += std::to_string(snap.wanCount);
  out += ",\"activeWanCount\":";
  out += std::to_string(snap.activeWanCount);
  out += ",\"totalRxBps\":";
  appendNum(out, snap.totalRxBps);
  out += ",\"totalTxBps\":";
  appendNum(out, snap.totalTxBps);
  out += ",\"interfaces\":[";

  for (size_t i = 0; i < snap.interfaces.size(); ++i) {
    const auto& ifc = snap.interfaces[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    appendJsonEscaped(out, ifc.id);
    out += ",\"ifIndex\":";
    out += std::to_string(ifc.ifIndex);
    out += ",\"name\":";
    appendJsonEscaped(out, ifc.name);
    out += ",\"description\":";
    appendJsonEscaped(out, ifc.description);
    out += ",\"type\":";
    appendJsonEscaped(out, ifc.type);
    out += ",\"mac\":";
    appendJsonEscaped(out, ifc.macAddress);
    out += ",\"operStatus\":";
    appendJsonEscaped(out, ifc.operStatus);
    out += ",\"mediaConnected\":";
    out += (ifc.mediaConnected ? "true" : "false");
    out += ",\"hardware\":";
    out += (ifc.hardwareInterface ? "true" : "false");
    out += ",\"isDefaultRoute\":";
    out += (ifc.isDefaultRoute ? "true" : "false");
    out += ",\"isWanCandidate\":";
    out += (ifc.isWanCandidate ? "true" : "false");
    out += ",\"linkSpeedBps\":";
    out += std::to_string(ifc.linkSpeedBps);
    out += ",\"mtu\":";
    out += std::to_string(ifc.mtu);
    out += ",\"ipv4\":";
    appendStrArray(out, ifc.ipv4);
    out += ",\"ipv6\":";
    appendStrArray(out, ifc.ipv6);
    out += ",\"gateways\":";
    appendStrArray(out, ifc.gateways);
    out += ",\"dnsServers\":";
    appendStrArray(out, ifc.dnsServers);
    out += ",\"rxBytes\":";
    out += std::to_string(ifc.rxBytes);
    out += ",\"txBytes\":";
    out += std::to_string(ifc.txBytes);
    out += ",\"rxPackets\":";
    out += std::to_string(ifc.rxPackets);
    out += ",\"txPackets\":";
    out += std::to_string(ifc.txPackets);
    out += ",\"rxErrors\":";
    out += std::to_string(ifc.rxErrors);
    out += ",\"txErrors\":";
    out += std::to_string(ifc.txErrors);
    out += ",\"rxDiscards\":";
    out += std::to_string(ifc.rxDiscards);
    out += ",\"txDiscards\":";
    out += std::to_string(ifc.txDiscards);
    out += ",\"rxBps\":";
    appendNum(out, ifc.rxBps);
    out += ",\"txBps\":";
    appendNum(out, ifc.txBps);
    out += ",\"rxPps\":";
    appendNum(out, ifc.rxPps);
    out += ",\"txPps\":";
    appendNum(out, ifc.txPps);
    out.push_back('}');
  }

  out += "]}";
  return out;
}

InterfaceMonitor::InterfaceMonitor(HistoryStore* history)
    : history_(history) {}

InterfaceInventorySnapshot InterfaceMonitor::collectOsRaw(uint64_t nowMs) {
  InterfaceInventorySnapshot snap;
  snap.collectedAtMs = nowMs;

#ifdef _WIN32
  DWORD bestIfIdx = 0;
  IN_ADDR probeDst{};
  if (inet_pton(AF_INET, "8.8.8.8", &probeDst) == 1) {
    if (GetBestInterface(probeDst.S_un.S_addr, &bestIfIdx) != NO_ERROR) {
      bestIfIdx = 0;
    }
  }

  struct IfMerge {
    NetworkInterfaceInfo info;
    uint32_t rawType = 0;
    bool isFilter = false;
  };
  std::unordered_map<uint32_t, IfMerge> byIndex;

  // 1. Address, Gateway, DNS & Adapter metadata
  ULONG bufLen = 32768;
  std::vector<uint8_t> buf(bufLen);
  const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  ULONG rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                  reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &bufLen);
  if (rc == ERROR_BUFFER_OVERFLOW) {
    buf.resize(bufLen);
    rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                              reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &bufLen);
  }
  if (rc == NO_ERROR) {
    for (auto* ad = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()); ad != nullptr; ad = ad->Next) {
      const uint32_t idx = (ad->IfIndex != 0) ? static_cast<uint32_t>(ad->IfIndex)
                                              : static_cast<uint32_t>(ad->Ipv6IfIndex);
      if (idx == 0) continue;
      auto& m = byIndex[idx];
      auto& info = m.info;
      info.ifIndex = idx;
      info.id = "if-" + std::to_string(idx);
      info.name = wideToUtf8Local(ad->FriendlyName);
      info.description = wideToUtf8Local(ad->Description);
      info.macAddress = formatMacAddress(ad->PhysicalAddress, static_cast<size_t>(ad->PhysicalAddressLength));
      info.mtu = static_cast<uint32_t>(ad->Mtu);
      info.operStatus = winOperStatusString(ad->OperStatus);
      m.rawType = static_cast<uint32_t>(ad->IfType);
      if (ad->ReceiveLinkSpeed > 0 && ad->ReceiveLinkSpeed < 0xFFFFFFFFFFFFFFFFULL) {
        info.linkSpeedBps = ad->ReceiveLinkSpeed;
      } else if (ad->TransmitLinkSpeed > 0 && ad->TransmitLinkSpeed < 0xFFFFFFFFFFFFFFFFULL) {
        info.linkSpeedBps = ad->TransmitLinkSpeed;
      }

      for (auto* ua = ad->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
        std::string ip = sockaddrToIpString(ua->Address.lpSockaddr);
        if (ip.empty()) continue;
        if (ua->Address.lpSockaddr->sa_family == AF_INET) pushUnique(info.ipv4, ip);
        else if (ua->Address.lpSockaddr->sa_family == AF_INET6) pushUnique(info.ipv6, ip);
      }
      for (auto* gw = ad->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
        std::string ip = sockaddrToIpString(gw->Address.lpSockaddr);
        if (!ip.empty() && ip != "0.0.0.0") pushUnique(info.gateways, ip);
      }
      for (auto* dns = ad->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
        std::string ip = sockaddrToIpString(dns->Address.lpSockaddr);
        // Ignore Windows site-local fec0:: DNS placeholders when adapter has no real IPv6 DNS
        if (!ip.empty() && ip != "0.0.0.0" && ip.rfind("fec0:", 0) != 0) {
          pushUnique(info.dnsServers, ip);
        }
      }
    }
  }

  // 2. Live MIB-II 64-bit counters (bytes, packets, errors, discards, link speed)
  PMIB_IF_TABLE2 ifTable = nullptr;
  if (GetIfTable2(&ifTable) == NO_ERROR && ifTable) {
    for (ULONG i = 0; i < ifTable->NumEntries; ++i) {
      const MIB_IF_ROW2& row = ifTable->Table[i];
      if (row.InterfaceAndOperStatusFlags.FilterInterface) continue;
      auto it = byIndex.find(static_cast<uint32_t>(row.InterfaceIndex));
      if (it == byIndex.end()) continue; // Skip hidden kernel sublayers without adapter addresses

      auto& m = it->second;
      auto& info = m.info;
      info.hardwareInterface = (row.InterfaceAndOperStatusFlags.HardwareInterface != 0);
      info.mediaConnected = (row.MediaConnectState == MediaConnectStateConnected);
      info.operStatus = winOperStatusString(row.OperStatus);
      if (row.ReceiveLinkSpeed > 0 && row.ReceiveLinkSpeed < 0xFFFFFFFFFFFFFFFFULL) {
        info.linkSpeedBps = row.ReceiveLinkSpeed;
      } else if (row.TransmitLinkSpeed > 0 && row.TransmitLinkSpeed < 0xFFFFFFFFFFFFFFFFULL) {
        info.linkSpeedBps = row.TransmitLinkSpeed;
      }
      info.rxBytes = row.InOctets;
      info.txBytes = row.OutOctets;
      info.rxPackets = row.InUcastPkts + row.InNUcastPkts;
      info.txPackets = row.OutUcastPkts + row.OutNUcastPkts;
      info.rxErrors = row.InErrors;
      info.txErrors = row.OutErrors;
      info.rxDiscards = row.InDiscards;
      info.txDiscards = row.OutDiscards;
      if (m.rawType == 0) m.rawType = static_cast<uint32_t>(row.Type);
    }
    FreeMibTable(ifTable);
  }

  for (auto& [idx, m] : byIndex) {
    auto& info = m.info;
    info.type = classifyInterfaceType(m.rawType, info.name, info.description, info.hardwareInterface);
    info.isDefaultRoute = (bestIfIdx != 0 && idx == bestIfIdx);
    info.isWanCandidate = (info.type != "loopback") &&
                          (info.hardwareInterface || info.type == "vpn" || !info.gateways.empty());
    if (info.isDefaultRoute) {
      snap.primaryIfId = info.id;
      snap.primaryIfName = info.name;
      if (!info.gateways.empty()) snap.primaryGateway = info.gateways.front();
    }
    if (info.isWanCandidate) {
      snap.wanCount++;
      if (info.operStatus == "up") snap.activeWanCount++;
    }
    snap.interfaces.push_back(std::move(info));
  }
#else
  struct LinuxIfaceAccum {
    NetworkInterfaceInfo info;
    uint32_t sysType = 0;
  };
  std::unordered_map<std::string, LinuxIfaceAccum> byName;

  // 1. /proc/net/dev for bytes, packets, errs, drops
  std::ifstream devIn("/proc/net/dev");
  if (devIn.is_open()) {
    std::string line;
    std::getline(devIn, line);
    std::getline(devIn, line);
    while (std::getline(devIn, line)) {
      auto colon = line.find(':');
      if (colon == std::string::npos) continue;
      std::string name = line.substr(0, colon);
      name.erase(0, name.find_first_not_of(" \t"));
      name.erase(name.find_last_not_of(" \t") + 1);
      if (name.empty()) continue;

      std::istringstream iss(line.substr(colon + 1));
      uint64_t rBytes = 0, rPkts = 0, rErr = 0, rDrop = 0, f1 = 0, f2 = 0, f3 = 0, f4 = 0;
      uint64_t tBytes = 0, tPkts = 0, tErr = 0, tDrop = 0;
      if (iss >> rBytes >> rPkts >> rErr >> rDrop >> f1 >> f2 >> f3 >> f4 >> tBytes >> tPkts >> tErr >> tDrop) {
        auto& acc = byName[name];
        acc.info.id = name;
        acc.info.name = name;
        acc.info.rxBytes = rBytes;
        acc.info.rxPackets = rPkts;
        acc.info.rxErrors = rErr;
        acc.info.rxDiscards = rDrop;
        acc.info.txBytes = tBytes;
        acc.info.txPackets = tPkts;
        acc.info.txErrors = tErr;
        acc.info.txDiscards = tDrop;
      }
    }
  }

  // 2. getifaddrs for IPv4/IPv6 & flags
  struct ifaddrs* ifap = nullptr;
  if (getifaddrs(&ifap) == 0 && ifap) {
    for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
      if (!ifa->ifa_name) continue;
      auto& acc = byName[ifa->ifa_name];
      acc.info.id = ifa->ifa_name;
      acc.info.name = ifa->ifa_name;
      acc.info.ifIndex = static_cast<uint32_t>(if_nametoindex(ifa->ifa_name));
      acc.info.mediaConnected = ((ifa->ifa_flags & IFF_RUNNING) != 0);
      acc.info.operStatus = ((ifa->ifa_flags & IFF_UP) != 0) ? "up" : "down";
      if (ifa->ifa_addr) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (ifa->ifa_addr->sa_family == AF_INET) {
          auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
          if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) pushUnique(acc.info.ipv4, buf);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
          auto* sin6 = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
          if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) pushUnique(acc.info.ipv6, buf);
        }
      }
    }
    freeifaddrs(ifap);
  }

  // 3. /proc/net/route for gateways + lowest-metric default route
  std::string bestDefaultIface;
  uint64_t bestMetric = UINT64_MAX;
  std::ifstream routeIn("/proc/net/route");
  if (routeIn.is_open()) {
    std::string line;
    std::getline(routeIn, line);
    while (std::getline(routeIn, line)) {
      std::istringstream ss(line);
      std::string iface, destHex, gwHex, flagsHex, ref, use, metricStr;
      if (!(ss >> iface >> destHex >> gwHex >> flagsHex >> ref >> use >> metricStr)) continue;
      if (destHex == "00000000" && gwHex.size() == 8 && gwHex != "00000000") {
        uint32_t rawGw = static_cast<uint32_t>(std::strtoul(gwHex.c_str(), nullptr, 16));
        struct in_addr a{};
        a.s_addr = rawGw;
        char ipBuf[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &a, ipBuf, sizeof(ipBuf))) {
          auto& acc = byName[iface];
          pushUnique(acc.info.gateways, ipBuf);
          uint64_t metric = std::strtoull(metricStr.c_str(), nullptr, 10);
          if (metric < bestMetric) {
            bestMetric = metric;
            bestDefaultIface = iface;
          }
        }
      }
    }
  }

  std::vector<std::string> systemDns;
  std::ifstream resIn("/etc/resolv.conf");
  if (resIn.is_open()) {
    std::string line;
    while (std::getline(resIn, line)) {
      std::istringstream ss(line);
      std::string kw, ip;
      if ((ss >> kw >> ip) && kw == "nameserver") {
        pushUnique(systemDns, ip);
      }
    }
  }

  auto readSysText = [](const std::string& p) -> std::string {
    std::ifstream in(p);
    std::string val;
    if (in.is_open()) std::getline(in, val);
    return val;
  };

  for (auto& [name, acc] : byName) {
    const std::string base = "/sys/class/net/" + name;
    std::string mac = readSysText(base + "/address");
    if (!mac.empty() && mac != "00:00:00:00:00:00") {
      std::transform(mac.begin(), mac.end(), mac.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
      acc.info.macAddress = std::move(mac);
    }
    if (std::string mtuStr = readSysText(base + "/mtu"); !mtuStr.empty()) {
      acc.info.mtu = static_cast<uint32_t>(std::strtoul(mtuStr.c_str(), nullptr, 10));
    }
    if (std::string opStr = readSysText(base + "/operstate"); !opStr.empty() && opStr != "unknown") {
      acc.info.operStatus = opStr;
    }
    if (std::string spdStr = readSysText(base + "/speed"); !spdStr.empty()) {
      long long mbps = std::strtoll(spdStr.c_str(), nullptr, 10);
      if (mbps > 0) acc.info.linkSpeedBps = static_cast<uint64_t>(mbps) * 1000000ULL;
    }
    if (std::string tStr = readSysText(base + "/type"); !tStr.empty()) {
      acc.sysType = static_cast<uint32_t>(std::strtoul(tStr.c_str(), nullptr, 10));
    }
    std::error_code ec;
    acc.info.hardwareInterface = std::filesystem::exists(base + "/device", ec);
    acc.info.type = classifyInterfaceType(acc.sysType, name, "", acc.info.hardwareInterface);
    if (!acc.info.gateways.empty()) acc.info.dnsServers = systemDns;
    acc.info.isDefaultRoute = (!bestDefaultIface.empty() && name == bestDefaultIface);
    acc.info.isWanCandidate = (acc.info.type != "loopback") &&
                              (acc.info.hardwareInterface || acc.info.type == "vpn" || !acc.info.gateways.empty());
    if (acc.info.isDefaultRoute) {
      snap.primaryIfId = acc.info.id;
      snap.primaryIfName = acc.info.name;
      if (!acc.info.gateways.empty()) snap.primaryGateway = acc.info.gateways.front();
    }
    if (acc.info.isWanCandidate) {
      snap.wanCount++;
      if (acc.info.operStatus == "up") snap.activeWanCount++;
    }
    snap.interfaces.push_back(std::move(acc.info));
  }
#endif

  // Sort: primary default route first, then up hardware/WAN, then active, then loopback/down
  std::sort(snap.interfaces.begin(), snap.interfaces.end(), [](const NetworkInterfaceInfo& a, const NetworkInterfaceInfo& b) {
    if (a.isDefaultRoute != b.isDefaultRoute) return a.isDefaultRoute;
    if (a.isWanCandidate != b.isWanCandidate) return a.isWanCandidate;
    if ((a.operStatus == "up") != (b.operStatus == "up")) return a.operStatus == "up";
    if ((a.rxBytes + a.txBytes) != (b.rxBytes + b.txBytes)) return (a.rxBytes + a.txBytes) > (b.rxBytes + b.txBytes);
    return a.name < b.name;
  });

  return snap;
}

InterfaceInventorySnapshot InterfaceMonitor::collect(uint64_t nowMs) {
  auto snap = collectOsRaw(nowMs);

  std::vector<MultiWanEvent> transitions;
  bool shouldPersistSample = false;

  {
    std::lock_guard lock(mutex_);
    for (auto& ifc : snap.interfaces) {
      computeInterfaceRates(prevCounters_[ifc.id], ifc, nowMs);
      if (ifc.type != "loopback" && ifc.operStatus == "up") {
        snap.totalRxBps += ifc.rxBps;
        snap.totalTxBps += ifc.txBps;
      }
    }

    if (hasPrevSnapshot_) {
      transitions = detectMultiWanTransitions(lastSnapshot_, snap);
    }
    lastSnapshot_ = snap;
    hasPrevSnapshot_ = true;

    if (history_ && (lastDbSampleMs_ == 0 || (nowMs >= lastDbSampleMs_ && (nowMs - lastDbSampleMs_) >= 10000ULL))) {
      lastDbSampleMs_ = nowMs;
      shouldPersistSample = true;
    }
  }

  if (history_) {
    for (const auto& ev : transitions) {
      history_->recordManualAction(ev.severity, ev.title, ev.detail);
    }
    if (shouldPersistSample) {
      std::vector<InterfaceSampleRecord> batch;
      for (const auto& ifc : snap.interfaces) {
        if (ifc.operStatus != "up" && !ifc.isWanCandidate && ifc.rxBytes == 0 && ifc.txBytes == 0) continue;
        batch.push_back(InterfaceSampleRecord{
            nowMs,
            ifc.id,
            ifc.name,
            ifc.type,
            ifc.operStatus,
            ifc.isDefaultRoute,
            ifc.linkSpeedBps,
            ifc.rxBps,
            ifc.txBps,
            ifc.rxBytes,
            ifc.txBytes,
            ifc.rxErrors,
            ifc.txErrors,
        });
      }
      history_->enqueueInterfaceSamples(batch);
    }
  }

  return snap;
}

std::string InterfaceMonitor::getSnapshotJson() const {
  InterfaceInventorySnapshot snapCopy;
  {
    std::lock_guard lock(mutex_);
    snapCopy = lastSnapshot_;
  }
  return serializeInterfacesJson(snapCopy);
}

} // namespace netpulse
