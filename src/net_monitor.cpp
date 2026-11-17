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
#include <tlhelp32.h>

#include "net_monitor.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace netpulse {

namespace {

std::string wideToUtf8(const wchar_t* wstr, int len = -1) {
  if (!wstr) return {};
  int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) return {};
  std::string out(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wstr, len, out.data(), needed, nullptr, nullptr);
  if (len == -1 && !out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}

std::string basenameFromPath(const std::string& path) {
  size_t pos = path.find_last_of("\\/");
  return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string formatIpv4(uint32_t addrNetOrder) {
  char buf[INET_ADDRSTRLEN] = {};
  IN_ADDR in{};
  in.S_un.S_addr = addrNetOrder;
  if (inet_ntop(AF_INET, &in, buf, sizeof(buf))) {
    return std::string(buf);
  }
  return "0.0.0.0";
}

std::string formatIpv6(const uint8_t bytes[16]) {
  char buf[INET6_ADDRSTRLEN] = {};
  IN6_ADDR in6{};
  std::memcpy(&in6, bytes, 16);
  if (inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) {
    return std::string(buf);
  }
  return "::";
}

std::string makeKey(const char* proto,
                    uint8_t ipVer,
                    const std::string& localIp,
                    uint16_t localPort,
                    const std::string& remoteIp,
                    uint16_t remotePort,
                    uint32_t pid) {
  std::string k;
  k.reserve(96);
  k += proto;
  k += (ipVer == 6 ? "6|" : "4|");
  k += localIp;
  k.push_back(':');
  k += std::to_string(localPort);
  k += "->";
  k += remoteIp;
  k.push_back(':');
  k += std::to_string(remotePort);
  k.push_back('|');
  k += std::to_string(pid);
  return k;
}

} // namespace

IpScope classifyIpv4(const uint8_t b[4]) {
  if (b[0] == 0) return IpScope::Unknown;                          // 0.0.0.0/8
  if (b[0] == 127) return IpScope::Loopback;                       // 127.0.0.0/8
  if (b[0] == 10) return IpScope::Lan;                             // 10.0.0.0/8
  if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return IpScope::Lan;// 172.16.0.0/12
  if (b[0] == 192 && b[1] == 168) return IpScope::Lan;             // 192.168.0.0/16
  if (b[0] == 169 && b[1] == 254) return IpScope::Lan;             // 169.254.0.0/16 link-local
  if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return IpScope::Lan;// 100.64.0.0/10 CGNAT
  if (b[0] >= 224) return IpScope::Lan;                            // Multicast / Reserved
  return IpScope::Public;
}

IpScope classifyIpv6(const uint8_t b[16]) {
  bool allZero = true;
  for (int i = 0; i < 16; ++i) {
    if (b[i] != 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) return IpScope::Unknown;

  bool isLoopback = true;
  for (int i = 0; i < 15; ++i) {
    if (b[i] != 0) {
      isLoopback = false;
      break;
    }
  }
  if (isLoopback && b[15] == 1) return IpScope::Loopback;

  // IPv4-mapped IPv6 ::ffff:a.b.c.d
  bool isV4Mapped = true;
  for (int i = 0; i < 10; ++i) {
    if (b[i] != 0) {
      isV4Mapped = false;
      break;
    }
  }
  if (isV4Mapped && b[10] == 0xff && b[11] == 0xff) {
    return classifyIpv4(&b[12]);
  }

  // fe80::/10 link-local
  if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return IpScope::Lan;
  // fc00::/7 unique local address
  if ((b[0] & 0xfe) == 0xfc) return IpScope::Lan;
  // ff00::/8 multicast
  if (b[0] == 0xff) return IpScope::Lan;

  return IpScope::Public;
}

IpScope classifyIpString(const std::string& ip) {
  IN_ADDR in4{};
  if (inet_pton(AF_INET, ip.c_str(), &in4) == 1) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&in4);
    return classifyIpv4(bytes);
  }
  IN6_ADDR in6{};
  if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&in6);
    return classifyIpv6(bytes);
  }
  return IpScope::Unknown;
}

std::string normalizeIpForGeo(const std::string& ip) {
  IN6_ADDR in6{};
  if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&in6);
    bool isV4Mapped = true;
    for (int i = 0; i < 10; ++i) {
      if (b[i] != 0) {
        isV4Mapped = false;
        break;
      }
    }
    if (isV4Mapped && b[10] == 0xff && b[11] == 0xff) {
      char buf[INET_ADDRSTRLEN] = {};
      IN_ADDR in4{};
      std::memcpy(&in4, &b[12], 4);
      if (inet_ntop(AF_INET, &in4, buf, sizeof(buf))) {
        return std::string(buf);
      }
    }
  }
  return ip;
}

const char* tcpStateToString(uint32_t state) {
  switch (state) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "UNKNOWN";
  }
}

void NetMonitor::pollTcp4(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  ULONG size = 65536;
  std::vector<uint8_t> buf(size);
  DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  if (ret == ERROR_INSUFFICIENT_BUFFER) {
    buf.resize(size);
    ret = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  }
  if (ret != NO_ERROR) return;

  const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto& row = table->table[i];
    if (row.dwState == MIB_TCP_STATE_LISTEN) {
      ++listeningCount;
      continue;
    }

    const uint8_t* remoteBytes = reinterpret_cast<const uint8_t*>(&row.dwRemoteAddr);
    IpScope scope = classifyIpv4(remoteBytes);
    if (scope == IpScope::Unknown) continue;

    SocketEntry e;
    e.protocol = "TCP";
    e.ipVersion = 4;
    e.localIp = formatIpv4(row.dwLocalAddr);
    e.remoteIp = formatIpv4(row.dwRemoteAddr);
    e.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
    e.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
    e.state = tcpStateToString(row.dwState);
    e.pid = row.dwOwningPid;
    e.scope = scope;
    e.key = makeKey("TCP", 4, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollTcp6(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  ULONG size = 65536;
  std::vector<uint8_t> buf(size);
  DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
  if (ret == ERROR_INSUFFICIENT_BUFFER) {
    buf.resize(size);
    ret = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
  }
  if (ret != NO_ERROR) return;

  const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto& row = table->table[i];
    if (row.dwState == MIB_TCP_STATE_LISTEN) {
      ++listeningCount;
      continue;
    }

    IpScope scope = classifyIpv6(row.ucRemoteAddr);
    if (scope == IpScope::Unknown) continue;

    std::string rawRemote = formatIpv6(row.ucRemoteAddr);
    std::string normRemote = normalizeIpForGeo(rawRemote);

    SocketEntry e;
    e.protocol = "TCP";
    e.ipVersion = (normRemote != rawRemote) ? 4 : 6;
    e.localIp = normalizeIpForGeo(formatIpv6(row.ucLocalAddr));
    e.remoteIp = std::move(normRemote);
    e.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
    e.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
    e.state = tcpStateToString(row.dwState);
    e.pid = row.dwOwningPid;
    e.scope = scope;
    e.key = makeKey("TCP", e.ipVersion, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollUdp4(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  ULONG size = 32768;
  std::vector<uint8_t> buf(size);
  DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
  if (ret == ERROR_INSUFFICIENT_BUFFER) {
    buf.resize(size);
    ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
  }
  if (ret != NO_ERROR) return;

  const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
  // UDP sockets are connectionless endpoints bound locally; count them in listening/UDP stats.
  listeningCount += table->dwNumEntries;
  (void)out;
}

void NetMonitor::pollUdp6(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  ULONG size = 32768;
  std::vector<uint8_t> buf(size);
  DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
  if (ret == ERROR_INSUFFICIENT_BUFFER) {
    buf.resize(size);
    ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
  }
  if (ret != NO_ERROR) return;

  const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
  listeningCount += table->dwNumEntries;
  (void)out;
}

NicThroughput NetMonitor::pollNicThroughput(uint64_t nowMs) {
  NicThroughput res;
  PMIB_IF_TABLE2 table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) {
    return res;
  }

  uint64_t hwRx = 0;
  uint64_t hwTx = 0;
  uint32_t hwCount = 0;

  uint64_t fallbackRx = 0;
  uint64_t fallbackTx = 0;
  uint32_t fallbackCount = 0;

  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IF_ROW2& row = table->Table[i];
    if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    if (row.OperStatus != IfOperStatusUp) continue;
    if (row.MediaConnectState != MediaConnectStateConnected) continue;

    if (row.InterfaceAndOperStatusFlags.HardwareInterface) {
      hwRx += row.InOctets;
      hwTx += row.OutOctets;
      ++hwCount;
    } else if (!row.InterfaceAndOperStatusFlags.FilterInterface) {
      fallbackRx += row.InOctets;
      fallbackTx += row.OutOctets;
      ++fallbackCount;
    }
  }

  FreeMibTable(table);

  if (hwCount > 0) {
    res.totalRxBytes = hwRx;
    res.totalTxBytes = hwTx;
    res.activeInterfaces = hwCount;
  } else {
    res.totalRxBytes = fallbackRx;
    res.totalTxBytes = fallbackTx;
    res.activeInterfaces = fallbackCount;
  }

  if (prevNicSampleMs_ > 0 && nowMs > prevNicSampleMs_) {
    double dtSec = static_cast<double>(nowMs - prevNicSampleMs_) / 1000.0;
    if (dtSec > 0.01 && res.totalRxBytes >= prevNicRxBytes_ && res.totalTxBytes >= prevNicTxBytes_) {
      res.rxBytesPerSec = static_cast<double>(res.totalRxBytes - prevNicRxBytes_) / dtSec;
      res.txBytesPerSec = static_cast<double>(res.totalTxBytes - prevNicTxBytes_) / dtSec;
    }
  }

  prevNicSampleMs_ = nowMs;
  prevNicRxBytes_ = res.totalRxBytes;
  prevNicTxBytes_ = res.totalTxBytes;
  return res;
}

std::unordered_map<uint32_t, std::string> NetMonitor::buildProcessSnapshotMap() {
  std::unordered_map<uint32_t, std::string> map;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return map;

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      map[pe.th32ProcessID] = wideToUtf8(pe.szExeFile);
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return map;
}

void NetMonitor::resolveProcessInfo(uint32_t pid,
                                    uint64_t nowMs,
                                    const std::unordered_map<uint32_t, std::string>& snapshotMap,
                                    std::string& outName,
                                    std::string& outPath) {
  if (pid == 0) {
    outName = "System Idle";
    outPath = "";
    return;
  }
  if (pid == 4) {
    outName = "System";
    outPath = "ntoskrnl.exe";
    return;
  }

  auto it = procCache_.find(pid);
  if (it != procCache_.end() && (nowMs - it->second.lastCheckedMs) < 5000) {
    outName = it->second.name;
    outPath = it->second.path;
    return;
  }

  std::string name;
  std::string path;

  HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProc) {
    wchar_t buf[MAX_PATH * 2];
    DWORD sz = static_cast<DWORD>(std::size(buf));
    if (QueryFullProcessImageNameW(hProc, 0, buf, &sz)) {
      path = wideToUtf8(buf, static_cast<int>(sz));
      name = basenameFromPath(path);
    }
    CloseHandle(hProc);
  }

  if (name.empty()) {
    auto snapIt = snapshotMap.find(pid);
    if (snapIt != snapshotMap.end()) {
      name = snapIt->second;
    } else {
      name = "PID " + std::to_string(pid);
    }
  }

  procCache_[pid] = ProcCacheEntry{name, path, nowMs};
  outName = std::move(name);
  outPath = std::move(path);
}

TelemetrySnapshot NetMonitor::poll(uint64_t nowMs) {
  const auto t0 = std::chrono::steady_clock::now();

  std::vector<SocketEntry> raw;
  raw.reserve(256);
  uint32_t listeningCount = 0;

  pollTcp4(raw, listeningCount);
  pollTcp6(raw, listeningCount);
  pollUdp4(raw, listeningCount);
  pollUdp6(raw, listeningCount);

  // Lazy snapshot only if we have PIDs missing from cache or expired.
  bool needSnap = false;
  for (const auto& s : raw) {
    if (s.pid <= 4) continue;
    auto it = procCache_.find(s.pid);
    if (it == procCache_.end() || (nowMs - it->second.lastCheckedMs) >= 5000) {
      needSnap = true;
      break;
    }
  }
  std::unordered_map<uint32_t, std::string> snapMap;
  if (needSnap) {
    snapMap = buildProcessSnapshotMap();
  }

  std::unordered_map<std::string, TrackedSocket> nextActive;
  nextActive.reserve(raw.size());

  TelemetrySnapshot snap;
  snap.timestampMs = nowMs;
  snap.listeningSockets = listeningCount;
  snap.nic = pollNicThroughput(nowMs);

  for (auto& s : raw) {
    resolveProcessInfo(s.pid, nowMs, snapMap, s.processName, s.processPath);

    auto prevIt = activeTracked_.find(s.key);
    if (prevIt != activeTracked_.end()) {
      s.firstSeenMs = prevIt->second.entry.firstSeenMs;
      // Stay "new" for 1200ms so UI catches the arrival pulse cleanly.
      s.lifecycle = (nowMs - s.firstSeenMs < 1200) ? Lifecycle::New : Lifecycle::Active;
    } else {
      s.firstSeenMs = nowMs;
      s.lifecycle = Lifecycle::New;
    }
    s.lastSeenMs = nowMs;

    if (s.scope == IpScope::Public) {
      ++snap.publicConnections;
    } else if (s.scope == IpScope::Lan || s.scope == IpScope::Loopback) {
      ++snap.lanConnections;
    }

    nextActive[s.key] = TrackedSocket{s, 0};
    snap.connections.push_back(std::move(s));
  }

  // Move disappeared sockets into recentlyClosed_ for 1200ms so UI renders closing animation.
  for (auto& [key, tracked] : activeTracked_) {
    if (nextActive.find(key) == nextActive.end()) {
      tracked.entry.lifecycle = Lifecycle::Closed;
      tracked.closedAtMs = nowMs;
      recentlyClosed_[key] = tracked;
    }
  }

  for (auto it = recentlyClosed_.begin(); it != recentlyClosed_.end();) {
    if (nextActive.find(it->first) != nextActive.end() || (nowMs - it->second.closedAtMs) > 1200) {
      it = recentlyClosed_.erase(it);
    } else {
      snap.connections.push_back(it->second.entry);
      ++it;
    }
  }

  activeTracked_ = std::move(nextActive);

  // Prune stale process cache entries periodically.
  if (procCache_.size() > 512) {
    for (auto it = procCache_.begin(); it != procCache_.end();) {
      if ((nowMs - it->second.lastCheckedMs) > 60000) {
        it = procCache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  snap.totalConnections = static_cast<uint32_t>(snap.connections.size());
  const auto t1 = std::chrono::steady_clock::now();
  snap.pollLatencyUs = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());

  return snap;
}

} // namespace netpulse
