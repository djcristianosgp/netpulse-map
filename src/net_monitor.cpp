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
#include <tcpestats.h>
#include <tlhelp32.h>
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#endif

#include "net_monitor.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace netpulse {

namespace {

#ifdef _WIN32
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
#endif

std::string basenameFromPath(const std::string& path) {
  size_t pos = path.find_last_of("\\/");
  return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string formatIpv4(uint32_t addrNetOrder) {
  char buf[INET_ADDRSTRLEN] = {};
  struct in_addr in{};
  in.s_addr = addrNetOrder;
  if (inet_ntop(AF_INET, &in, buf, sizeof(buf))) {
    return std::string(buf);
  }
  return "0.0.0.0";
}

std::string formatIpv6(const uint8_t bytes[16]) {
  char buf[INET6_ADDRSTRLEN] = {};
  struct in6_addr in6{};
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

bool isProcessElevated() {
#ifdef _WIN32
  HANDLE tok = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
  TOKEN_ELEVATION elev{};
  DWORD sz = sizeof(elev);
  BOOL ok = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz);
  CloseHandle(tok);
  return ok && elev.TokenIsElevated != 0;
#else
  return geteuid() == 0;
#endif
}

NetMonitor::NetMonitor() : elevated_(isProcessElevated()) {}

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
  struct in_addr in4{};
  if (inet_pton(AF_INET, ip.c_str(), &in4) == 1) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&in4);
    return classifyIpv4(bytes);
  }
  struct in6_addr in6{};
  if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&in6);
    return classifyIpv6(bytes);
  }
  return IpScope::Unknown;
}

std::string normalizeIpForGeo(const std::string& ip) {
  struct in6_addr in6{};
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
      struct in_addr in4{};
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
    case 1: return "CLOSED";
    case 2: return "LISTEN";
    case 3: return "SYN_SENT";
    case 4: return "SYN_RCVD";
    case 5: return "ESTABLISHED";
    case 6: return "FIN_WAIT1";
    case 7: return "FIN_WAIT2";
    case 8: return "CLOSE_WAIT";
    case 9: return "CLOSING";
    case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";
    case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
  }
}

#ifdef _WIN32

void NetMonitor::pollTcp4(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs) {
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

    if (elevated_ && row.dwState == MIB_TCP_STATE_ESTAB) {
      MIB_TCPROW tcpRow{};
      tcpRow.dwState = row.dwState;
      tcpRow.dwLocalAddr = row.dwLocalAddr;
      tcpRow.dwLocalPort = row.dwLocalPort;
      tcpRow.dwRemoteAddr = row.dwRemoteAddr;
      tcpRow.dwRemotePort = row.dwRemotePort;

      auto prevIt = activeTracked_.find(e.key);
      bool estatsOn = (prevIt != activeTracked_.end() && prevIt->second.estatsEnabled);
      if (!estatsOn) {
        TCP_ESTATS_DATA_RW_v0 rw{};
        rw.EnableCollection = TRUE;
        if (SetPerTcpConnectionEStats(&tcpRow, TcpConnectionEstatsData,
                                      reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0) == NO_ERROR) {
          estatsOn = true;
        }
      }
      if (estatsOn) {
        TCP_ESTATS_DATA_ROD_v0 rod{};
        if (GetPerTcpConnectionEStats(&tcpRow, TcpConnectionEstatsData,
                                      nullptr, 0, 0,
                                      nullptr, 0, 0,
                                      reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod)) == NO_ERROR) {
          if (prevIt != activeTracked_.end() && prevIt->second.prevStatsMs > 0 && nowMs > prevIt->second.prevStatsMs) {
            double dt = static_cast<double>(nowMs - prevIt->second.prevStatsMs) / 1000.0;
            if (dt > 0.01 && rod.DataBytesIn >= prevIt->second.prevBytesIn && rod.DataBytesOut >= prevIt->second.prevBytesOut) {
              e.rxBps = static_cast<double>(rod.DataBytesIn - prevIt->second.prevBytesIn) / dt;
              e.txBps = static_cast<double>(rod.DataBytesOut - prevIt->second.prevBytesOut) / dt;
            }
          }
          // Temporarily stash raw totals inside firstSeenMs? No, store in activeTracked_ during merge.
          e.firstSeenMs = rod.DataBytesIn;
          e.lastSeenMs = rod.DataBytesOut;
        }
      }
    }
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollTcp6(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs) {
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

    if (elevated_ && row.dwState == MIB_TCP_STATE_ESTAB) {
      MIB_TCP6ROW tcp6Row{};
      tcp6Row.State = static_cast<MIB_TCP_STATE>(row.dwState);
      std::memcpy(&tcp6Row.LocalAddr, row.ucLocalAddr, 16);
      tcp6Row.dwLocalScopeId = row.dwLocalScopeId;
      tcp6Row.dwLocalPort = row.dwLocalPort;
      std::memcpy(&tcp6Row.RemoteAddr, row.ucRemoteAddr, 16);
      tcp6Row.dwRemoteScopeId = row.dwRemoteScopeId;
      tcp6Row.dwRemotePort = row.dwRemotePort;

      auto prevIt = activeTracked_.find(e.key);
      bool estatsOn = (prevIt != activeTracked_.end() && prevIt->second.estatsEnabled);
      if (!estatsOn) {
        TCP_ESTATS_DATA_RW_v0 rw{};
        rw.EnableCollection = TRUE;
        if (SetPerTcp6ConnectionEStats(&tcp6Row, TcpConnectionEstatsData,
                                       reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0) == NO_ERROR) {
          estatsOn = true;
        }
      }
      if (estatsOn) {
        TCP_ESTATS_DATA_ROD_v0 rod{};
        if (GetPerTcp6ConnectionEStats(&tcp6Row, TcpConnectionEstatsData,
                                       nullptr, 0, 0,
                                       nullptr, 0, 0,
                                       reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod)) == NO_ERROR) {
          if (prevIt != activeTracked_.end() && prevIt->second.prevStatsMs > 0 && nowMs > prevIt->second.prevStatsMs) {
            double dt = static_cast<double>(nowMs - prevIt->second.prevStatsMs) / 1000.0;
            if (dt > 0.01 && rod.DataBytesIn >= prevIt->second.prevBytesIn && rod.DataBytesOut >= prevIt->second.prevBytesOut) {
              e.rxBps = static_cast<double>(rod.DataBytesIn - prevIt->second.prevBytesIn) / dt;
              e.txBps = static_cast<double>(rod.DataBytesOut - prevIt->second.prevBytesOut) / dt;
            }
          }
          e.firstSeenMs = rod.DataBytesIn;
          e.lastSeenMs = rod.DataBytesOut;
        }
      }
    }
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
                                    std::string& outPath,
                                    double& outIoBps) {
  outIoBps = 0.0;
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

  auto& entry = procCache_[pid];
  const bool needName = entry.name.empty() || (nowMs - entry.lastCheckedMs) >= 5000;
  const bool needIo = (entry.prevIoTimeMs == 0) || (nowMs - entry.prevIoTimeMs) >= 250;

  if (needName || needIo) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
      if (needName) {
        wchar_t buf[MAX_PATH * 2];
        DWORD sz = static_cast<DWORD>(std::size(buf));
        if (QueryFullProcessImageNameW(hProc, 0, buf, &sz)) {
          entry.path = wideToUtf8(buf, static_cast<int>(sz));
          entry.name = basenameFromPath(entry.path);
        }
        entry.lastCheckedMs = nowMs;
      }
      if (needIo) {
        IO_COUNTERS io{};
        if (GetProcessIoCounters(hProc, &io)) {
          const uint64_t totalBytes = io.ReadTransferCount + io.WriteTransferCount + io.OtherTransferCount;
          if (entry.prevIoTimeMs > 0 && nowMs > entry.prevIoTimeMs && totalBytes >= entry.prevIoBytes) {
            double dt = static_cast<double>(nowMs - entry.prevIoTimeMs) / 1000.0;
            if (dt > 0.01) {
              entry.ioBps = static_cast<double>(totalBytes - entry.prevIoBytes) / dt;
            }
          }
          entry.prevIoBytes = totalBytes;
          entry.prevIoTimeMs = nowMs;
        }
      }
      CloseHandle(hProc);
    }
  }

  if (entry.name.empty()) {
    auto snapIt = snapshotMap.find(pid);
    entry.name = (snapIt != snapshotMap.end()) ? snapIt->second : ("PID " + std::to_string(pid));
    entry.lastCheckedMs = nowMs;
  }

  outName = entry.name;
  outPath = entry.path;
  outIoBps = entry.ioBps;
}

#else

namespace {

uint32_t mapLinuxTcpState(uint32_t st) {
  switch (st) {
    case 0x01: return 5;  // ESTABLISHED
    case 0x02: return 3;  // SYN_SENT
    case 0x03: return 4;  // SYN_RCVD
    case 0x04: return 6;  // FIN_WAIT1
    case 0x05: return 7;  // FIN_WAIT2
    case 0x06: return 11; // TIME_WAIT
    case 0x07: return 1;  // CLOSE
    case 0x08: return 8;  // CLOSE_WAIT
    case 0x09: return 10; // LAST_ACK
    case 0x0A: return 2;  // LISTEN
    case 0x0B: return 9;  // CLOSING
    default: return 0;
  }
}

std::unordered_map<uint64_t, uint32_t>& cachedInodePidMap(bool refresh) {
  static std::unordered_map<uint64_t, uint32_t> map;
  if (!refresh) return map;
  map.clear();

  DIR* procDir = opendir("/proc");
  if (!procDir) return map;
  struct dirent* ent = nullptr;
  while ((ent = readdir(procDir)) != nullptr) {
    if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
    char* endp = nullptr;
    unsigned long pidVal = std::strtoul(ent->d_name, &endp, 10);
    if (!endp || *endp != '\0' || pidVal == 0) continue;
    uint32_t pid = static_cast<uint32_t>(pidVal);

    std::string fdPath = std::string("/proc/") + ent->d_name + "/fd";
    DIR* fdDir = opendir(fdPath.c_str());
    if (!fdDir) continue;
    struct dirent* fdEnt = nullptr;
    char linkBuf[128];
    while ((fdEnt = readdir(fdDir)) != nullptr) {
      if (fdEnt->d_name[0] == '.') continue;
      std::string fullFd = fdPath + "/" + fdEnt->d_name;
      ssize_t len = readlink(fullFd.c_str(), linkBuf, sizeof(linkBuf) - 1);
      if (len > 9 && std::strncmp(linkBuf, "socket:[", 8) == 0) {
        linkBuf[len] = '\0';
        uint64_t inode = std::strtoull(linkBuf + 8, nullptr, 10);
        if (inode > 0) map[inode] = pid;
      }
    }
    closedir(fdDir);
  }
  closedir(procDir);
  return map;
}

bool parseProcIpv4(const std::string& hexIpPort, std::string& outIp, uint16_t& outPort) {
  uint32_t addr = 0;
  unsigned int port = 0;
  if (std::sscanf(hexIpPort.c_str(), "%8x:%4x", &addr, &port) != 2) return false;
  outIp = formatIpv4(addr);
  outPort = static_cast<uint16_t>(port);
  return true;
}

bool parseProcIpv6(const std::string& hexIpPort, std::string& outIp, uint16_t& outPort) {
  size_t colon = hexIpPort.find(':');
  if (colon == std::string::npos || colon != 32) return false;
  uint8_t bytes[16] = {};
  for (int i = 0; i < 4; ++i) {
    char word[9] = {};
    std::memcpy(word, hexIpPort.data() + i * 8, 8);
    uint32_t w = static_cast<uint32_t>(std::strtoul(word, nullptr, 16));
    std::memcpy(bytes + i * 4, &w, 4);
  }
  outIp = formatIpv6(bytes);
  outPort = static_cast<uint16_t>(std::strtoul(hexIpPort.c_str() + colon + 1, nullptr, 16));
  return true;
}

} // namespace

void NetMonitor::pollTcp4(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs) {
  (void)nowMs;
  auto& inodeMap = cachedInodePidMap(true);
  std::ifstream in("/proc/net/tcp");
  if (!in.is_open()) return;
  std::string line;
  std::getline(in, line); // header
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string sl, loc, rem, stHex, q, tr, retr, uid, timeout;
    uint64_t inode = 0;
    if (!(iss >> sl >> loc >> rem >> stHex >> q >> tr >> retr >> uid >> timeout >> inode)) continue;
    uint32_t st = mapLinuxTcpState(static_cast<uint32_t>(std::strtoul(stHex.c_str(), nullptr, 16)));
    if (st == 2) {
      ++listeningCount;
      continue;
    }
    std::string localIp, remoteIp;
    uint16_t localPort = 0, remotePort = 0;
    if (!parseProcIpv4(loc, localIp, localPort) || !parseProcIpv4(rem, remoteIp, remotePort)) continue;
    if (remoteIp == "0.0.0.0" && remotePort == 0) continue;

    SocketEntry e;
    e.protocol = "TCP";
    e.ipVersion = 4;
    e.localIp = std::move(localIp);
    e.localPort = localPort;
    e.remoteIp = std::move(remoteIp);
    e.remotePort = remotePort;
    e.state = tcpStateToString(st);
    auto it = inodeMap.find(inode);
    e.pid = (it != inodeMap.end()) ? it->second : 0;
    e.scope = classifyIpString(e.remoteIp);
    e.key = makeKey("TCP", 4, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollTcp6(std::vector<SocketEntry>& out, uint32_t& listeningCount, uint64_t nowMs) {
  (void)nowMs;
  auto& inodeMap = cachedInodePidMap(false);
  std::ifstream in("/proc/net/tcp6");
  if (!in.is_open()) return;
  std::string line;
  std::getline(in, line);
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string sl, loc, rem, stHex, q, tr, retr, uid, timeout;
    uint64_t inode = 0;
    if (!(iss >> sl >> loc >> rem >> stHex >> q >> tr >> retr >> uid >> timeout >> inode)) continue;
    uint32_t st = mapLinuxTcpState(static_cast<uint32_t>(std::strtoul(stHex.c_str(), nullptr, 16)));
    if (st == 2) {
      ++listeningCount;
      continue;
    }
    std::string localIp, remoteIp;
    uint16_t localPort = 0, remotePort = 0;
    if (!parseProcIpv6(loc, localIp, localPort) || !parseProcIpv6(rem, remoteIp, remotePort)) continue;
    if ((remoteIp == "::" || remoteIp == "0.0.0.0") && remotePort == 0) continue;

    SocketEntry e;
    e.protocol = "TCP";
    e.ipVersion = 6;
    e.localIp = std::move(localIp);
    e.localPort = localPort;
    e.remoteIp = std::move(remoteIp);
    e.remotePort = remotePort;
    e.state = tcpStateToString(st);
    auto it = inodeMap.find(inode);
    e.pid = (it != inodeMap.end()) ? it->second : 0;
    e.scope = classifyIpString(normalizeIpForGeo(e.remoteIp));
    e.key = makeKey("TCP", 6, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollUdp4(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  auto& inodeMap = cachedInodePidMap(false);
  std::ifstream in("/proc/net/udp");
  if (!in.is_open()) return;
  std::string line;
  std::getline(in, line);
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string sl, loc, rem, stHex, q, tr, retr, uid, timeout;
    uint64_t inode = 0;
    if (!(iss >> sl >> loc >> rem >> stHex >> q >> tr >> retr >> uid >> timeout >> inode)) continue;
    std::string localIp, remoteIp;
    uint16_t localPort = 0, remotePort = 0;
    if (!parseProcIpv4(loc, localIp, localPort) || !parseProcIpv4(rem, remoteIp, remotePort)) continue;
    if (remoteIp == "0.0.0.0" && remotePort == 0) {
      ++listeningCount;
      continue;
    }

    SocketEntry e;
    e.protocol = "UDP";
    e.ipVersion = 4;
    e.localIp = std::move(localIp);
    e.localPort = localPort;
    e.remoteIp = std::move(remoteIp);
    e.remotePort = remotePort;
    e.state = "UDP";
    auto it = inodeMap.find(inode);
    e.pid = (it != inodeMap.end()) ? it->second : 0;
    e.scope = classifyIpString(e.remoteIp);
    e.key = makeKey("UDP", 4, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

void NetMonitor::pollUdp6(std::vector<SocketEntry>& out, uint32_t& listeningCount) {
  auto& inodeMap = cachedInodePidMap(false);
  std::ifstream in("/proc/net/udp6");
  if (!in.is_open()) return;
  std::string line;
  std::getline(in, line);
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string sl, loc, rem, stHex, q, tr, retr, uid, timeout;
    uint64_t inode = 0;
    if (!(iss >> sl >> loc >> rem >> stHex >> q >> tr >> retr >> uid >> timeout >> inode)) continue;
    std::string localIp, remoteIp;
    uint16_t localPort = 0, remotePort = 0;
    if (!parseProcIpv6(loc, localIp, localPort) || !parseProcIpv6(rem, remoteIp, remotePort)) continue;
    if ((remoteIp == "::" || remoteIp == "0.0.0.0") && remotePort == 0) {
      ++listeningCount;
      continue;
    }

    SocketEntry e;
    e.protocol = "UDP";
    e.ipVersion = 6;
    e.localIp = std::move(localIp);
    e.localPort = localPort;
    e.remoteIp = std::move(remoteIp);
    e.remotePort = remotePort;
    e.state = "UDP";
    auto it = inodeMap.find(inode);
    e.pid = (it != inodeMap.end()) ? it->second : 0;
    e.scope = classifyIpString(normalizeIpForGeo(e.remoteIp));
    e.key = makeKey("UDP", 6, e.localIp, e.localPort, e.remoteIp, e.remotePort, e.pid);
    out.push_back(std::move(e));
  }
}

NicThroughput NetMonitor::pollNicThroughput(uint64_t nowMs) {
  NicThroughput t;
  std::ifstream in("/proc/net/dev");
  if (!in.is_open()) return t;

  uint64_t totalRx = 0;
  uint64_t totalTx = 0;
  std::string line;
  std::getline(in, line);
  std::getline(in, line);
  while (std::getline(in, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string iface = line.substr(0, colon);
    size_t first = iface.find_first_not_of(" \t");
    if (first != std::string::npos) iface = iface.substr(first);
    if (iface == "lo") continue;

    std::istringstream iss(line.substr(colon + 1));
    uint64_t rxBytes = 0, dummy = 0, txBytes = 0;
    if (!(iss >> rxBytes)) continue;
    for (int i = 0; i < 7; ++i) iss >> dummy;
    if (!(iss >> txBytes)) continue;
    totalRx += rxBytes;
    totalTx += txBytes;
    ++t.activeInterfaces;
  }

  t.totalRxBytes = totalRx;
  t.totalTxBytes = totalTx;

  if (prevNicSampleMs_ > 0 && nowMs > prevNicSampleMs_) {
    const double dt = static_cast<double>(nowMs - prevNicSampleMs_) / 1000.0;
    if (dt > 0.0) {
      if (totalRx >= prevNicRxBytes_) {
        t.rxBytesPerSec = static_cast<double>(totalRx - prevNicRxBytes_) / dt;
      }
      if (totalTx >= prevNicTxBytes_) {
        t.txBytesPerSec = static_cast<double>(totalTx - prevNicTxBytes_) / dt;
      }
    }
  }
  prevNicSampleMs_ = nowMs;
  prevNicRxBytes_ = totalRx;
  prevNicTxBytes_ = totalTx;
  return t;
}

std::unordered_map<uint32_t, std::string> NetMonitor::buildProcessSnapshotMap() {
  std::unordered_map<uint32_t, std::string> map;
  DIR* procDir = opendir("/proc");
  if (!procDir) return map;
  struct dirent* ent = nullptr;
  while ((ent = readdir(procDir)) != nullptr) {
    if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
    char* endp = nullptr;
    unsigned long pidVal = std::strtoul(ent->d_name, &endp, 10);
    if (!endp || *endp != '\0' || pidVal == 0) continue;
    std::ifstream comm(std::string("/proc/") + ent->d_name + "/comm");
    std::string name;
    if (std::getline(comm, name) && !name.empty()) {
      map[static_cast<uint32_t>(pidVal)] = std::move(name);
    }
  }
  closedir(procDir);
  return map;
}

void NetMonitor::resolveProcessInfo(uint32_t pid,
                                    uint64_t nowMs,
                                    const std::unordered_map<uint32_t, std::string>& snapshotMap,
                                    std::string& outName,
                                    std::string& outPath,
                                    double& outIoBps) {
  if (pid == 0) {
    outName = "Kernel / Socket";
    outPath.clear();
    outIoBps = 0.0;
    return;
  }

  auto& entry = procCache_[pid];
  const bool needRefresh = entry.name.empty() || (nowMs - entry.lastCheckedMs) >= 5000;
  if (needRefresh) {
    entry.lastCheckedMs = nowMs;
    char exeBuf[1024] = {};
    std::string exeLink = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t len = readlink(exeLink.c_str(), exeBuf, sizeof(exeBuf) - 1);
    if (len > 0) {
      exeBuf[len] = '\0';
      entry.path = exeBuf;
      entry.name = basenameFromPath(entry.path);
    }
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    std::string commName;
    if (std::getline(comm, commName) && !commName.empty()) {
      entry.name = std::move(commName);
    }
    std::ifstream ioFile("/proc/" + std::to_string(pid) + "/io");
    if (ioFile.is_open()) {
      std::string k;
      uint64_t v = 0, rBytes = 0, wBytes = 0;
      while (ioFile >> k >> v) {
        if (k == "read_bytes:") rBytes = v;
        else if (k == "write_bytes:") wBytes = v;
      }
      uint64_t totalIo = rBytes + wBytes;
      if (entry.prevIoTimeMs > 0 && nowMs > entry.prevIoTimeMs && totalIo >= entry.prevIoBytes) {
        double dt = static_cast<double>(nowMs - entry.prevIoTimeMs) / 1000.0;
        if (dt > 0.0) entry.ioBps = static_cast<double>(totalIo - entry.prevIoBytes) / dt;
      }
      entry.prevIoBytes = totalIo;
      entry.prevIoTimeMs = nowMs;
    }
  }

  if (entry.name.empty()) {
    auto snapIt = snapshotMap.find(pid);
    entry.name = (snapIt != snapshotMap.end()) ? snapIt->second : ("PID " + std::to_string(pid));
  }

  outName = entry.name;
  outPath = entry.path;
  outIoBps = entry.ioBps;
}

#endif

TelemetrySnapshot NetMonitor::poll(uint64_t nowMs) {
  const auto t0 = std::chrono::steady_clock::now();

  std::vector<SocketEntry> raw;
  raw.reserve(256);
  uint32_t listeningCount = 0;

  pollTcp4(raw, listeningCount, nowMs);
  pollTcp6(raw, listeningCount, nowMs);
  pollUdp4(raw, listeningCount);
  pollUdp6(raw, listeningCount);

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
  snap.isElevated = elevated_;
  snap.bandwidthMode = elevated_ ? "exact_estats" : "process_io";
  snap.nic = pollNicThroughput(nowMs);

  std::unordered_map<uint32_t, ProcessBandwidth> procAgg;

  for (auto& s : raw) {
    const uint64_t estatsIn = s.firstSeenMs;
    const uint64_t estatsOut = s.lastSeenMs;
    double ioBps = 0.0;
    resolveProcessInfo(s.pid, nowMs, snapMap, s.processName, s.processPath, ioBps);

    auto prevIt = activeTracked_.find(s.key);
    if (prevIt != activeTracked_.end()) {
      s.firstSeenMs = prevIt->second.entry.firstSeenMs;
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

    auto& pb = procAgg[s.pid];
    pb.pid = s.pid;
    pb.processName = s.processName;
    pb.processPath = s.processPath;
    ++pb.connections;
    if (s.scope == IpScope::Public) ++pb.publicConnections;
    pb.rxBps += s.rxBps;
    pb.txBps += s.txBps;
    if (elevated_) {
      pb.activityBps += (s.rxBps + s.txBps);
    } else {
      pb.activityBps = ioBps;
    }

    TrackedSocket ts;
    ts.entry = s;
    if (elevated_ && s.state == "ESTABLISHED") {
      ts.estatsEnabled = true;
      ts.prevBytesIn = estatsIn;
      ts.prevBytesOut = estatsOut;
      ts.prevStatsMs = nowMs;
    }
    nextActive[s.key] = std::move(ts);
    snap.connections.push_back(std::move(s));
  }

  snap.processStats.reserve(procAgg.size());
  for (auto& [pid, pb] : procAgg) {
    (void)pid;
    snap.processStats.push_back(std::move(pb));
  }
  std::sort(snap.processStats.begin(), snap.processStats.end(),
            [](const ProcessBandwidth& a, const ProcessBandwidth& b) {
              if (a.activityBps != b.activityBps) return a.activityBps > b.activityBps;
              return a.connections > b.connections;
            });

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
