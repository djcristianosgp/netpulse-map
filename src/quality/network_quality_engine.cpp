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
#include <icmpapi.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <fstream>
#endif

#include "network_quality_engine.hpp"
#include "../models.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

bool isNumericIp(const std::string& host) {
  struct in_addr in4{};
  struct in6_addr in6{};
  return inet_pton(AF_INET, host.c_str(), &in4) == 1 ||
         inet_pton(AF_INET6, host.c_str(), &in6) == 1;
}

bool isValidTargetHost(const std::string& host) {
  if (host.empty() || host.size() > 253) return false;
  for (unsigned char c : host) {
    if (std::isalnum(c) || c == '.' || c == '-' || c == ':') continue;
    return false;
  }
  return true;
}

std::string sanitizeSlug(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  for (unsigned char c : raw) {
    if (std::isalnum(c)) out.push_back(static_cast<char>(std::tolower(c)));
    else if (c == '.' || c == '-' || c == '_' || c == ':') out.push_back('_');
  }
  if (out.empty()) out = "target";
  if (out.size() > 40) out.resize(40);
  return out;
}

std::string fmtNum(double v, int decimals = 1) {
  char buf[32];
  if (decimals == 2) std::snprintf(buf, sizeof(buf), "%.2f", v);
  else std::snprintf(buf, sizeof(buf), "%.1f", v);
  return std::string(buf);
}

void appendJsonStrArr(std::string& out, const std::vector<std::string>& arr) {
  out.push_back('[');
  for (size_t i = 0; i < arr.size(); ++i) {
    if (i > 0) out.push_back(',');
    appendJsonEscaped(out, arr[i]);
  }
  out.push_back(']');
}

double interpPercentile(std::vector<double>& sorted, double pct) {
  if (sorted.empty()) return 0.0;
  double pos = (pct / 100.0) * static_cast<double>(sorted.size() - 1);
  size_t lo = static_cast<size_t>(pos);
  size_t hi = std::min(sorted.size() - 1, lo + 1);
  double frac = pos - static_cast<double>(lo);
  return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

struct LowLevelProbeResult {
  bool ok = false;
  double rttMs = 0.0;
  double dnsMs = 0.0;
  std::string resolvedIp;
  std::string methodUsed;
  std::string error;
};

bool resolveHostTimed(const std::string& host,
                      uint16_t port,
                      int sockType,
                      int proto,
                      std::vector<sockaddr_storage>& outAddrs,
                      std::string& outFirstIp,
                      double& outDnsMs,
                      std::string& outErr) {
  outAddrs.clear();
  outDnsMs = 0.0;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = sockType;
  hints.ai_protocol = proto;
  if (isNumericIp(host)) {
    hints.ai_flags = AI_NUMERICHOST;
  }

  const std::string portStr = port > 0 ? std::to_string(port) : std::string("0");
  addrinfo* resList = nullptr;
  const auto t0 = std::chrono::steady_clock::now();
  int gai = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &resList);
  const auto t1 = std::chrono::steady_clock::now();
  if (!isNumericIp(host)) {
    outDnsMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
  }

  if (gai != 0 || !resList) {
    outErr = "DNS error (" + std::to_string(gai) + ")";
    return false;
  }

  for (addrinfo* ai = resList; ai != nullptr; ai = ai->ai_next) {
    if (ai->ai_addrlen > sizeof(sockaddr_storage)) continue;
    sockaddr_storage ss{};
    std::memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
    outAddrs.push_back(ss);
    if (outFirstIp.empty()) {
      char ipBuf[INET6_ADDRSTRLEN] = {};
      if (ai->ai_family == AF_INET) {
        auto* sa = reinterpret_cast<const sockaddr_in*>(ai->ai_addr);
        inet_ntop(AF_INET, &sa->sin_addr, ipBuf, sizeof(ipBuf));
      } else if (ai->ai_family == AF_INET6) {
        auto* sa6 = reinterpret_cast<const sockaddr_in6*>(ai->ai_addr);
        inet_ntop(AF_INET6, &sa6->sin6_addr, ipBuf, sizeof(ipBuf));
      }
      outFirstIp = ipBuf;
    }
  }
  freeaddrinfo(resList);
  if (outAddrs.empty()) {
    outErr = "No resolved address";
    return false;
  }
  return true;
}

LowLevelProbeResult probeTcpConnect(const std::string& host, uint16_t port, int timeoutMs = 1500) {
  LowLevelProbeResult out;
  out.methodUsed = "tcp";
  const uint16_t effPort = (port > 0) ? port : 443;

  std::vector<sockaddr_storage> addrs;
  if (!resolveHostTimed(host, effPort, SOCK_STREAM, IPPROTO_TCP, addrs, out.resolvedIp, out.dnsMs, out.error)) {
    return out;
  }

  for (const auto& ss : addrs) {
    const int family = static_cast<int>(ss.ss_family);
    const socklen_t addrLen = (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
#ifdef _WIN32
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) continue;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
#else
    int s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) continue;
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    const auto t0 = std::chrono::steady_clock::now();
    int rc = connect(s, reinterpret_cast<const sockaddr*>(&ss), static_cast<int>(addrLen));
    bool connected = false;
    std::string errMsg;

    if (rc == 0) {
      connected = true;
    } else {
#ifdef _WIN32
      int sockErr = WSAGetLastError();
      bool inProg = (sockErr == WSAEWOULDBLOCK || sockErr == WSAEINPROGRESS);
#else
      int sockErr = errno;
      bool inProg = (sockErr == EINPROGRESS || sockErr == EWOULDBLOCK);
#endif
      if (inProg) {
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(s, &wset);
        FD_SET(s, &eset);
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
#ifdef _WIN32
        int sel = select(0, nullptr, &wset, &eset, &tv);
#else
        int sel = select(s + 1, nullptr, &wset, &eset, &tv);
#endif
        if (sel > 0) {
          int soErr = 0;
          socklen_t len = sizeof(soErr);
          if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len) == 0 && soErr == 0) {
            connected = true;
          } else {
            errMsg = "TCP error (" + std::to_string(soErr) + ")";
          }
        } else {
          errMsg = "Timeout >" + std::to_string(timeoutMs) + " ms";
        }
      } else {
        errMsg = "Connect error (" + std::to_string(sockErr) + ")";
      }
    }

    const auto t1 = std::chrono::steady_clock::now();
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif

    if (connected) {
      out.ok = true;
      out.rttMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
      out.error.clear();
      return out;
    }
    out.error = errMsg;
  }
  return out;
}

LowLevelProbeResult probeIcmpOrFallback(const std::string& host, uint16_t fallbackPort, int timeoutMs = 1200) {
  LowLevelProbeResult out;
  out.methodUsed = "icmp";

  std::vector<sockaddr_storage> addrs;
  if (!resolveHostTimed(host, 0, SOCK_DGRAM, IPPROTO_UDP, addrs, out.resolvedIp, out.dnsMs, out.error)) {
    return out;
  }

#ifdef _WIN32
  for (const auto& ss : addrs) {
    if (ss.ss_family != AF_INET) continue;
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&ss);
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
      out.error = "IcmpCreateFile failed";
      break;
    }

    char payload[24] = "NetPulseQualityProbe02";
    uint8_t replyBuf[sizeof(ICMP_ECHO_REPLY) + 64] = {};
    const auto t0 = std::chrono::steady_clock::now();
    DWORD cnt = IcmpSendEcho(hIcmp,
                             sin->sin_addr.S_un.S_addr,
                             payload,
                             static_cast<WORD>(sizeof(payload)),
                             nullptr,
                             replyBuf,
                             static_cast<DWORD>(sizeof(replyBuf)),
                             static_cast<DWORD>(timeoutMs));
    const auto t1 = std::chrono::steady_clock::now();
    IcmpCloseHandle(hIcmp);

    if (cnt > 0) {
      const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuf);
      if (reply->Status == IP_SUCCESS) {
        const double elapsed = std::chrono::duration<double, std::milli>(t1 - t0).count();
        out.ok = true;
        out.rttMs = (reply->RoundTripTime > 0)
                        ? std::max(elapsed, static_cast<double>(reply->RoundTripTime))
                        : std::max(0.1, elapsed);
        out.error.clear();
        return out;
      }
      out.error = "ICMP status " + std::to_string(reply->Status);
    } else {
      out.error = "ICMP timeout";
    }
  }
  if (!out.ok && fallbackPort > 0) {
    auto tcpRes = probeTcpConnect(out.resolvedIp.empty() ? host : out.resolvedIp, fallbackPort, timeoutMs);
    if (tcpRes.ok) {
      tcpRes.dnsMs = out.dnsMs;
      return tcpRes;
    }
  }
  return out;
#else
  // Linux: try unprivileged ICMP datagram socket first, fallback to TCP if disallowed
  static uint16_t seqCounter = 1;
  bool icmpPermitted = false;
  for (const auto& ss : addrs) {
    if (ss.ss_family != AF_INET) continue;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) {
      out.error = "ICMP unavailable (" + std::to_string(errno) + ")";
      break;
    }
    icmpPermitted = true;

    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t pkt[32] = {};
    uint16_t seq = htons(seqCounter++);
    pkt[0] = 8; // Echo request
    pkt[1] = 0;
    std::memcpy(pkt + 6, &seq, 2);
    std::memcpy(pkt + 8, "NetPulseQuality", 15);

    sockaddr_in dst = *reinterpret_cast<const sockaddr_in*>(&ss);
    const auto t0 = std::chrono::steady_clock::now();
    ssize_t sent = sendto(fd, pkt, sizeof(pkt), 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (sent > 0) {
      uint8_t rxBuf[128] = {};
      ssize_t recvd = recvfrom(fd, rxBuf, sizeof(rxBuf), 0, nullptr, nullptr);
      const auto t1 = std::chrono::steady_clock::now();
      ::close(fd);
      if (recvd >= 8) {
        out.ok = true;
        out.methodUsed = "icmp_dgram";
        out.rttMs = std::max(0.1, std::chrono::duration<double, std::milli>(t1 - t0).count());
        out.error.clear();
        return out;
      }
      out.error = "ICMP timeout";
    } else {
      out.error = "ICMP send error";
      ::close(fd);
    }
  }

  if (!icmpPermitted || (!out.ok && fallbackPort > 0)) {
    auto tcpRes = probeTcpConnect(out.resolvedIp.empty() ? host : out.resolvedIp,
                                  fallbackPort > 0 ? fallbackPort : 443,
                                  timeoutMs);
    if (tcpRes.ok || !icmpPermitted) {
      tcpRes.dnsMs = out.dnsMs;
      return tcpRes;
    }
  }
  return out;
#endif
}

LowLevelProbeResult probeDnsServerUdp(const std::string& serverHost, uint16_t port, int timeoutMs = 1200) {
  LowLevelProbeResult out;
  out.methodUsed = "dns_udp";
  const uint16_t dnsPort = (port > 0) ? port : 53;

  std::vector<sockaddr_storage> addrs;
  if (!resolveHostTimed(serverHost, dnsPort, SOCK_DGRAM, IPPROTO_UDP, addrs, out.resolvedIp, out.dnsMs, out.error)) {
    return out;
  }

  static std::atomic<uint16_t> txGen{0x4200};
  const uint16_t txId = txGen.fetch_add(1);
  const auto queryPkt = buildDnsQueryPacket(txId, "one.one.one.one");

  for (const auto& ss : addrs) {
    const int family = static_cast<int>(ss.ss_family);
    const socklen_t addrLen = (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
#ifdef _WIN32
    SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) continue;
    DWORD to = static_cast<DWORD>(timeoutMs);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
#else
    int s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) continue;
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    const auto t0 = std::chrono::steady_clock::now();
    int sent = sendto(s,
                      reinterpret_cast<const char*>(queryPkt.data()),
                      static_cast<int>(queryPkt.size()),
                      0,
                      reinterpret_cast<const sockaddr*>(&ss),
                      static_cast<int>(addrLen));
    if (sent > 0) {
      uint8_t rxBuf[512] = {};
      int recvd = recvfrom(s, reinterpret_cast<char*>(rxBuf), sizeof(rxBuf), 0, nullptr, nullptr);
      const auto t1 = std::chrono::steady_clock::now();
#ifdef _WIN32
      closesocket(s);
#else
      ::close(s);
#endif
      if (recvd >= 12) {
        uint8_t rcode = 0;
        if (parseDnsResponseHeader(rxBuf, static_cast<size_t>(recvd), txId, rcode)) {
          double elapsed = std::max(0.1, std::chrono::duration<double, std::milli>(t1 - t0).count());
          out.ok = (rcode == 0 || rcode == 3);
          out.dnsMs = elapsed;
          out.rttMs = elapsed;
          if (!out.ok) out.error = "DNS RCODE " + std::to_string(rcode);
          else out.error.clear();
          return out;
        }
        out.error = "Malformed DNS response";
      } else {
        out.error = "DNS timeout >" + std::to_string(timeoutMs) + " ms";
      }
    } else {
#ifdef _WIN32
      closesocket(s);
#else
      ::close(s);
#endif
      out.error = "DNS UDP send failed";
    }
  }
  return out;
}

} // namespace

std::vector<uint8_t> buildDnsQueryPacket(uint16_t txId, const std::string& domain) {
  std::vector<uint8_t> pkt;
  pkt.reserve(64);
  // Header: ID, Flags (0x0100 = standard query RD=1), QDCOUNT=1, AN=0, NS=0, AR=0
  pkt.push_back(static_cast<uint8_t>((txId >> 8) & 0xFF));
  pkt.push_back(static_cast<uint8_t>(txId & 0xFF));
  pkt.push_back(0x01);
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x01);
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x00);

  size_t pos = 0;
  while (pos < domain.size()) {
    size_t dot = domain.find('.', pos);
    if (dot == std::string::npos) dot = domain.size();
    size_t labelLen = dot - pos;
    if (labelLen > 63) labelLen = 63;
    if (labelLen > 0) {
      pkt.push_back(static_cast<uint8_t>(labelLen));
      for (size_t i = 0; i < labelLen; ++i) {
        pkt.push_back(static_cast<uint8_t>(domain[pos + i]));
      }
    }
    pos = dot + 1;
  }
  pkt.push_back(0x00); // Root terminator
  pkt.push_back(0x00);
  pkt.push_back(0x01); // QTYPE = A (1)
  pkt.push_back(0x00);
  pkt.push_back(0x01); // QCLASS = IN (1)
  return pkt;
}

bool parseDnsResponseHeader(const uint8_t* buf, size_t len, uint16_t expectedTxId, uint8_t& outRcode) {
  if (!buf || len < 12) return false;
  uint16_t txId = static_cast<uint16_t>((static_cast<uint16_t>(buf[0]) << 8) | buf[1]);
  if (txId != expectedTxId) return false;
  uint16_t flags = static_cast<uint16_t>((static_cast<uint16_t>(buf[2]) << 8) | buf[3]);
  if ((flags & 0x8000U) == 0) return false; // Must be response (QR=1)
  outRcode = static_cast<uint8_t>(flags & 0x000FU);
  return true;
}

DiscoveredInfra discoverNetworkInfra() {
  DiscoveredInfra out;
  std::unordered_set<std::string> seenGw;
  std::unordered_set<std::string> seenDns;

#ifdef _WIN32
  ULONG bufLen = 16384;
  std::vector<uint8_t> buf(bufLen);
  const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
                      GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;

  ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &bufLen);
  if (rc == ERROR_BUFFER_OVERFLOW) {
    buf.resize(bufLen);
    rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                              reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &bufLen);
  }
  if (rc == NO_ERROR) {
    for (auto* ad = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()); ad != nullptr; ad = ad->Next) {
      if (ad->OperStatus != IfOperStatusUp) continue;
      if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

      for (auto* gw = ad->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
        if (!gw->Address.lpSockaddr) continue;
        char ipBuf[INET6_ADDRSTRLEN] = {};
        if (gw->Address.lpSockaddr->sa_family == AF_INET) {
          auto* sin = reinterpret_cast<const sockaddr_in*>(gw->Address.lpSockaddr);
          inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
        }
        std::string ip = ipBuf;
        if (!ip.empty() && ip != "0.0.0.0" && seenGw.insert(ip).second) {
          out.gateways.push_back(std::move(ip));
        }
      }

      for (auto* dns = ad->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
        if (!dns->Address.lpSockaddr) continue;
        char ipBuf[INET6_ADDRSTRLEN] = {};
        if (dns->Address.lpSockaddr->sa_family == AF_INET) {
          auto* sin = reinterpret_cast<const sockaddr_in*>(dns->Address.lpSockaddr);
          inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
        }
        std::string ip = ipBuf;
        if (!ip.empty() && ip != "0.0.0.0" && ip.rfind("127.", 0) != 0 && seenDns.insert(ip).second) {
          out.dnsServers.push_back(std::move(ip));
        }
      }
    }
  }
#else
  // Linux default gateway via /proc/net/route
  std::ifstream routeIn("/proc/net/route");
  if (routeIn.is_open()) {
    std::string line;
    std::getline(routeIn, line); // header
    while (std::getline(routeIn, line)) {
      std::istringstream ss(line);
      std::string iface, destHex, gwHex;
      if (!(ss >> iface >> destHex >> gwHex)) continue;
      if (destHex == "00000000" && gwHex.size() == 8 && gwHex != "00000000") {
        uint32_t rawGw = static_cast<uint32_t>(std::strtoul(gwHex.c_str(), nullptr, 16));
        struct in_addr a{};
        a.s_addr = rawGw;
        char ipBuf[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &a, ipBuf, sizeof(ipBuf))) {
          std::string ip = ipBuf;
          if (seenGw.insert(ip).second) out.gateways.push_back(std::move(ip));
        }
      }
    }
  }

  std::ifstream resIn("/etc/resolv.conf");
  if (resIn.is_open()) {
    std::string line;
    while (std::getline(resIn, line)) {
      std::istringstream ss(line);
      std::string kw, ip;
      if ((ss >> kw >> ip) && kw == "nameserver") {
        if (!ip.empty() && ip.rfind("127.", 0) != 0 && seenDns.insert(ip).second) {
          out.dnsServers.push_back(std::move(ip));
        }
      }
    }
  }
#endif
  return out;
}

QualityMetricsSummary computeQualityMetrics(const std::vector<QualitySampleRecord>& samples) {
  QualityMetricsSummary m;
  m.sampleCount = samples.size();
  if (samples.empty()) return m;

  std::vector<double> rtts;
  rtts.reserve(samples.size());
  double rttSum = 0.0;
  double dnsSum = 0.0;
  size_t dnsCount = 0;
  double jitterSum = 0.0;
  size_t jitterPairs = 0;

  bool hasPrevOk = false;
  double prevOkRtt = 0.0;
  bool hasPrevState = false;
  bool prevState = true;

  const size_t splitIdx = samples.size() / 2;
  double olderRttSum = 0.0, recentRttSum = 0.0;
  size_t olderOk = 0, recentOk = 0;
  size_t olderTotal = 0, recentTotal = 0;

  for (size_t i = 0; i < samples.size(); ++i) {
    const auto& s = samples[i];
    if (hasPrevState && prevState != s.ok) {
      m.flaps++;
    }
    prevState = s.ok;
    hasPrevState = true;

    if (s.dnsMs > 0.0) {
      dnsSum += s.dnsMs;
      dnsCount++;
      m.currentDnsMs = s.dnsMs;
    }

    if (i < splitIdx) olderTotal++;
    else recentTotal++;

    if (s.ok) {
      m.okCount++;
      m.currentLatencyMs = s.rttMs;
      rtts.push_back(s.rttMs);
      rttSum += s.rttMs;

      if (i < splitIdx) {
        olderOk++;
        olderRttSum += s.rttMs;
      } else {
        recentOk++;
        recentRttSum += s.rttMs;
      }

      if (hasPrevOk) {
        jitterSum += std::abs(s.rttMs - prevOkRtt);
        jitterPairs++;
      }
      prevOkRtt = s.rttMs;
      hasPrevOk = true;
    } else {
      hasPrevOk = false;
    }
  }

  m.availabilityPct = 100.0 * static_cast<double>(m.okCount) / static_cast<double>(m.sampleCount);
  m.packetLossPct = 100.0 - m.availabilityPct;
  m.avgDnsMs = dnsCount > 0 ? (dnsSum / static_cast<double>(dnsCount)) : 0.0;
  m.jitterMs = jitterPairs > 0 ? (jitterSum / static_cast<double>(jitterPairs)) : 0.0;

  if (!rtts.empty()) {
    std::sort(rtts.begin(), rtts.end());
    m.minLatencyMs = rtts.front();
    m.maxLatencyMs = rtts.back();
    m.avgLatencyMs = rttSum / static_cast<double>(rtts.size());
    m.p50Ms = interpPercentile(rtts, 50.0);
    m.p90Ms = interpPercentile(rtts, 90.0);
    m.p95Ms = interpPercentile(rtts, 95.0);
    m.p99Ms = interpPercentile(rtts, 99.0);
  }

  if (olderOk > 0) m.olderHalfAvgMs = olderRttSum / static_cast<double>(olderOk);
  if (recentOk > 0) m.recentHalfAvgMs = recentRttSum / static_cast<double>(recentOk);
  if (olderTotal > 0) m.olderHalfAvailPct = 100.0 * static_cast<double>(olderOk) / static_cast<double>(olderTotal);
  if (recentTotal > 0) m.recentHalfAvailPct = 100.0 * static_cast<double>(recentOk) / static_cast<double>(recentTotal);

  return m;
}

QualityDiagnosisReport diagnoseNetworkQuality(const std::vector<QualityTargetSnapshot>& targets) {
  QualityDiagnosisReport rep;
  rep.evaluatedAtMs = nowEpochMs();

  std::vector<const QualityTargetSnapshot*> gateways;
  std::vector<const QualityTargetSnapshot*> dnsNodes;
  std::vector<const QualityTargetSnapshot*> externals;

  for (const auto& t : targets) {
    if (!t.target.enabled || t.metrics.sampleCount == 0) continue;
    if (t.target.category == "gateway") gateways.push_back(&t);
    else if (t.target.category == "isp_dns" || t.target.category == "public_dns" || t.target.probeMode == "dns") dnsNodes.push_back(&t);
    else externals.push_back(&t);
  }

  if (gateways.empty() && dnsNodes.empty() && externals.empty()) {
    rep.overallHealth = "unknown";
    return rep;
  }

  bool anyUpstreamHealthy = false;
  for (const auto* d : dnsNodes) {
    if (d->metrics.availabilityPct >= 80.0) anyUpstreamHealthy = true;
  }
  for (const auto* e : externals) {
    if (e->metrics.availabilityPct >= 80.0) anyUpstreamHealthy = true;
  }

  bool anyGatewayDown = false;
  bool anyGatewayHealthy = false;
  for (const auto* gw : gateways) {
    if (gw->metrics.packetLossPct >= 50.0 || gw->status == "down") {
      if (anyUpstreamHealthy) {
        anyGatewayHealthy = true;
        DiagnosisFinding f;
        f.code = "gateway_icmp_filtered";
        f.severity = "info";
        f.title = "Gateway local não responde ICMP/TCP, mas saída externa está operacional";
        f.targetId = gw->target.id;
        f.targetName = gw->target.name;
        f.observedFacts = {
            "Sondagens diretas ao gateway " + gw->target.host + " falharam (" + fmtNum(gw->metrics.packetLossPct) + "%)",
            "Destinos externos / DNS respondem normalmente no mesmo período.",
        };
        f.hypotheses = {
            "Hipótese: firewall ou política do roteador descartando pacotes ICMP/TCP direcionados ao próprio IP do gateway (enlace ativo).",
        };
        f.suggestedChecks = {
            "Opcional: pausar ICMP para este gateway ou configurar uma porta de gerência aberta caso deseje medir o RTT local.",
        };
        rep.findings.push_back(std::move(f));
      } else {
        anyGatewayDown = true;
        DiagnosisFinding f;
        f.code = "gateway_unreachable";
        f.severity = "critical";
        f.title = "Gateway local indisponível ou com perda severa";
        f.targetId = gw->target.id;
        f.targetName = gw->target.name;
        f.observedFacts = {
            "Alvo " + gw->target.name + " (" + gw->target.host + "): " + fmtNum(gw->metrics.packetLossPct) + "% de perda em " +
                std::to_string(gw->metrics.sampleCount) + " sondagens",
            "Disponibilidade medida: " + fmtNum(gw->metrics.availabilityPct) + "%" +
                (gw->lastError.empty() ? "" : " · último erro: " + gw->lastError),
        };
        f.hypotheses = {
            "Hipótese: queda do enlace local (cabo Ethernet/Wi-Fi), reinicialização do roteador ou indisponibilidade do gateway.",
        };
        f.suggestedChecks = {
            "Verificar interface ativa, cabo/Wi-Fi e energia do roteador local.",
            "Testar conectividade com outro dispositivo na mesma sub-rede LAN.",
        };
        rep.findings.push_back(std::move(f));
      }
    } else if (gw->metrics.availabilityPct >= 95.0) {
      anyGatewayHealthy = true;
    }
  }

  bool allDnsFailing = !dnsNodes.empty();
  int failingDnsCount = 0;
  for (const auto* d : dnsNodes) {
    if (d->metrics.packetLossPct >= 25.0 || d->status == "down") {
      failingDnsCount++;
    } else {
      allDnsFailing = false;
    }
  }
  bool anyExternalIpOk = false;
  for (const auto* e : externals) {
    if (isNumericIp(e->target.host) && e->metrics.availabilityPct >= 90.0) anyExternalIpOk = true;
  }
  for (const auto* d : dnsNodes) {
    if (d->metrics.packetLossPct >= 25.0 || d->status == "down") {
      DiagnosisFinding f;
      f.code = "dns_unreachable";
      f.severity = allDnsFailing ? "critical" : "warn";
      f.title = "Falha ou degradação na resolução DNS (" + d->target.name + ")";
      f.targetId = d->target.id;
      f.targetName = d->target.name;
      f.observedFacts = {
          "Servidor DNS " + d->target.host + ": " + fmtNum(d->metrics.packetLossPct) + "% de falhas em " +
              std::to_string(d->metrics.sampleCount) + " consultas",
          anyGatewayHealthy ? "Gateway local responde normalmente durante o mesmo período." : "Estado do gateway local também instável ou ausente.",
      };
      if (anyExternalIpOk) {
        f.observedFacts.push_back("Tráfego direto por IP externo responde sem perda relevante.");
      }
      f.hypotheses = {
          "Hipótese: instabilidade no servidor DNS configurado ou bloqueio/perda em UDP porta 53.",
      };
      f.suggestedChecks = {
          "Comparar o DNS do provedor com resolvedores públicos (1.1.1.1 / 8.8.8.8).",
          "Inspecionar regras de firewall local ou do roteador para UDP/53.",
      };
      rep.findings.push_back(std::move(f));
    }
  }

  // External unreachable while gateway is healthy
  for (const auto* ext : externals) {
    if ((ext->metrics.packetLossPct >= 50.0 || ext->status == "down") && anyGatewayHealthy) {
      DiagnosisFinding f;
      f.code = "external_unreachable";
      f.severity = "critical";
      f.title = "Destino externo inacessível (" + ext->target.name + ")";
      f.targetId = ext->target.id;
      f.targetName = ext->target.name;
      f.observedFacts = {
          "Alvo externo " + ext->target.host + ": " + fmtNum(ext->metrics.packetLossPct) + "% de falha (" +
              std::to_string(ext->metrics.okCount) + "/" + std::to_string(ext->metrics.sampleCount) + " OK)",
          "Gateway local permanece acessível.",
      };
      f.hypotheses = {
          "Hipótese: falha no link WAN do provedor, rota upstream ou indisponibilidade do próprio endpoint de destino.",
      };
      f.suggestedChecks = {
          "Executar Traceroute para identificar o salto onde o tráfego é interrompido.",
      };
      rep.findings.push_back(std::move(f));
    }
  }

  // Evaluate latency, jitter/oscillation, packet loss, flapping & progressive degradation across active targets
  for (const auto& t : targets) {
    if (!t.target.enabled || t.metrics.sampleCount < 4) continue;
    const auto& m = t.metrics;

    // Packet loss (when not already flagged down)
    if (m.packetLossPct > 2.0 && m.packetLossPct < 50.0) {
      DiagnosisFinding f;
      f.code = "packet_loss";
      f.severity = (m.packetLossPct >= 10.0) ? "critical" : "warn";
      f.title = "Perda de pacotes detectada em " + t.target.name;
      f.targetId = t.target.id;
      f.targetName = t.target.name;
      f.observedFacts = {
          "Perda observada: " + fmtNum(m.packetLossPct) + "% (" +
              std::to_string(m.sampleCount - m.okCount) + " falhas em " + std::to_string(m.sampleCount) + " sondagens)",
          "P50: " + fmtNum(m.p50Ms) + " ms · P95: " + fmtNum(m.p95Ms) + " ms",
      };
      f.hypotheses = {
          t.target.category == "gateway"
              ? "Hipótese: interferência Wi-Fi, cabo defeituoso ou perda na rede local."
              : "Hipótese: congestionamento de enlace ou descarte de pacotes no caminho até o destino.",
      };
      rep.findings.push_back(std::move(f));
    }

    // High latency
    const double latWarnThresh = (t.target.category == "gateway") ? 15.0 : 120.0;
    const double latCritThresh = (t.target.category == "gateway") ? 45.0 : 250.0;
    if (m.okCount >= 3 && (m.p95Ms >= latWarnThresh || m.avgLatencyMs >= latWarnThresh)) {
      DiagnosisFinding f;
      f.code = "high_latency";
      f.severity = (m.p95Ms >= latCritThresh) ? "critical" : "warn";
      f.title = "Latência elevada em " + t.target.name;
      f.targetId = t.target.id;
      f.targetName = t.target.name;
      f.observedFacts = {
          "Média: " + fmtNum(m.avgLatencyMs) + " ms · P50: " + fmtNum(m.p50Ms) +
              " ms · P95: " + fmtNum(m.p95Ms) + " ms · Máx: " + fmtNum(m.maxLatencyMs) + " ms",
      };
      f.hypotheses = {
          t.target.category == "gateway"
              ? "Hipótese: saturação no Wi-Fi local ou sobrecarga de CPU no roteador."
              : "Hipótese: rota longa/subótima, congestionamento de banda (bufferbloat) ou distância geográfica do destino.",
      };
      rep.findings.push_back(std::move(f));
    }

    // Latency oscillation (jitter / spread)
    const double spread = m.p95Ms - m.p50Ms;
    const double jitThresh = (t.target.category == "gateway") ? 8.0 : 25.0;
    if (m.okCount >= 5 && (m.jitterMs >= jitThresh || (spread >= jitThresh * 2.0 && spread > m.p50Ms))) {
      DiagnosisFinding f;
      f.code = "latency_oscillation";
      f.severity = (m.jitterMs >= jitThresh * 2.5) ? "critical" : "warn";
      f.title = "Oscilação de latência (Jitter alto) em " + t.target.name;
      f.targetId = t.target.id;
      f.targetName = t.target.name;
      f.observedFacts = {
          "Jitter médio medido: " + fmtNum(m.jitterMs) + " ms · Dispersão P95-P50: " + fmtNum(spread) + " ms",
      };
      f.hypotheses = {
          "Hipótese: bufferbloat sob upload/download simultâneo, disputa de canal Wi-Fi ou balanceamento instável de rota.",
      };
      rep.findings.push_back(std::move(f));
    }

    // Frequent interruptions (flapping)
    if (m.sampleCount >= 6 && m.flaps >= 3) {
      DiagnosisFinding f;
      f.code = "frequent_interruptions";
      f.severity = (m.flaps >= 6) ? "critical" : "warn";
      f.title = "Interrupções intermitentes frequentes em " + t.target.name;
      f.targetId = t.target.id;
      f.targetName = t.target.name;
      f.observedFacts = {
          std::to_string(m.flaps) + " transições OK/Falha observadas nas últimas " + std::to_string(m.sampleCount) + " sondagens",
          "Disponibilidade na janela: " + fmtNum(m.availabilityPct) + "%",
      };
      f.hypotheses = {
          "Hipótese: queda micro-intermitente de enlace, roaming Wi-Fi ou rate-limiting intermitente no destino.",
      };
      rep.findings.push_back(std::move(f));
    }

    // Progressive degradation (recent half noticeably worse than older half)
    if (m.sampleCount >= 8 && m.olderHalfAvgMs > 0.0 && m.recentHalfAvgMs > 0.0) {
      const double deltaMs = m.recentHalfAvgMs - m.olderHalfAvgMs;
      const double ratio = m.recentHalfAvgMs / std::max(1.0, m.olderHalfAvgMs);
      const double availDrop = m.olderHalfAvailPct - m.recentHalfAvailPct;
      if ((ratio >= 1.35 && deltaMs >= 15.0) || availDrop >= 15.0) {
        DiagnosisFinding f;
        f.code = "progressive_degradation";
        f.severity = (availDrop >= 30.0 || deltaMs >= 80.0) ? "critical" : "warn";
        f.title = "Degradação progressiva detectada em " + t.target.name;
        f.targetId = t.target.id;
        f.targetName = t.target.name;
        f.observedFacts = {
            "Metade anterior: média " + fmtNum(m.olderHalfAvgMs) + " ms (" + fmtNum(m.olderHalfAvailPct) + "% OK)",
            "Metade recente: média " + fmtNum(m.recentHalfAvgMs) + " ms (" + fmtNum(m.recentHalfAvailPct) + "% OK)",
        };
        f.hypotheses = {
            "Hipótese: aumento progressivo de congestionamento ou saturação crescente de fila no enlace atual.",
        };
        rep.findings.push_back(std::move(f));
      }
    }
  }

  bool hasCrit = false;
  bool hasWarn = false;
  for (const auto& f : rep.findings) {
    if (f.severity == "critical") hasCrit = true;
    else if (f.severity == "warn") hasWarn = true;
  }

  if (rep.findings.empty()) {
    rep.overallHealth = "healthy";
    DiagnosisFinding okF;
    okF.code = "all_checks_nominal";
    okF.severity = "ok";
    okF.title = "Qualidade da rede nominal em todos os destinos ativos";
    for (const auto* gw : gateways) {
      okF.observedFacts.push_back("Gateway " + gw->target.host + ": P50 " + fmtNum(gw->metrics.p50Ms) + " ms · perda " + fmtNum(gw->metrics.packetLossPct) + "%");
    }
    if (!dnsNodes.empty()) {
      okF.observedFacts.push_back("DNS (" + dnsNodes.front()->target.host + "): disponibilidade " + fmtNum(dnsNodes.front()->metrics.availabilityPct) +
                                  "% · DNS " + fmtNum(dnsNodes.front()->metrics.avgDnsMs) + " ms");
    }
    if (!externals.empty()) {
      okF.observedFacts.push_back("Externo (" + externals.front()->target.name + "): P95 " + fmtNum(externals.front()->metrics.p95Ms) +
                                  " ms · jitter " + fmtNum(externals.front()->metrics.jitterMs) + " ms");
    }
    okF.hypotheses.push_back("Nenhum padrão determinístico de falha, perda relevante ou degradação progressiva detectado na janela atual.");
    rep.findings.push_back(std::move(okF));
  } else {
    rep.overallHealth = hasCrit ? "critical" : (hasWarn ? "degraded" : "healthy");
  }
  (void)anyGatewayDown;
  return rep;
}

NetworkQualityEngine::NetworkQualityEngine(HistoryStore& history)
    : history_(history) {}

NetworkQualityEngine::~NetworkQualityEngine() {
  stop();
}

void NetworkQualityEngine::seedTargetsLocked() {
  const auto persisted = history_.loadQualityTargets();
  for (const auto& t : persisted) {
    TargetState ts;
    ts.snapshot.target = t;
    ts.snapshot.methodUsed = t.probeMode;
    auto recent = history_.loadRecentQualitySamples(t.id, 120);
    for (auto& r : recent) ts.window.push_back(std::move(r));
    if (!ts.window.empty()) {
      std::vector<QualitySampleRecord> vec(ts.window.begin(), ts.window.end());
      ts.snapshot.metrics = computeQualityMetrics(vec);
      const auto& last = ts.window.back();
      ts.snapshot.lastProbeMs = last.tsMs;
      ts.snapshot.lastError = last.error;
      ts.snapshot.methodUsed = last.method;
      ts.snapshot.status = last.ok ? (ts.snapshot.metrics.packetLossPct > 5.0 ? "degraded" : "ok") : "down";
    }
    targetOrder_.push_back(t.id);
    targets_[t.id] = std::move(ts);
  }

  // Default curated baseline targets seeded once if absent
  struct SeedDef {
    const char* id;
    const char* name;
    const char* host;
    uint16_t port;
    const char* cat;
    const char* mode;
  };
  const SeedDef defaults[] = {
      {"pub-dns-cf", "Cloudflare DNS (1.1.1.1)", "1.1.1.1", 53, "public_dns", "dns"},
      {"pub-dns-gg", "Google DNS (8.8.8.8)", "8.8.8.8", 53, "public_dns", "dns"},
      {"pub-dns-q9", "Quad9 DNS (9.9.9.9)", "9.9.9.9", 53, "public_dns", "dns"},
      {"known-github", "GitHub Edge (HTTPS)", "github.com", 443, "known_server", "tcp"},
      {"known-msft", "Microsoft Connectivity", "www.microsoft.com", 443, "known_server", "tcp"},
  };
  for (const auto& d : defaults) {
    if (targets_.find(d.id) != targets_.end()) continue;
    QualityTargetRecord t;
    t.id = d.id;
    t.name = d.name;
    t.host = d.host;
    t.port = d.port;
    t.category = d.cat;
    t.probeMode = d.mode;
    t.intervalSec = 10;
    t.enabled = true;
    t.isAuto = false;
    t.createdAtMs = nowEpochMs();
    history_.upsertQualityTarget(t);

    TargetState ts;
    ts.snapshot.target = std::move(t);
    ts.snapshot.methodUsed = d.mode;
    targetOrder_.push_back(d.id);
    targets_[d.id] = std::move(ts);
  }
}

void NetworkQualityEngine::syncAutoInfraTargetsLocked(const DiscoveredInfra& infra) {
  lastInfra_ = infra;
  auto upsertAuto = [&](const std::string& id,
                        const std::string& name,
                        const std::string& host,
                        uint16_t port,
                        const std::string& category,
                        const std::string& mode) {
    auto it = targets_.find(id);
    if (it != targets_.end()) {
      if (it->second.snapshot.target.host != host) {
        it->second.snapshot.target.host = host;
        it->second.snapshot.target.name = name;
        history_.upsertQualityTarget(it->second.snapshot.target);
      }
      return;
    }
    QualityTargetRecord t;
    t.id = id;
    t.name = name;
    t.host = host;
    t.port = port;
    t.category = category;
    t.probeMode = mode;
    t.intervalSec = 10;
    t.enabled = true;
    t.isAuto = true;
    t.createdAtMs = nowEpochMs();
    history_.upsertQualityTarget(t);

    TargetState ts;
    ts.snapshot.target = std::move(t);
    ts.snapshot.methodUsed = mode;
    targetOrder_.insert(targetOrder_.begin(), id);
    targets_[id] = std::move(ts);
  };

  if (!infra.gateways.empty()) {
    upsertAuto("auto-gw-primary",
               "Gateway Local (" + infra.gateways.front() + ")",
               infra.gateways.front(),
               80,
               "gateway",
               "icmp");
  }
  if (!infra.dnsServers.empty()) {
    const std::string& ispDns = infra.dnsServers.front();
    upsertAuto("auto-dns-isp",
               "DNS Local/Provedor (" + ispDns + ")",
               ispDns,
               53,
               "isp_dns",
               "dns");
  }
}

void NetworkQualityEngine::start() {
  if (running_.exchange(true)) return;
  {
    std::lock_guard lock(mutex_);
    targets_.clear();
    targetOrder_.clear();
    seedTargetsLocked();
    syncAutoInfraTargetsLocked(discoverNetworkInfra());
  }
  probeRequested_.store(true);
  workerThread_ = std::jthread([this](std::stop_token st) { workerLoop(st); });
}

void NetworkQualityEngine::stop() {
  if (!running_.exchange(false)) return;
  if (workerThread_.joinable()) {
    workerThread_.request_stop();
    wakeCv_.notify_all();
    workerThread_.join();
  }
}

void NetworkQualityEngine::probeNowAsync() {
  probeRequested_.store(true);
  wakeCv_.notify_all();
}

void NetworkQualityEngine::rediscoverInfra() {
  const auto infra = discoverNetworkInfra();
  {
    std::lock_guard lock(mutex_);
    syncAutoInfraTargetsLocked(infra);
  }
  probeNowAsync();
}

bool NetworkQualityEngine::addTarget(const std::string& name,
                                     const std::string& host,
                                     uint16_t port,
                                     const std::string& category,
                                     const std::string& probeMode,
                                     int intervalSec,
                                     std::string& outId,
                                     std::string& outError) {
  if (!isValidTargetHost(host)) {
    outError = "Host ou IP inválido";
    return false;
  }
  std::string mode = probeMode;
  if (mode != "icmp" && mode != "tcp" && mode != "dns") mode = "icmp";
  std::string cat = category;
  if (cat != "gateway" && cat != "isp_dns" && cat != "public_dns" && cat != "known_server" && cat != "custom") {
    cat = "custom";
  }

  std::string id = "q-" + sanitizeSlug(host) + "-" + std::to_string(nowEpochMs() % 100000);
  QualityTargetRecord t;
  t.id = id;
  t.name = name.empty() ? host : name;
  t.host = host;
  t.port = (port == 0 && mode == "tcp") ? 443 : ((port == 0 && mode == "dns") ? 53 : port);
  t.category = cat;
  t.probeMode = mode;
  t.intervalSec = std::clamp(intervalSec, 5, 300);
  t.enabled = true;
  t.isAuto = false;
  t.createdAtMs = nowEpochMs();

  if (!history_.upsertQualityTarget(t)) {
    outError = "Falha ao salvar alvo no SQLite";
    return false;
  }

  {
    std::lock_guard lock(mutex_);
    TargetState ts;
    ts.snapshot.target = std::move(t);
    ts.snapshot.methodUsed = mode;
    targetOrder_.push_back(id);
    targets_[id] = std::move(ts);
  }
  outId = id;
  probeNowAsync();
  return true;
}

bool NetworkQualityEngine::updateTarget(const std::string& id,
                                        const std::string& name,
                                        uint16_t port,
                                        const std::string& probeMode,
                                        int intervalSec,
                                        bool enabled,
                                        std::string& outError) {
  QualityTargetRecord updated;
  {
    std::lock_guard lock(mutex_);
    auto it = targets_.find(id);
    if (it == targets_.end()) {
      outError = "Alvo não encontrado";
      return false;
    }
    auto& t = it->second.snapshot.target;
    if (!name.empty()) t.name = name;
    if (port > 0) t.port = port;
    if (probeMode == "icmp" || probeMode == "tcp" || probeMode == "dns") t.probeMode = probeMode;
    t.intervalSec = std::clamp(intervalSec, 5, 300);
    t.enabled = enabled;
    updated = t;
  }
  if (!history_.upsertQualityTarget(updated)) {
    outError = "Falha ao atualizar alvo no SQLite";
    return false;
  }
  if (enabled) probeNowAsync();
  return true;
}

bool NetworkQualityEngine::removeTarget(const std::string& id) {
  bool erased = false;
  {
    std::lock_guard lock(mutex_);
    auto it = targets_.find(id);
    if (it != targets_.end()) {
      targets_.erase(it);
      targetOrder_.erase(std::remove(targetOrder_.begin(), targetOrder_.end(), id), targetOrder_.end());
      erased = true;
    }
  }
  if (!erased) return false;
  history_.deleteQualityTarget(id);
  return true;
}

void NetworkQualityEngine::probeSingleTarget(const QualityTargetRecord& target, uint64_t nowMs) {
  LowLevelProbeResult res;
  if (target.probeMode == "dns") {
    res = probeDnsServerUdp(target.host, target.port > 0 ? target.port : 53, 1200);
    // Also check ICMP echo when host is numeric DNS so RTT + DNS query time are both accurate
    if (res.ok && target.category != "isp_dns") {
      auto icmpRes = probeIcmpOrFallback(target.host, 443, 1000);
      if (icmpRes.ok) {
        res.rttMs = icmpRes.rttMs;
        res.methodUsed = "icmp+dns";
      }
    }
  } else if (target.probeMode == "tcp") {
    res = probeTcpConnect(target.host, target.port > 0 ? target.port : 443, 1500);
  } else {
    res = probeIcmpOrFallback(target.host, target.port, 1200);
  }

  QualitySampleRecord rec;
  rec.tsMs = nowMs;
  rec.targetId = target.id;
  rec.ok = res.ok;
  rec.rttMs = res.ok ? res.rttMs : 0.0;
  rec.dnsMs = res.dnsMs;
  rec.method = res.methodUsed;
  rec.error = res.error;

  {
    std::lock_guard lock(mutex_);
    auto it = targets_.find(target.id);
    if (it == targets_.end()) return;
    auto& st = it->second;

    if (rec.ok) {
      for (auto rIt = st.window.rbegin(); rIt != st.window.rend(); ++rIt) {
        if (rIt->ok) {
          rec.jitterMs = std::abs(rec.rttMs - rIt->rttMs);
          break;
        }
      }
    }

    st.window.push_back(rec);
    while (st.window.size() > 120) st.window.pop_front();

    std::vector<QualitySampleRecord> vec(st.window.begin(), st.window.end());
    st.snapshot.metrics = computeQualityMetrics(vec);
    st.snapshot.lastProbeMs = nowMs;
    st.snapshot.nextProbeMs = nowMs + static_cast<uint64_t>(std::clamp(target.intervalSec, 5, 300)) * 1000ULL;
    st.snapshot.lastError = res.error;
    st.snapshot.methodUsed = res.methodUsed;

    if (!rec.ok) {
      st.snapshot.status = (st.snapshot.metrics.packetLossPct >= 50.0 || st.snapshot.metrics.okCount == 0) ? "down" : "degraded";
    } else if (st.snapshot.metrics.packetLossPct > 5.0 || st.snapshot.metrics.jitterMs > 30.0) {
      st.snapshot.status = "degraded";
    } else {
      st.snapshot.status = "ok";
    }
  }

  history_.enqueueQualitySample(rec);
}

void NetworkQualityEngine::workerLoop(std::stop_token st) {
  while (!st.stop_requested()) {
    const uint64_t now = nowEpochMs();
    const bool forced = probeRequested_.exchange(false);

    std::vector<QualityTargetRecord> dueTargets;
    {
      std::lock_guard lock(mutex_);
      for (const auto& id : targetOrder_) {
        auto it = targets_.find(id);
        if (it == targets_.end()) continue;
        const auto& snap = it->second.snapshot;
        if (!snap.target.enabled) continue;
        if (forced || snap.lastProbeMs == 0 || now >= snap.nextProbeMs) {
          dueTargets.push_back(snap.target);
        }
      }
    }

    for (const auto& t : dueTargets) {
      if (st.stop_requested()) break;
      probeSingleTarget(t, nowEpochMs());
    }

    std::unique_lock lk(wakeMutex_);
    wakeCv_.wait_for(lk, st, std::chrono::milliseconds(1500), [this]() {
      return probeRequested_.load();
    });
  }
}

QualityDiagnosisReport NetworkQualityEngine::getLatestDiagnosis() const {
  return diagnoseNetworkQuality(getTargetsSnapshot());
}

std::vector<QualityTargetSnapshot> NetworkQualityEngine::getTargetsSnapshot() const {
  std::vector<QualityTargetSnapshot> snaps;
  std::lock_guard lock(mutex_);
  snaps.reserve(targetOrder_.size());
  for (const auto& id : targetOrder_) {
    auto it = targets_.find(id);
    if (it != targets_.end()) snaps.push_back(it->second.snapshot);
  }
  return snaps;
}

std::string NetworkQualityEngine::getStatusJson() const {
  std::vector<QualityTargetSnapshot> snaps;
  DiscoveredInfra infraCopy;
  {
    std::lock_guard lock(mutex_);
    infraCopy = lastInfra_;
    snaps.reserve(targetOrder_.size());
    for (const auto& id : targetOrder_) {
      auto it = targets_.find(id);
      if (it != targets_.end()) snaps.push_back(it->second.snapshot);
    }
  }

  const auto diag = diagnoseNetworkQuality(snaps);
  char num[32];
  auto appendNum = [&](std::string& dst, double v) {
    std::snprintf(num, sizeof(num), "%.2f", v);
    dst += num;
  };

  std::string out = "{\"evaluatedAt\":";
  out += std::to_string(diag.evaluatedAtMs);
  out += ",\"infra\":{\"gateways\":";
  appendJsonStrArr(out, infraCopy.gateways);
  out += ",\"dnsServers\":";
  appendJsonStrArr(out, infraCopy.dnsServers);
  out += "},\"diagnosis\":{\"overallHealth\":";
  appendJsonEscaped(out, diag.overallHealth);
  out += ",\"findings\":[";
  for (size_t i = 0; i < diag.findings.size(); ++i) {
    const auto& f = diag.findings[i];
    if (i > 0) out.push_back(',');
    out += "{\"code\":";
    appendJsonEscaped(out, f.code);
    out += ",\"severity\":";
    appendJsonEscaped(out, f.severity);
    out += ",\"title\":";
    appendJsonEscaped(out, f.title);
    out += ",\"targetId\":";
    appendJsonEscaped(out, f.targetId);
    out += ",\"targetName\":";
    appendJsonEscaped(out, f.targetName);
    out += ",\"observedFacts\":";
    appendJsonStrArr(out, f.observedFacts);
    out += ",\"hypotheses\":";
    appendJsonStrArr(out, f.hypotheses);
    out += ",\"suggestedChecks\":";
    appendJsonStrArr(out, f.suggestedChecks);
    out.push_back('}');
  }
  out += "]},\"targets\":[";

  for (size_t i = 0; i < snaps.size(); ++i) {
    const auto& s = snaps[i];
    const auto& t = s.target;
    const auto& m = s.metrics;
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    appendJsonEscaped(out, t.id);
    out += ",\"name\":";
    appendJsonEscaped(out, t.name);
    out += ",\"host\":";
    appendJsonEscaped(out, t.host);
    out += ",\"port\":";
    out += std::to_string(t.port);
    out += ",\"category\":";
    appendJsonEscaped(out, t.category);
    out += ",\"probeMode\":";
    appendJsonEscaped(out, t.probeMode);
    out += ",\"methodUsed\":";
    appendJsonEscaped(out, s.methodUsed);
    out += ",\"intervalSec\":";
    out += std::to_string(t.intervalSec);
    out += ",\"enabled\":";
    out += (t.enabled ? "true" : "false");
    out += ",\"isAuto\":";
    out += (t.isAuto ? "true" : "false");
    out += ",\"status\":";
    appendJsonEscaped(out, s.status);
    out += ",\"lastProbeMs\":";
    out += std::to_string(s.lastProbeMs);
    out += ",\"lastError\":";
    appendJsonEscaped(out, s.lastError);
    out += ",\"metrics\":{\"samples\":";
    out += std::to_string(m.sampleCount);
    out += ",\"okCount\":";
    out += std::to_string(m.okCount);
    out += ",\"currentMs\":";
    appendNum(out, m.currentLatencyMs);
    out += ",\"minMs\":";
    appendNum(out, m.minLatencyMs);
    out += ",\"maxMs\":";
    appendNum(out, m.maxLatencyMs);
    out += ",\"avgMs\":";
    appendNum(out, m.avgLatencyMs);
    out += ",\"p50Ms\":";
    appendNum(out, m.p50Ms);
    out += ",\"p90Ms\":";
    appendNum(out, m.p90Ms);
    out += ",\"p95Ms\":";
    appendNum(out, m.p95Ms);
    out += ",\"p99Ms\":";
    appendNum(out, m.p99Ms);
    out += ",\"jitterMs\":";
    appendNum(out, m.jitterMs);
    out += ",\"lossPct\":";
    appendNum(out, m.packetLossPct);
    out += ",\"availabilityPct\":";
    appendNum(out, m.availabilityPct);
    out += ",\"currentDnsMs\":";
    appendNum(out, m.currentDnsMs);
    out += ",\"avgDnsMs\":";
    appendNum(out, m.avgDnsMs);
    out += ",\"flaps\":";
    out += std::to_string(m.flaps);
    out += "}}";
  }

  out += "]}";
  return out;
}

} // namespace netpulse
