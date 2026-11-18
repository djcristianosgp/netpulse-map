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
#include <netinet/in.h>
#include <sstream>
#endif

#include "models.hpp"
#include "net_monitor.hpp"
#include "traceroute.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace netpulse {

TracerouteService::TracerouteService(GeoDnsService& geoDns)
    : geoDns_(geoDns) {}

TracerouteService::~TracerouteService() {
  stop();
}

void TracerouteService::stop() {
  if (worker_.joinable()) {
    worker_.request_stop();
    worker_.join();
  }
}

bool TracerouteService::startTrace(const std::string& targetIp) {
  struct in_addr in4{};
  struct in6_addr in6{};
  if (inet_pton(AF_INET, targetIp.c_str(), &in4) != 1 &&
      inet_pton(AF_INET6, targetIp.c_str(), &in6) != 1) {
    return false;
  }

  stop();
  {
    std::lock_guard lock(mutex_);
    session_ = TraceSession{};
    session_.targetIp = targetIp;
    session_.running = true;
  }

  worker_ = std::jthread([this, targetIp](std::stop_token st) { runTrace(st, targetIp); });
  return true;
}

void TracerouteService::runTrace(std::stop_token st, std::string targetIp) {
#ifdef _WIN32
  IN_ADDR in4{};
  IN6_ADDR in6{};
  const bool isV4 = (inet_pton(AF_INET, targetIp.c_str(), &in4) == 1);
  const bool isV6 = (!isV4 && inet_pton(AF_INET6, targetIp.c_str(), &in6) == 1);

  if (!isV4 && !isV6) {
    std::lock_guard lock(mutex_);
    session_.running = false;
    session_.completed = true;
    session_.error = "Invalid IP address";
    return;
  }

  HANDLE hIcmp = isV4 ? IcmpCreateFile() : Icmp6CreateFile();
  if (hIcmp == INVALID_HANDLE_VALUE) {
    std::lock_guard lock(mutex_);
    session_.running = false;
    session_.completed = true;
    session_.error = "Failed to open ICMP handle";
    return;
  }

  char sendData[32] = "NetPulse2D-TraceProbe";
  int consecutiveTimeouts = 0;

  for (int ttl = 1; ttl <= 28 && !st.stop_requested(); ++ttl) {
    TraceHop hop;
    hop.ttl = ttl;

    IP_OPTION_INFORMATION opts{};
    opts.Ttl = static_cast<UCHAR>(ttl);

    const auto t0 = std::chrono::steady_clock::now();

    if (isV4) {
      uint8_t replyBuf[sizeof(ICMP_ECHO_REPLY) + 64] = {};
      DWORD count = IcmpSendEcho(hIcmp, in4.S_un.S_addr, sendData, sizeof(sendData),
                                 &opts, replyBuf, sizeof(replyBuf), 850);
      const auto t1 = std::chrono::steady_clock::now();
      double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

      if (count > 0) {
        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuf);
        if (reply->Status == IP_SUCCESS || reply->Status == IP_TTL_EXPIRED_TRANSIT) {
          char ipBuf[INET_ADDRSTRLEN] = {};
          IN_ADDR rAddr{};
          rAddr.S_un.S_addr = reply->Address;
          if (inet_ntop(AF_INET, &rAddr, ipBuf, sizeof(ipBuf))) {
            hop.ip = ipBuf;
          }
          hop.rttMs = (reply->RoundTripTime > 0) ? static_cast<double>(reply->RoundTripTime) : elapsedMs;
        } else {
          hop.timedOut = true;
        }
      } else {
        hop.timedOut = true;
      }
    } else {
      sockaddr_in6 srcAddr{};
      srcAddr.sin6_family = AF_INET6;
      sockaddr_in6 dstAddr{};
      dstAddr.sin6_family = AF_INET6;
      dstAddr.sin6_addr = in6;

      uint8_t replyBuf[sizeof(ICMPV6_ECHO_REPLY) + 64] = {};
      DWORD count = Icmp6SendEcho2(hIcmp, nullptr, nullptr, nullptr,
                                   &srcAddr, &dstAddr, sendData, sizeof(sendData),
                                   &opts, replyBuf, sizeof(replyBuf), 850);
      const auto t1 = std::chrono::steady_clock::now();
      double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

      if (count > 0) {
        const auto* reply = reinterpret_cast<const ICMPV6_ECHO_REPLY*>(replyBuf);
        if (reply->Status == IP_SUCCESS || reply->Status == IP_TTL_EXPIRED_TRANSIT) {
          char ipBuf[INET6_ADDRSTRLEN] = {};
          IN6_ADDR rAddr{};
          std::memcpy(&rAddr, reply->Address.sin6_addr, 16);
          if (inet_ntop(AF_INET6, &rAddr, ipBuf, sizeof(ipBuf))) {
            hop.ip = ipBuf;
          }
          hop.rttMs = (reply->RoundTripTime > 0) ? static_cast<double>(reply->RoundTripTime) : elapsedMs;
        } else {
          hop.timedOut = true;
        }
      } else {
        hop.timedOut = true;
      }
    }

    if (!hop.timedOut && !hop.ip.empty()) {
      consecutiveTimeouts = 0;
      if (classifyIpString(hop.ip) == IpScope::Public) {
        geoDns_.enqueueLookups({hop.ip});
      }
    } else {
      ++consecutiveTimeouts;
    }

    const bool reachedTarget = (!hop.timedOut && hop.ip == targetIp);
    {
      std::lock_guard lock(mutex_);
      session_.hops.push_back(hop);
    }

    if (reachedTarget) break;
    if (ttl >= 12 && consecutiveTimeouts >= 4) break;
  }

  IcmpCloseHandle(hIcmp);

  std::lock_guard lock(mutex_);
  session_.running = false;
  session_.completed = true;
#else
  std::string cmd = "traceroute -n -q 1 -w 1 -m 28 " + targetIp + " 2>&1";
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    std::lock_guard lock(mutex_);
    session_.running = false;
    session_.completed = true;
    session_.error = "Falha ao executar traceroute";
    return;
  }
  char lineBuf[512];
  int consecutiveTimeouts = 0;
  while (!st.stop_requested() && fgets(lineBuf, sizeof(lineBuf), pipe) != nullptr) {
    std::istringstream iss(lineBuf);
    int ttl = 0;
    if (!(iss >> ttl) || ttl <= 0) continue;
    std::string tok1;
    if (!(iss >> tok1)) continue;
    TraceHop hop;
    hop.ttl = ttl;
    if (tok1 == "*") {
      hop.timedOut = true;
      ++consecutiveTimeouts;
    } else {
      hop.ip = tok1;
      consecutiveTimeouts = 0;
      double rtt = 0.0;
      if (iss >> rtt) hop.rttMs = rtt;
      geoDns_.enqueueLookups({hop.ip});
    }
    const bool reachedTarget = (!hop.timedOut && hop.ip == targetIp);
    {
      std::lock_guard lock(mutex_);
      session_.hops.push_back(hop);
    }
    if (reachedTarget || (ttl >= 12 && consecutiveTimeouts >= 4)) break;
  }
  pclose(pipe);

  std::lock_guard lock(mutex_);
  session_.running = false;
  session_.completed = true;
#endif
}

std::string TracerouteService::getStatusJson() const {
  TraceSession snap;
  {
    std::lock_guard lock(mutex_);
    snap = session_;
  }

  std::string out = "{\"targetIp\":";
  appendJsonEscaped(out, snap.targetIp);
  out += ",\"running\":";
  out += (snap.running ? "true" : "false");
  out += ",\"completed\":";
  out += (snap.completed ? "true" : "false");
  out += ",\"error\":";
  appendJsonEscaped(out, snap.error);
  out += ",\"hops\":[";

  char numBuf[32];
  for (size_t i = 0; i < snap.hops.size(); ++i) {
    const auto& h = snap.hops[i];
    if (i > 0) out.push_back(',');
    out += "{\"ttl\":";
    out += std::to_string(h.ttl);
    out += ",\"timedOut\":";
    out += (h.timedOut ? "true" : "false");
    out += ",\"ip\":";
    appendJsonEscaped(out, h.ip);
    std::snprintf(numBuf, sizeof(numBuf), "%.1f", h.rttMs);
    out += ",\"rttMs\":";
    out += numBuf;

    if (!h.ip.empty()) {
      if (auto g = geoDns_.getGeo(h.ip); g.has_value()) {
        out += ",\"geo\":{\"cc\":";
        appendJsonEscaped(out, g->countryCode);
        out += ",\"country\":";
        appendJsonEscaped(out, g->country);
        out += ",\"city\":";
        appendJsonEscaped(out, g->city);
        std::snprintf(numBuf, sizeof(numBuf), "%.4f", g->lat);
        out += ",\"lat\":";
        out += numBuf;
        std::snprintf(numBuf, sizeof(numBuf), "%.4f", g->lon);
        out += ",\"lon\":";
        out += numBuf;
        out.push_back('}');
      }
      if (auto dns = geoDns_.getHostname(h.ip); dns.has_value()) {
        out += ",\"host\":";
        appendJsonEscaped(out, *dns);
      }
    }
    out.push_back('}');
  }

  out += "]}";
  return out;
}

} // namespace netpulse
