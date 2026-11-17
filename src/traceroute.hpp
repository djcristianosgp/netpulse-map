#pragma once

#include "geo_dns.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netpulse {

struct TraceHop {
  int ttl = 0;
  bool timedOut = false;
  std::string ip;
  double rttMs = 0.0;
};

struct TraceSession {
  std::string targetIp;
  bool running = false;
  bool completed = false;
  std::string error;
  std::vector<TraceHop> hops;
};

class TracerouteService {
public:
  explicit TracerouteService(GeoDnsService& geoDns);
  ~TracerouteService();

  TracerouteService(const TracerouteService&) = delete;
  TracerouteService& operator=(const TracerouteService&) = delete;

  bool startTrace(const std::string& targetIp);
  void stop();
  std::string getStatusJson() const;

private:
  void runTrace(std::stop_token st, std::string targetIp);

  GeoDnsService& geoDns_;
  mutable std::mutex mutex_;
  TraceSession session_;
  std::jthread worker_;
};

} // namespace netpulse
