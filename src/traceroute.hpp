#pragma once

#include "geo_dns.hpp"
#include "history_store.hpp"

#include <atomic>
#include <condition_variable>
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
  int64_t runId = 0;
  std::string targetIp;
  std::string targetLabel;
  bool running = false;
  bool completed = false;
  bool changedFromPrev = false;
  std::string pathHash;
  std::string error;
  std::vector<TraceHop> hops;
};

struct TraceHopDiff {
  int ttl = 0;
  std::string kind = "unchanged"; // "unchanged" | "changed" | "added" | "removed" | "timeout_change"
  std::string ipA;
  std::string ipB;
  double rttMsA = 0.0;
  double rttMsB = 0.0;
  double deltaRttMs = 0.0;
  std::string asnA;
  std::string asnB;
};

struct TraceRouteDiff {
  int64_t runAId = 0;
  int64_t runBId = 0;
  std::string targetIp;
  bool pathChanged = false;
  size_t hopCountA = 0;
  size_t hopCountB = 0;
  int changedHopsCount = 0;
  double totalRttDeltaMs = 0.0;
  std::vector<TraceHopDiff> diffs;
};

// Pure deterministic helpers exposed for unit testing
std::string computeTracePathHash(const std::vector<TraceHopRecord>& hops);
TraceRouteDiff computeTraceRouteDiff(const TraceRunRecord& runA, const TraceRunRecord& runB);
std::string serializeTraceDiffJson(const TraceRouteDiff& diff);

class TracerouteService {
public:
  explicit TracerouteService(GeoDnsService& geoDns, HistoryStore* history = nullptr);
  ~TracerouteService();

  TracerouteService(const TracerouteService&) = delete;
  TracerouteService& operator=(const TracerouteService&) = delete;

  void startScheduler();
  void stop();
  bool startTrace(const std::string& targetIp, const std::string& targetLabel = {});
  std::string getStatusJson() const;

  std::string getHistoryJson(const std::string& targetIp, size_t limit = 30) const;
  std::string getDiffJson(int64_t runAId, int64_t runBId, const std::string& targetIp) const;
  std::string getMonitorsJson() const;
  bool upsertMonitor(const std::string& targetIp, const std::string& label, int intervalSec, bool enabled);
  bool removeMonitor(const std::string& targetIp);

private:
  TraceRunRecord executeTraceBlocking(std::stop_token st,
                                      const std::string& targetIp,
                                      const std::string& targetLabel,
                                      const std::string& triggerKind,
                                      bool publishLiveSession);
  void enrichHopsFromGeoDns(TraceRunRecord& run) const;
  void runInteractiveTrace(std::stop_token st, std::string targetIp, std::string targetLabel);
  void schedulerLoop(std::stop_token st);

  GeoDnsService& geoDns_;
  HistoryStore* history_ = nullptr;
  mutable std::mutex mutex_;
  TraceSession session_;
  std::jthread worker_;

  std::mutex schedMutex_;
  std::condition_variable_any schedCv_;
  std::atomic<bool> schedWake_{false};
  std::jthread scheduler_;
};

} // namespace netpulse
