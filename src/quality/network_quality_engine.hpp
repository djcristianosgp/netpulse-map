#pragma once

#include "../history_store.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace netpulse {

struct QualityMetricsSummary {
  size_t sampleCount = 0;
  size_t okCount = 0;
  double currentLatencyMs = 0.0;
  double minLatencyMs = 0.0;
  double maxLatencyMs = 0.0;
  double avgLatencyMs = 0.0;
  double p50Ms = 0.0;
  double p90Ms = 0.0;
  double p95Ms = 0.0;
  double p99Ms = 0.0;
  double jitterMs = 0.0;
  double packetLossPct = 0.0;
  double availabilityPct = 0.0;
  double currentDnsMs = 0.0;
  double avgDnsMs = 0.0;
  int flaps = 0;
  double recentHalfAvgMs = 0.0;
  double olderHalfAvgMs = 0.0;
  double recentHalfAvailPct = 0.0;
  double olderHalfAvailPct = 0.0;
};

struct QualityTargetSnapshot {
  QualityTargetRecord target;
  std::string status = "pending"; // "pending" | "ok" | "degraded" | "down"
  std::string methodUsed = "icmp";
  std::string lastError;
  uint64_t lastProbeMs = 0;
  uint64_t nextProbeMs = 0;
  QualityMetricsSummary metrics;
};

struct DiagnosisFinding {
  std::string code;     // "gateway_unreachable" | "dns_unreachable" | "external_unreachable" | "high_latency" | "latency_oscillation" | "packet_loss" | "frequent_interruptions" | "progressive_degradation" | "all_checks_nominal"
  std::string severity; // "ok" | "info" | "warn" | "critical"
  std::string title;
  std::string targetId;
  std::string targetName;
  std::vector<std::string> observedFacts;
  std::vector<std::string> hypotheses;
  std::vector<std::string> suggestedChecks;
};

struct QualityDiagnosisReport {
  std::string overallHealth = "unknown"; // "healthy" | "degraded" | "critical" | "unknown"
  uint64_t evaluatedAtMs = 0;
  std::vector<DiagnosisFinding> findings;
};

struct DiscoveredInfra {
  std::vector<std::string> gateways;
  std::vector<std::string> dnsServers;
};

// Pure deterministic helpers exposed for unit testing
QualityMetricsSummary computeQualityMetrics(const std::vector<QualitySampleRecord>& samples);
QualityDiagnosisReport diagnoseNetworkQuality(const std::vector<QualityTargetSnapshot>& targets);
std::vector<uint8_t> buildDnsQueryPacket(uint16_t txId, const std::string& domain);
bool parseDnsResponseHeader(const uint8_t* buf, size_t len, uint16_t expectedTxId, uint8_t& outRcode);
DiscoveredInfra discoverNetworkInfra();

class NetworkQualityEngine {
public:
  explicit NetworkQualityEngine(HistoryStore& history);
  ~NetworkQualityEngine();

  NetworkQualityEngine(const NetworkQualityEngine&) = delete;
  NetworkQualityEngine& operator=(const NetworkQualityEngine&) = delete;

  void start();
  void stop();
  void probeNowAsync();
  void rediscoverInfra();

  bool addTarget(const std::string& name,
                 const std::string& host,
                 uint16_t port,
                 const std::string& category,
                 const std::string& probeMode,
                 int intervalSec,
                 std::string& outId,
                 std::string& outError);
  bool updateTarget(const std::string& id,
                    const std::string& name,
                    uint16_t port,
                    const std::string& probeMode,
                    int intervalSec,
                    bool enabled,
                    std::string& outError);
  bool removeTarget(const std::string& id);

  std::string getStatusJson() const;
  QualityDiagnosisReport getLatestDiagnosis() const;
  std::vector<QualityTargetSnapshot> getTargetsSnapshot() const;

private:
  struct TargetState {
    QualityTargetSnapshot snapshot;
    std::deque<QualitySampleRecord> window;
  };

  void seedTargetsLocked();
  void syncAutoInfraTargetsLocked(const DiscoveredInfra& infra);
  void workerLoop(std::stop_token st);
  void probeSingleTarget(const QualityTargetRecord& target, uint64_t nowMs);

  HistoryStore& history_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, TargetState> targets_;
  std::vector<std::string> targetOrder_;
  DiscoveredInfra lastInfra_;

  std::mutex wakeMutex_;
  std::condition_variable_any wakeCv_;
  std::atomic<bool> probeRequested_{false};
  std::atomic<bool> running_{false};
  std::jthread workerThread_;
};

} // namespace netpulse
