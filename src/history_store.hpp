#pragma once

#include "geo_dns.hpp"
#include "models.hpp"
#include "service_monitor.hpp"
#include "storage/sqlite_db.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace netpulse {

struct HistoryEvent {
  uint64_t tsMs = 0;
  std::string severity; // "info" | "warn" | "critical"
  std::string kind;     // "new_country" | "sensitive_port" | "service_down" | "service_up" | "action"
  std::string title;
  std::string detail;
};

struct ServiceMetricPoint {
  uint64_t tsMs = 0;
  std::string serviceId;
  std::string status;
  double latencyMs = 0.0;
};

struct NotificationCategories {
  bool serviceDown = true;
  bool serviceDegraded = true;
  bool sensitivePort = true;
  bool newCountry = true;
};

struct ConnectionHistoryRecord {
  std::string connKey;
  std::string processName;
  uint32_t pid = 0;
  std::string exePath;
  std::string localIp;
  std::string remoteIp;
  uint16_t localPort = 0;
  uint16_t remotePort = 0;
  std::string protocol;
  uint8_t ipVersion = 4;
  std::string state;
  std::string scope;
  uint64_t startedAtMs = 0;
  uint64_t endedAtMs = 0;
  uint64_t durationMs = 0;
  std::string country;
  std::string countryCode;
  std::string city;
  std::string asn;
  std::string isp;
  std::string dnsName;
  uint64_t rxBytes = 0;
  uint64_t txBytes = 0;
  uint64_t lastCheckpointMs = 0;
  bool countedInRollup = false;
};

struct ConnectionQuery {
  size_t limit = 50;
  size_t offset = 0;
  std::string process;
  std::string remoteIp;
  std::string country;
  std::string protocol;
  std::string scope;
  std::string search;
  uint64_t fromMs = 0;
  uint64_t toMs = 0;
};

struct QualityTargetRecord {
  std::string id;
  std::string name;
  std::string host;
  uint16_t port = 0;
  std::string category = "custom"; // "gateway" | "isp_dns" | "public_dns" | "known_server" | "custom"
  std::string probeMode = "icmp";  // "icmp" | "tcp" | "dns"
  int intervalSec = 10;
  bool enabled = true;
  bool isAuto = false;
  uint64_t createdAtMs = 0;
};

struct QualitySampleRecord {
  uint64_t tsMs = 0;
  std::string targetId;
  bool ok = false;
  double rttMs = 0.0;
  double dnsMs = 0.0;
  double jitterMs = 0.0;
  std::string method = "icmp";
  std::string error;
};

struct TraceHopRecord {
  int ttl = 0;
  bool timedOut = false;
  std::string ip;
  double rttMs = 0.0;
  std::string hostname;
  std::string asn;
  std::string country;
  std::string countryCode;
  std::string city;
  double lat = 0.0;
  double lon = 0.0;
};

struct TraceRunRecord {
  int64_t id = 0;
  std::string targetIp;
  std::string targetLabel;
  std::string triggerKind = "manual"; // "manual" | "scheduled"
  uint64_t startedAtMs = 0;
  uint64_t completedAtMs = 0;
  bool reached = false;
  double totalRttMs = 0.0;
  std::string pathHash;
  bool changedFromPrev = false;
  std::string error;
  std::vector<TraceHopRecord> hops;
};

struct TraceMonitorRecord {
  std::string targetIp;
  std::string label;
  int intervalSec = 300;
  bool enabled = true;
  uint64_t createdAtMs = 0;
  uint64_t lastRunMs = 0;
};

struct InterfaceSampleRecord {
  uint64_t tsMs = 0;
  std::string ifId;
  std::string ifName;
  std::string ifType = "other";
  std::string operStatus = "unknown";
  bool isDefaultRoute = false;
  uint64_t linkSpeedBps = 0;
  double rxBps = 0.0;
  double txBps = 0.0;
  uint64_t rxBytes = 0;
  uint64_t txBytes = 0;
  uint64_t rxErrors = 0;
  uint64_t txErrors = 0;
};

struct LanDeviceRecord {
  std::string deviceKey;
  std::string ip;
  std::string mac;
  std::string vendor;
  std::string hostname;
  std::string deviceType = "unknown";
  std::string interfaceName;
  std::string subnet;
  bool isGateway = false;
  bool isLocalHost = false;
  bool online = true;
  double latencyMs = 0.0;
  std::string openPorts;
  std::string customLabel;
  uint64_t firstSeenMs = 0;
  uint64_t lastSeenMs = 0;
  uint64_t seenCount = 1;
};

bool isSensitivePort(uint16_t port);
uint64_t rangeToDurationMs(const std::string& range);

class HistoryStore {
public:
  using AlertCallback = std::function<void(const std::string& title, const std::string& body, bool isWarning)>;

  explicit HistoryStore(std::filesystem::path dataDir);
  ~HistoryStore();

  HistoryStore(const HistoryStore&) = delete;
  HistoryStore& operator=(const HistoryStore&) = delete;

  void stop();
  void setAlertCallback(AlertCallback cb);
  void setAlertsEnabled(bool enabled) { alertsEnabled_.store(enabled); }
  bool alertsEnabled() const { return alertsEnabled_.load(); }
  void setNotificationCategories(const NotificationCategories& cats);
  bool shouldNotifyKind(const std::string& kind) const;

  void setRetentionConfig(int retentionDays, int maxDbSizeMb);

  void processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns);
  void processServices(const std::vector<ServiceStatus>& services);
  void recordManualAction(const std::string& severity, const std::string& title, const std::string& detail);
  void enqueueQualitySample(const QualitySampleRecord& sample);

  std::vector<QualityTargetRecord> loadQualityTargets();
  bool upsertQualityTarget(const QualityTargetRecord& target);
  bool deleteQualityTarget(const std::string& id);
  std::string queryQualityHistoryJson(const std::string& targetId, const std::string& range);
  std::vector<QualitySampleRecord> loadRecentQualitySamples(const std::string& targetId, size_t maxCount = 120);

  int64_t saveTraceRun(TraceRunRecord& run);
  std::vector<TraceRunRecord> loadTraceRuns(const std::string& targetIp = {}, size_t limit = 30);
  bool getTraceRunById(int64_t runId, TraceRunRecord& out);
  std::string queryTraceHistoryJson(const std::string& targetIp = {}, size_t limit = 30);
  std::vector<TraceMonitorRecord> loadTraceMonitors();
  bool upsertTraceMonitor(const TraceMonitorRecord& mon);
  bool deleteTraceMonitor(const std::string& targetIp);
  bool updateTraceMonitorLastRun(const std::string& targetIp, uint64_t lastRunMs);

  void enqueueInterfaceSamples(const std::vector<InterfaceSampleRecord>& samples);
  std::string queryInterfaceHistoryJson(const std::string& ifId, const std::string& range);

  std::vector<LanDeviceRecord> loadLanDevices();
  bool upsertLanDevices(const std::vector<LanDeviceRecord>& devices, bool markOthersOffline);
  bool setLanDeviceLabel(const std::string& deviceKey, const std::string& label);
  bool deleteLanDevice(const std::string& deviceKey);

  void flushNow();
  bool pruneNow();

  std::string getEventsJson(size_t maxItems = 150,
                            size_t offset = 0,
                            const std::string& severityFilter = {},
                            const std::string& kindFilter = {}) const;
  std::string getServiceHistoryJson(const std::string& serviceId, size_t maxPoints = 60) const;
  std::string queryConnectionsJson(const ConnectionQuery& q);
  std::string queryProcessesJson(const std::string& range, size_t limit = 50, size_t offset = 0, const std::string& procFilter = {});
  std::string queryAnalyticsJson(const std::string& range);
  std::string getStorageStatsJson();

private:
  struct RollupDelta {
    uint64_t bucketStartMs = 0;
    std::string processName;
    std::string remoteIp;
    std::string country;
    std::string countryCode;
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    uint64_t connCount = 0;
    uint64_t totalDurationMs = 0;
  };

  struct NicSampleDelta {
    uint64_t bucketStartMs = 0;
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    double maxRxBps = 0.0;
    double maxTxBps = 0.0;
    uint64_t connsSum = 0;
    uint64_t sampleCount = 0;
  };

  void loadCachesFromDb();
  void importLegacyTsvIfNeeded();
  void writerLoop(std::stop_token st);
  void drainAndWriteBatch();
  bool applyRetentionLocked(sqlite3* db);
  void enqueueEvent(HistoryEvent ev, bool notifyTray);

  std::filesystem::path dataDir_;
  std::filesystem::path dbPath_;
  std::filesystem::path legacyEventsPath_;
  std::filesystem::path legacyMetricsPath_;
  std::filesystem::path migrationMarkerPath_;

  mutable SqliteDb db_;

  mutable std::mutex cacheMutex_;
  std::deque<HistoryEvent> events_;
  std::unordered_map<std::string, std::deque<ServiceMetricPoint>> serviceSeries_;
  std::unordered_map<std::string, std::string> prevServiceStatus_;
  std::unordered_map<std::string, uint64_t> prevServiceSampleMs_;
  std::unordered_set<std::string> seenCountries_;
  std::unordered_map<std::string, uint64_t> alertCooldownMs_;
  uint64_t startupWarmupEndMs_ = 0;

  std::unordered_map<std::string, ConnectionHistoryRecord> activeConns_;
  uint64_t prevTelemetryMs_ = 0;

  std::mutex queueMutex_;
  std::condition_variable_any queueCv_;
  std::vector<HistoryEvent> pendingEvents_;
  std::vector<ServiceMetricPoint> pendingMetrics_;
  std::vector<ConnectionHistoryRecord> pendingConns_;
  std::vector<QualitySampleRecord> pendingQualitySamples_;
  std::vector<InterfaceSampleRecord> pendingInterfaceSamples_;
  std::unordered_map<std::string, RollupDelta> pendingRollups_;
  std::unordered_map<uint64_t, NicSampleDelta> pendingNicSamples_;

  std::atomic<bool> alertsEnabled_{true};
  NotificationCategories categories_;
  AlertCallback alertCb_;

  std::atomic<int> retentionDays_{30};
  std::atomic<int> maxDbSizeMb_{256};
  std::atomic<bool> pruneRequested_{false};
  std::atomic<uint64_t> lastPruneMs_{0};

  std::jthread writerThread_;
};

} // namespace netpulse
