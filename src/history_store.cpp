#include "history_store.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr uint64_t kHourMs = 3600ULL * 1000ULL;
constexpr uint64_t kFiveMinMs = 300ULL * 1000ULL;
constexpr uint64_t kDayMs = 24ULL * kHourMs;

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

uint64_t floorBucket(uint64_t tsMs, uint64_t bucketMs) {
  return (tsMs / bucketMs) * bucketMs;
}

} // namespace

bool isSensitivePort(uint16_t port) {
  switch (port) {
    case 21:    // FTP
    case 22:    // SSH
    case 23:    // Telnet
    case 25:    // SMTP
    case 135:   // RPC
    case 139:   // NetBIOS
    case 445:   // SMB
    case 1433:  // MSSQL
    case 3306:  // MySQL
    case 3389:  // RDP
    case 4444:  // Common reverse shell
    case 5432:  // PostgreSQL
    case 5900:  // VNC
    case 6379:  // Redis
      return true;
    default:
      return false;
  }
}

uint64_t rangeToDurationMs(const std::string& range) {
  if (range == "15m") return 15ULL * 60ULL * 1000ULL;
  if (range == "1h") return kHourMs;
  if (range == "24h" || range == "1d") return kDayMs;
  if (range == "7d") return 7ULL * kDayMs;
  if (range == "30d") return 30ULL * kDayMs;
  if (range == "90d") return 90ULL * kDayMs;
  if (range == "all") return 3650ULL * kDayMs;
  return 7ULL * kDayMs;
}

HistoryStore::HistoryStore(std::filesystem::path dataDir)
    : dataDir_(std::move(dataDir)),
      dbPath_(dataDir_ / "netpulse.db"),
      legacyEventsPath_(dataDir_ / "events_history.tsv"),
      legacyMetricsPath_(dataDir_ / "service_metrics.tsv"),
      migrationMarkerPath_(dataDir_ / ".tsv_imported_v1"),
      startupWarmupEndMs_(nowEpochMs() + 6000) {
  std::string err;
  if (db_.open(dbPath_, err)) {
    db_.runMigrations(err);
    importLegacyTsvIfNeeded();
    loadCachesFromDb();
  }
  lastPruneMs_.store(nowEpochMs());
  writerThread_ = std::jthread([this](std::stop_token st) { writerLoop(st); });
}

HistoryStore::~HistoryStore() {
  stop();
}

void HistoryStore::stop() {
  const uint64_t now = nowEpochMs();
  {
    std::lock_guard cLock(cacheMutex_);
    std::lock_guard qLock(queueMutex_);
    for (auto& [k, rec] : activeConns_) {
      rec.endedAtMs = now;
      rec.durationMs = (now >= rec.startedAtMs) ? (now - rec.startedAtMs) : 0;
      pendingConns_.push_back(rec);
    }
    activeConns_.clear();
  }

  if (writerThread_.joinable()) {
    writerThread_.request_stop();
    queueCv_.notify_all();
    writerThread_.join();
  }
  drainAndWriteBatch();
  db_.close();
}

void HistoryStore::setAlertCallback(AlertCallback cb) {
  std::lock_guard lock(cacheMutex_);
  alertCb_ = std::move(cb);
}

void HistoryStore::setNotificationCategories(const NotificationCategories& cats) {
  std::lock_guard lock(cacheMutex_);
  categories_ = cats;
}

bool HistoryStore::shouldNotifyKind(const std::string& kind) const {
  if (!alertsEnabled_.load()) return false;
  std::lock_guard lock(cacheMutex_);
  if (kind == "service_down" || kind == "service_up") return categories_.serviceDown;
  if (kind == "service_degraded") return categories_.serviceDegraded;
  if (kind == "sensitive_port") return categories_.sensitivePort;
  if (kind == "new_country") return categories_.newCountry;
  return true;
}

void HistoryStore::setRetentionConfig(int retentionDays, int maxDbSizeMb) {
  retentionDays_.store(std::clamp(retentionDays, 1, 365));
  maxDbSizeMb_.store(std::clamp(maxDbSizeMb, 32, 2048));
}

void HistoryStore::importLegacyTsvIfNeeded() {
  std::error_code ec;
  if (std::filesystem::exists(migrationMarkerPath_, ec)) return;
  if (!db_.isOpen()) return;

  bool hasEvents = false;
  bool hasMetrics = false;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt se(db, "SELECT 1 FROM events LIMIT 1;");
    hasEvents = (se.valid() && se.step() == SQLITE_ROW);
    SqliteStmt sm(db, "SELECT 1 FROM service_metrics LIMIT 1;");
    hasMetrics = (sm.valid() && sm.step() == SQLITE_ROW);
    return true;
  });

  if (!hasEvents && std::filesystem::exists(legacyEventsPath_, ec)) {
    std::ifstream in(legacyEventsPath_);
    if (in.is_open()) {
      db_.withTransaction([&](sqlite3* db) {
        SqliteStmt ins(db, "INSERT INTO events(ts_ms, severity, kind, title, detail) VALUES(?,?,?,?,?);");
        if (!ins.valid()) return false;
        std::string line;
        while (std::getline(in, line)) {
          if (line.empty()) continue;
          std::vector<std::string> cols;
          std::stringstream ss(line);
          std::string item;
          while (std::getline(ss, item, '\t')) cols.push_back(item);
          if (cols.size() < 5) continue;
          ins.reset();
          ins.bindInt64(1, static_cast<int64_t>(std::strtoull(cols[0].c_str(), nullptr, 10)));
          ins.bindText(2, cols[1]);
          ins.bindText(3, cols[2]);
          ins.bindText(4, cols[3]);
          ins.bindText(5, cols[4]);
          ins.stepDone();
        }
        return true;
      });
    }
  }

  if (!hasMetrics && std::filesystem::exists(legacyMetricsPath_, ec)) {
    std::ifstream in(legacyMetricsPath_);
    if (in.is_open()) {
      db_.withTransaction([&](sqlite3* db) {
        SqliteStmt ins(db, "INSERT INTO service_metrics(ts_ms, service_id, status, latency_ms) VALUES(?,?,?,?);");
        if (!ins.valid()) return false;
        std::string line;
        while (std::getline(in, line)) {
          if (line.empty()) continue;
          std::vector<std::string> cols;
          std::stringstream ss(line);
          std::string item;
          while (std::getline(ss, item, '\t')) cols.push_back(item);
          if (cols.size() < 4) continue;
          ins.reset();
          ins.bindInt64(1, static_cast<int64_t>(std::strtoull(cols[0].c_str(), nullptr, 10)));
          ins.bindText(2, cols[1]);
          ins.bindText(3, cols[2]);
          ins.bindDouble(4, std::strtod(cols[3].c_str(), nullptr));
          ins.stepDone();
        }
        return true;
      });
    }
  }

  std::ofstream marker(migrationMarkerPath_, std::ios::trunc);
  if (marker.is_open()) {
    marker << "imported_at_ms=" << nowEpochMs() << '\n';
  }
}

void HistoryStore::loadCachesFromDb() {
  if (!db_.isOpen()) return;
  const uint64_t cutoff = nowEpochMs() > (7ULL * kDayMs) ? (nowEpochMs() - 7ULL * kDayMs) : 0;

  db_.withLock([&](sqlite3* db) {
    {
      SqliteStmt st(db, "SELECT ts_ms, severity, kind, title, detail FROM events WHERE ts_ms >= ? ORDER BY ts_ms DESC, id DESC LIMIT 400;");
      if (st.valid()) {
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        std::lock_guard lock(cacheMutex_);
        events_.clear();
        while (st.step() == SQLITE_ROW) {
          events_.push_back(HistoryEvent{
              static_cast<uint64_t>(st.colInt64(0)),
              st.colText(1),
              st.colText(2),
              st.colText(3),
              st.colText(4),
          });
        }
      }
    }

    {
      SqliteStmt st(db, "SELECT ts_ms, service_id, status, latency_ms FROM service_metrics WHERE ts_ms >= ? ORDER BY ts_ms ASC;");
      if (st.valid()) {
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        std::lock_guard lock(cacheMutex_);
        serviceSeries_.clear();
        while (st.step() == SQLITE_ROW) {
          std::string sid = st.colText(1);
          auto& q = serviceSeries_[sid];
          q.push_back(ServiceMetricPoint{
              static_cast<uint64_t>(st.colInt64(0)),
              std::move(sid),
              st.colText(2),
              st.colDouble(3),
          });
          if (q.size() > 120) q.pop_front();
        }
      }
    }
    return true;
  });
}

void HistoryStore::enqueueEvent(HistoryEvent ev, bool notifyTray) {
  AlertCallback cb;
  {
    std::lock_guard lock(cacheMutex_);
    events_.push_front(ev);
    while (events_.size() > 400) events_.pop_back();
    cb = alertCb_;
  }
  {
    std::lock_guard lock(queueMutex_);
    pendingEvents_.push_back(ev);
  }
  queueCv_.notify_one();

  if (notifyTray && alertsEnabled_.load() && cb) {
    cb(ev.title, ev.detail, ev.severity != "info");
  }
}

void HistoryStore::processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns) {
  const uint64_t now = snap.timestampMs;
  const bool warmedUp = (now >= startupWarmupEndMs_);

  std::vector<HistoryEvent> pendingAlerts;
  std::vector<ConnectionHistoryRecord> toPersistConns;
  std::vector<RollupDelta> rollupDeltas;
  NicSampleDelta nicDelta{};

  const double dtSec = (prevTelemetryMs_ > 0 && now > prevTelemetryMs_)
                           ? std::clamp(static_cast<double>(now - prevTelemetryMs_) / 1000.0, 0.0, 10.0)
                           : 0.0;
  const uint64_t dtMs = (prevTelemetryMs_ > 0 && now > prevTelemetryMs_)
                            ? std::min<uint64_t>(now - prevTelemetryMs_, 10000ULL)
                            : 0ULL;
  prevTelemetryMs_ = now;

  nicDelta.bucketStartMs = floorBucket(now, kFiveMinMs);
  nicDelta.rxBytes = static_cast<uint64_t>(std::max(0.0, snap.nic.rxBytesPerSec * dtSec));
  nicDelta.txBytes = static_cast<uint64_t>(std::max(0.0, snap.nic.txBytesPerSec * dtSec));
  nicDelta.maxRxBps = snap.nic.rxBytesPerSec;
  nicDelta.maxTxBps = snap.nic.txBytesPerSec;
  nicDelta.connsSum = snap.totalConnections;
  nicDelta.sampleCount = 1;

  std::unordered_set<std::string> seenKeys;
  seenKeys.reserve(snap.connections.size());

  {
    std::lock_guard lock(cacheMutex_);
    if (alertCooldownMs_.size() > 512) {
      for (auto it = alertCooldownMs_.begin(); it != alertCooldownMs_.end();) {
        if (now > it->second && (now - it->second) > 300000) it = alertCooldownMs_.erase(it);
        else ++it;
      }
    }

    const uint64_t hourBucket = floorBucket(now, kHourMs);

    for (const auto& c : snap.connections) {
      if (c.lifecycle == Lifecycle::Closed) continue;
      seenKeys.insert(c.key);

      auto geoOpt = (c.scope == IpScope::Public) ? geoDns.getGeo(c.remoteIp) : std::nullopt;
      auto dnsOpt = (c.scope == IpScope::Public) ? geoDns.getHostname(c.remoteIp) : std::nullopt;

      if (c.scope == IpScope::Public && c.lifecycle == Lifecycle::New) {
        if (isSensitivePort(c.remotePort)) {
          std::string cdKey = "port:" + c.processName + ":" + c.remoteIp + ":" + std::to_string(c.remotePort);
          auto cdIt = alertCooldownMs_.find(cdKey);
          if (cdIt == alertCooldownMs_.end() || (now - cdIt->second) > 120000) {
            alertCooldownMs_[cdKey] = now;
            pendingAlerts.push_back(HistoryEvent{
                now,
                "warn",
                "sensitive_port",
                "Porta sensível detectada (" + std::to_string(c.remotePort) + ")",
                c.processName + " -> " + c.remoteIp + ":" + std::to_string(c.remotePort),
            });
          }
        }

        if (geoOpt.has_value() && !geoOpt->countryCode.empty()) {
          if (seenCountries_.insert(geoOpt->countryCode).second && warmedUp) {
            pendingAlerts.push_back(HistoryEvent{
                now,
                "info",
                "new_country",
                "Novo país acessado: " + geoOpt->country + " (" + geoOpt->countryCode + ")",
                c.processName + " conectou em " + (geoOpt->city.empty() ? geoOpt->country : geoOpt->city) + " (" + c.remoteIp + ")",
            });
          }
        }
      }

      auto it = activeConns_.find(c.key);
      if (it == activeConns_.end()) {
        ConnectionHistoryRecord rec;
        rec.connKey = c.key;
        rec.processName = c.processName;
        rec.pid = c.pid;
        rec.exePath = c.processPath;
        rec.localIp = c.localIp;
        rec.remoteIp = c.remoteIp;
        rec.localPort = c.localPort;
        rec.remotePort = c.remotePort;
        rec.protocol = c.protocol;
        rec.ipVersion = c.ipVersion;
        rec.state = c.state;
        rec.scope = scopeToString(c.scope);
        rec.startedAtMs = (c.firstSeenMs > 0) ? c.firstSeenMs : now;
        rec.endedAtMs = 0;
        rec.durationMs = 0;
        rec.lastCheckpointMs = now;
        if (geoOpt.has_value()) {
          rec.country = geoOpt->country;
          rec.countryCode = geoOpt->countryCode;
          rec.city = geoOpt->city;
          rec.asn = geoOpt->asn;
          rec.isp = geoOpt->isp;
        }
        if (dnsOpt.has_value()) {
          rec.dnsName = *dnsOpt;
        }
        if (c.scope == IpScope::Public) {
          rec.countedInRollup = true;
          rollupDeltas.push_back(RollupDelta{
              hourBucket,
              rec.processName,
              rec.remoteIp,
              rec.country,
              rec.countryCode,
              0,
              0,
              1,
              0,
          });
        }
        activeConns_[c.key] = std::move(rec);
      } else {
        auto& rec = it->second;
        rec.state = c.state;
        if (rec.exePath.empty() && !c.processPath.empty()) rec.exePath = c.processPath;
        if (geoOpt.has_value()) {
          if (rec.country.empty()) rec.country = geoOpt->country;
          if (rec.countryCode.empty()) rec.countryCode = geoOpt->countryCode;
          if (rec.city.empty()) rec.city = geoOpt->city;
          if (rec.asn.empty()) rec.asn = geoOpt->asn;
          if (rec.isp.empty()) rec.isp = geoOpt->isp;
        }
        if (rec.dnsName.empty() && dnsOpt.has_value()) {
          rec.dnsName = *dnsOpt;
        }

        const uint64_t addRx = static_cast<uint64_t>(std::max(0.0, c.rxBps * dtSec));
        const uint64_t addTx = static_cast<uint64_t>(std::max(0.0, c.txBps * dtSec));
        rec.rxBytes += addRx;
        rec.txBytes += addTx;
        rec.durationMs = (now >= rec.startedAtMs) ? (now - rec.startedAtMs) : rec.durationMs;

        if (c.scope == IpScope::Public && (addRx > 0 || addTx > 0 || dtMs > 0)) {
          rollupDeltas.push_back(RollupDelta{
              hourBucket,
              rec.processName,
              rec.remoteIp,
              rec.country,
              rec.countryCode,
              addRx,
              addTx,
              rec.countedInRollup ? 0ULL : 1ULL,
              dtMs,
          });
          rec.countedInRollup = true;
        }

        if (now > rec.lastCheckpointMs && (now - rec.lastCheckpointMs) >= 30000) {
          rec.lastCheckpointMs = now;
          toPersistConns.push_back(rec);
        }
      }
    }

    for (auto it = activeConns_.begin(); it != activeConns_.end();) {
      if (seenKeys.find(it->first) == seenKeys.end()) {
        it->second.endedAtMs = now;
        it->second.durationMs = (now >= it->second.startedAtMs) ? (now - it->second.startedAtMs) : 0;
        toPersistConns.push_back(std::move(it->second));
        it = activeConns_.erase(it);
      } else {
        ++it;
      }
    }
  }

  for (auto& ev : pendingAlerts) {
    const bool notify = shouldNotifyKind(ev.kind);
    enqueueEvent(std::move(ev), notify);
  }

  if (!toPersistConns.empty() || !rollupDeltas.empty() || nicDelta.sampleCount > 0) {
    std::lock_guard qLock(queueMutex_);
    for (auto& c : toPersistConns) {
      pendingConns_.push_back(std::move(c));
    }
    for (auto& rd : rollupDeltas) {
      std::string rKey = std::to_string(rd.bucketStartMs) + "|" + rd.processName + "|" + rd.remoteIp;
      auto& acc = pendingRollups_[rKey];
      acc.bucketStartMs = rd.bucketStartMs;
      acc.processName = rd.processName;
      acc.remoteIp = rd.remoteIp;
      if (acc.country.empty()) acc.country = rd.country;
      if (acc.countryCode.empty()) acc.countryCode = rd.countryCode;
      acc.rxBytes += rd.rxBytes;
      acc.txBytes += rd.txBytes;
      acc.connCount += rd.connCount;
      acc.totalDurationMs += rd.totalDurationMs;
    }
    auto& ns = pendingNicSamples_[nicDelta.bucketStartMs];
    ns.bucketStartMs = nicDelta.bucketStartMs;
    ns.rxBytes += nicDelta.rxBytes;
    ns.txBytes += nicDelta.txBytes;
    ns.maxRxBps = std::max(ns.maxRxBps, nicDelta.maxRxBps);
    ns.maxTxBps = std::max(ns.maxTxBps, nicDelta.maxTxBps);
    ns.connsSum += nicDelta.connsSum;
    ns.sampleCount += nicDelta.sampleCount;

    if (pendingConns_.size() >= 128) {
      queueCv_.notify_one();
    }
  }
}

void HistoryStore::processServices(const std::vector<ServiceStatus>& services) {
  const uint64_t now = nowEpochMs();
  std::vector<HistoryEvent> transitions;
  std::vector<ServiceMetricPoint> samples;

  for (const auto& s : services) {
    if (s.checksTotal == 0 || s.lastCheckedMs == 0) continue;

    bool shouldSample = false;
    {
      std::lock_guard lock(cacheMutex_);
      auto prevSampleIt = prevServiceSampleMs_.find(s.target.id);
      if (prevSampleIt == prevServiceSampleMs_.end() || s.lastCheckedMs > prevSampleIt->second) {
        prevServiceSampleMs_[s.target.id] = s.lastCheckedMs;
        shouldSample = true;
      }

      auto prevStIt = prevServiceStatus_.find(s.target.id);
      if (prevStIt == prevServiceStatus_.end()) {
        prevServiceStatus_[s.target.id] = s.status;
      } else if (prevStIt->second != s.status) {
        std::string oldSt = prevStIt->second;
        prevStIt->second = s.status;
        if (s.status == "down") {
          transitions.push_back(HistoryEvent{
              now,
              "critical",
              "service_down",
              "Serviço offline: " + s.target.name,
              s.target.host + ":" + std::to_string(s.target.port) + " (" + (s.lastError.empty() ? "sem resposta" : s.lastError) + ")",
          });
        } else if (s.status == "degraded" && oldSt == "up") {
          transitions.push_back(HistoryEvent{
              now,
              "warn",
              "service_degraded",
              "Latência elevada: " + s.target.name,
              std::to_string(static_cast<int>(s.latencyMs)) + " ms em " + s.target.host,
          });
        } else if (s.status == "up" && oldSt == "down") {
          transitions.push_back(HistoryEvent{
              now,
              "info",
              "service_up",
              "Serviço restabelecido: " + s.target.name,
              std::to_string(static_cast<int>(s.latencyMs)) + " ms",
          });
        }
      }

      if (shouldSample) {
        ServiceMetricPoint pt{s.lastCheckedMs, s.target.id, s.status, s.latencyMs};
        auto& q = serviceSeries_[pt.serviceId];
        q.push_back(pt);
        while (q.size() > 120) q.pop_front();
        samples.push_back(std::move(pt));
      }
    }
  }

  if (!samples.empty()) {
    std::lock_guard qLock(queueMutex_);
    for (auto& pt : samples) pendingMetrics_.push_back(std::move(pt));
  }

  for (auto& ev : transitions) {
    const bool notify = shouldNotifyKind(ev.kind);
    enqueueEvent(std::move(ev), notify);
  }
}

void HistoryStore::recordManualAction(const std::string& severity,
                                      const std::string& title,
                                      const std::string& detail) {
  enqueueEvent(HistoryEvent{nowEpochMs(), severity, "action", title, detail}, false);
}

void HistoryStore::enqueueQualitySample(const QualitySampleRecord& sample) {
  std::lock_guard lock(queueMutex_);
  pendingQualitySamples_.push_back(sample);
  if (pendingQualitySamples_.size() >= 32) {
    queueCv_.notify_one();
  }
}

void HistoryStore::enqueueInterfaceSamples(const std::vector<InterfaceSampleRecord>& samples) {
  if (samples.empty()) return;
  std::lock_guard lock(queueMutex_);
  for (const auto& s : samples) pendingInterfaceSamples_.push_back(s);
  if (pendingInterfaceSamples_.size() >= 32) {
    queueCv_.notify_one();
  }
}

void HistoryStore::writerLoop(std::stop_token st) {
  while (!st.stop_requested()) {
    {
      std::unique_lock lock(queueMutex_);
      queueCv_.wait_for(lock, st, std::chrono::milliseconds(2000), [this]() {
        return pendingEvents_.size() >= 32 ||
               pendingConns_.size() >= 128 ||
               pendingMetrics_.size() >= 32 ||
               pendingQualitySamples_.size() >= 32 ||
               pendingInterfaceSamples_.size() >= 32 ||
               pruneRequested_.load();
      });
    }
    drainAndWriteBatch();

    const uint64_t now = nowEpochMs();
    if (pruneRequested_.exchange(false) || (now - lastPruneMs_.load()) >= 600000ULL) {
      pruneNow();
    }
  }
}

void HistoryStore::drainAndWriteBatch() {
  std::vector<HistoryEvent> evs;
  std::vector<ServiceMetricPoint> mets;
  std::vector<ConnectionHistoryRecord> conns;
  std::vector<QualitySampleRecord> qsamples;
  std::vector<InterfaceSampleRecord> ifsamples;
  std::unordered_map<std::string, RollupDelta> rollups;
  std::unordered_map<uint64_t, NicSampleDelta> nics;

  {
    std::lock_guard lock(queueMutex_);
    if (pendingEvents_.empty() && pendingMetrics_.empty() && pendingConns_.empty() &&
        pendingQualitySamples_.empty() && pendingInterfaceSamples_.empty() &&
        pendingRollups_.empty() && pendingNicSamples_.empty()) {
      return;
    }
    evs.swap(pendingEvents_);
    mets.swap(pendingMetrics_);
    conns.swap(pendingConns_);
    qsamples.swap(pendingQualitySamples_);
    ifsamples.swap(pendingInterfaceSamples_);
    rollups.swap(pendingRollups_);
    nics.swap(pendingNicSamples_);
  }

  if (!db_.isOpen()) return;

  db_.withTransaction([&](sqlite3* db) {
    if (!evs.empty()) {
      SqliteStmt insEv(db, "INSERT INTO events(ts_ms, severity, kind, title, detail) VALUES(?,?,?,?,?);");
      for (const auto& e : evs) {
        insEv.reset();
        insEv.bindInt64(1, static_cast<int64_t>(e.tsMs));
        insEv.bindText(2, e.severity);
        insEv.bindText(3, e.kind);
        insEv.bindText(4, e.title);
        insEv.bindText(5, e.detail);
        insEv.stepDone();
      }
    }

    if (!mets.empty()) {
      SqliteStmt insMet(db, "INSERT INTO service_metrics(ts_ms, service_id, status, latency_ms) VALUES(?,?,?,?);");
      for (const auto& m : mets) {
        insMet.reset();
        insMet.bindInt64(1, static_cast<int64_t>(m.tsMs));
        insMet.bindText(2, m.serviceId);
        insMet.bindText(3, m.status);
        insMet.bindDouble(4, m.latencyMs);
        insMet.stepDone();
      }
    }

    if (!conns.empty()) {
      SqliteStmt upConn(
          db,
          "INSERT INTO connection_history("
          "  conn_key, process_name, pid, exe_path, local_ip, remote_ip, local_port, remote_port,"
          "  protocol, ip_version, state, scope, started_at_ms, ended_at_ms, duration_ms,"
          "  country, country_code, city, asn, isp, dns_name, rx_bytes, tx_bytes"
          ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
          "ON CONFLICT(conn_key, started_at_ms) DO UPDATE SET "
          "  exe_path=CASE WHEN excluded.exe_path<>'' THEN excluded.exe_path ELSE connection_history.exe_path END,"
          "  state=excluded.state,"
          "  ended_at_ms=MAX(connection_history.ended_at_ms, excluded.ended_at_ms),"
          "  duration_ms=MAX(connection_history.duration_ms, excluded.duration_ms),"
          "  country=CASE WHEN excluded.country<>'' THEN excluded.country ELSE connection_history.country END,"
          "  country_code=CASE WHEN excluded.country_code<>'' THEN excluded.country_code ELSE connection_history.country_code END,"
          "  city=CASE WHEN excluded.city<>'' THEN excluded.city ELSE connection_history.city END,"
          "  asn=CASE WHEN excluded.asn<>'' THEN excluded.asn ELSE connection_history.asn END,"
          "  isp=CASE WHEN excluded.isp<>'' THEN excluded.isp ELSE connection_history.isp END,"
          "  dns_name=CASE WHEN excluded.dns_name<>'' THEN excluded.dns_name ELSE connection_history.dns_name END,"
          "  rx_bytes=MAX(connection_history.rx_bytes, excluded.rx_bytes),"
          "  tx_bytes=MAX(connection_history.tx_bytes, excluded.tx_bytes);");
      for (const auto& c : conns) {
        upConn.reset();
        upConn.bindText(1, c.connKey);
        upConn.bindText(2, c.processName);
        upConn.bindInt64(3, static_cast<int64_t>(c.pid));
        upConn.bindText(4, c.exePath);
        upConn.bindText(5, c.localIp);
        upConn.bindText(6, c.remoteIp);
        upConn.bindInt64(7, static_cast<int64_t>(c.localPort));
        upConn.bindInt64(8, static_cast<int64_t>(c.remotePort));
        upConn.bindText(9, c.protocol);
        upConn.bindInt64(10, static_cast<int64_t>(c.ipVersion));
        upConn.bindText(11, c.state);
        upConn.bindText(12, c.scope);
        upConn.bindInt64(13, static_cast<int64_t>(c.startedAtMs));
        upConn.bindInt64(14, static_cast<int64_t>(c.endedAtMs));
        upConn.bindInt64(15, static_cast<int64_t>(c.durationMs));
        upConn.bindText(16, c.country);
        upConn.bindText(17, c.countryCode);
        upConn.bindText(18, c.city);
        upConn.bindText(19, c.asn);
        upConn.bindText(20, c.isp);
        upConn.bindText(21, c.dnsName);
        upConn.bindInt64(22, static_cast<int64_t>(c.rxBytes));
        upConn.bindInt64(23, static_cast<int64_t>(c.txBytes));
        upConn.stepDone();
      }
    }

    if (!rollups.empty()) {
      SqliteStmt upRoll(
          db,
          "INSERT INTO traffic_rollups("
          "  bucket_start_ms, process_name, remote_ip, country, country_code, rx_bytes, tx_bytes, conn_count, total_duration_ms"
          ") VALUES(?,?,?,?,?,?,?,?,?) "
          "ON CONFLICT(bucket_start_ms, process_name, remote_ip) DO UPDATE SET "
          "  country=CASE WHEN excluded.country<>'' THEN excluded.country ELSE traffic_rollups.country END,"
          "  country_code=CASE WHEN excluded.country_code<>'' THEN excluded.country_code ELSE traffic_rollups.country_code END,"
          "  rx_bytes=traffic_rollups.rx_bytes + excluded.rx_bytes,"
          "  tx_bytes=traffic_rollups.tx_bytes + excluded.tx_bytes,"
          "  conn_count=traffic_rollups.conn_count + excluded.conn_count,"
          "  total_duration_ms=traffic_rollups.total_duration_ms + excluded.total_duration_ms;");
      for (const auto& [k, r] : rollups) {
        (void)k;
        upRoll.reset();
        upRoll.bindInt64(1, static_cast<int64_t>(r.bucketStartMs));
        upRoll.bindText(2, r.processName);
        upRoll.bindText(3, r.remoteIp);
        upRoll.bindText(4, r.country);
        upRoll.bindText(5, r.countryCode);
        upRoll.bindInt64(6, static_cast<int64_t>(r.rxBytes));
        upRoll.bindInt64(7, static_cast<int64_t>(r.txBytes));
        upRoll.bindInt64(8, static_cast<int64_t>(r.connCount));
        upRoll.bindInt64(9, static_cast<int64_t>(r.totalDurationMs));
        upRoll.stepDone();
      }
    }

    if (!nics.empty()) {
      SqliteStmt upNic(
          db,
          "INSERT INTO nic_traffic_samples(bucket_start_ms, rx_bytes, tx_bytes, max_rx_bps, max_tx_bps, avg_conns, sample_count) "
          "VALUES(?,?,?,?,?,?,?) "
          "ON CONFLICT(bucket_start_ms) DO UPDATE SET "
          "  rx_bytes=nic_traffic_samples.rx_bytes + excluded.rx_bytes,"
          "  tx_bytes=nic_traffic_samples.tx_bytes + excluded.tx_bytes,"
          "  max_rx_bps=MAX(nic_traffic_samples.max_rx_bps, excluded.max_rx_bps),"
          "  max_tx_bps=MAX(nic_traffic_samples.max_tx_bps, excluded.max_tx_bps),"
          "  avg_conns=((nic_traffic_samples.avg_conns * nic_traffic_samples.sample_count) + (excluded.avg_conns * excluded.sample_count)) / (nic_traffic_samples.sample_count + excluded.sample_count),"
          "  sample_count=nic_traffic_samples.sample_count + excluded.sample_count;");
      for (const auto& [bucket, ns] : nics) {
        (void)bucket;
        double avgC = (ns.sampleCount > 0) ? (static_cast<double>(ns.connsSum) / static_cast<double>(ns.sampleCount)) : 0.0;
        upNic.reset();
        upNic.bindInt64(1, static_cast<int64_t>(ns.bucketStartMs));
        upNic.bindInt64(2, static_cast<int64_t>(ns.rxBytes));
        upNic.bindInt64(3, static_cast<int64_t>(ns.txBytes));
        upNic.bindDouble(4, ns.maxRxBps);
        upNic.bindDouble(5, ns.maxTxBps);
        upNic.bindDouble(6, avgC);
        upNic.bindInt64(7, static_cast<int64_t>(ns.sampleCount));
        upNic.stepDone();
      }
    }

    if (!qsamples.empty()) {
      SqliteStmt insQs(
          db,
          "INSERT INTO quality_samples(ts_ms, target_id, ok, rtt_ms, dns_ms, jitter_ms, method, error) "
          "VALUES(?,?,?,?,?,?,?,?);");
      for (const auto& qs : qsamples) {
        insQs.reset();
        insQs.bindInt64(1, static_cast<int64_t>(qs.tsMs));
        insQs.bindText(2, qs.targetId);
        insQs.bindInt64(3, qs.ok ? 1 : 0);
        insQs.bindDouble(4, qs.rttMs);
        insQs.bindDouble(5, qs.dnsMs);
        insQs.bindDouble(6, qs.jitterMs);
        insQs.bindText(7, qs.method);
        insQs.bindText(8, qs.error);
        insQs.stepDone();
      }
    }

    if (!ifsamples.empty()) {
      SqliteStmt insIf(
          db,
          "INSERT INTO interface_samples(ts_ms, if_id, if_name, if_type, oper_status, is_default_route, link_speed_bps, rx_bps, tx_bps, rx_bytes, tx_bytes, rx_errors, tx_errors) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);");
      for (const auto& is : ifsamples) {
        insIf.reset();
        insIf.bindInt64(1, static_cast<int64_t>(is.tsMs));
        insIf.bindText(2, is.ifId);
        insIf.bindText(3, is.ifName);
        insIf.bindText(4, is.ifType);
        insIf.bindText(5, is.operStatus);
        insIf.bindInt64(6, is.isDefaultRoute ? 1 : 0);
        insIf.bindInt64(7, static_cast<int64_t>(is.linkSpeedBps));
        insIf.bindDouble(8, is.rxBps);
        insIf.bindDouble(9, is.txBps);
        insIf.bindInt64(10, static_cast<int64_t>(is.rxBytes));
        insIf.bindInt64(11, static_cast<int64_t>(is.txBytes));
        insIf.bindInt64(12, static_cast<int64_t>(is.rxErrors));
        insIf.bindInt64(13, static_cast<int64_t>(is.txErrors));
        insIf.stepDone();
      }
    }
    return true;
  });
}

void HistoryStore::flushNow() {
  const uint64_t now = nowEpochMs();
  {
    std::lock_guard cLock(cacheMutex_);
    std::lock_guard qLock(queueMutex_);
    for (auto& [k, rec] : activeConns_) {
      rec.durationMs = (now >= rec.startedAtMs) ? (now - rec.startedAtMs) : rec.durationMs;
      pendingConns_.push_back(rec);
    }
  }
  drainAndWriteBatch();
}

bool HistoryStore::applyRetentionLocked(sqlite3* db) {
  const uint64_t now = nowEpochMs();
  const uint64_t retMs = static_cast<uint64_t>(retentionDays_.load()) * kDayMs;
  const uint64_t cutoff = (now > retMs) ? (now - retMs) : 0ULL;

  auto delBefore = [&](const char* sql) {
    SqliteStmt st(db, sql);
    if (st.valid()) {
      st.bindInt64(1, static_cast<int64_t>(cutoff));
      st.stepDone();
    }
  };
  delBefore("DELETE FROM events WHERE ts_ms < ?;");
  delBefore("DELETE FROM service_metrics WHERE ts_ms < ?;");
  delBefore("DELETE FROM connection_history WHERE started_at_ms < ?;");
  delBefore("DELETE FROM traffic_rollups WHERE bucket_start_ms < ?;");
  delBefore("DELETE FROM nic_traffic_samples WHERE bucket_start_ms < ?;");
  delBefore("DELETE FROM quality_samples WHERE ts_ms < ?;");
  delBefore("DELETE FROM interface_samples WHERE ts_ms < ?;");
  delBefore("DELETE FROM trace_runs WHERE started_at_ms < ?;");
  delBefore("DELETE FROM security_alerts WHERE ts_ms < ?;");
  delBefore("DELETE FROM lan_devices WHERE online = 0 AND custom_label = '' AND last_seen_ms < ?;");
  {
    SqliteStmt st(db, "DELETE FROM trace_hops WHERE run_id NOT IN (SELECT id FROM trace_runs);");
    if (st.valid()) st.stepDone();
  }
  return true;
}

bool HistoryStore::pruneNow() {
  lastPruneMs_.store(nowEpochMs());
  if (!db_.isOpen()) return false;

  bool ok = db_.withTransaction([&](sqlite3* db) {
    return applyRetentionLocked(db);
  });

  const uint64_t maxBytes = static_cast<uint64_t>(maxDbSizeMb_.load()) * 1024ULL * 1024ULL;
  if (ok && db_.fileSizeBytes() > maxBytes) {
    db_.withTransaction([&](sqlite3* db) {
      SqliteStmt delConn(db, "DELETE FROM connection_history WHERE id IN (SELECT id FROM connection_history ORDER BY started_at_ms ASC LIMIT 5000);");
      if (delConn.valid()) delConn.stepDone();
      SqliteStmt delMet(db, "DELETE FROM service_metrics WHERE id IN (SELECT id FROM service_metrics ORDER BY ts_ms ASC LIMIT 5000);");
      if (delMet.valid()) delMet.stepDone();
      SqliteStmt delQs(db, "DELETE FROM quality_samples WHERE id IN (SELECT id FROM quality_samples ORDER BY ts_ms ASC LIMIT 5000);");
      if (delQs.valid()) delQs.stepDone();
      SqliteStmt delIf(db, "DELETE FROM interface_samples WHERE id IN (SELECT id FROM interface_samples ORDER BY ts_ms ASC LIMIT 5000);");
      if (delIf.valid()) delIf.stepDone();
      return true;
    });
  }

  std::string err;
  db_.checkpointAndVacuum(err);
  loadCachesFromDb();
  return ok;
}

std::string HistoryStore::getEventsJson(size_t maxItems,
                                        size_t offset,
                                        const std::string& severityFilter,
                                        const std::string& kindFilter) const {
  if (offset == 0 && severityFilter.empty() && kindFilter.empty()) {
    std::lock_guard lock(cacheMutex_);
    std::string out = "{\"alertsEnabled\":";
    out += (alertsEnabled_.load() ? "true" : "false");
    out += ",\"total\":";
    out += std::to_string(events_.size());
    out += ",\"events\":[";

    const size_t count = std::min(maxItems, events_.size());
    for (size_t i = 0; i < count; ++i) {
      const auto& e = events_[i];
      if (i > 0) out.push_back(',');
      out += "{\"ts\":";
      out += std::to_string(e.tsMs);
      out += ",\"sev\":";
      appendJsonEscaped(out, e.severity);
      out += ",\"kind\":";
      appendJsonEscaped(out, e.kind);
      out += ",\"title\":";
      appendJsonEscaped(out, e.title);
      out += ",\"detail\":";
      appendJsonEscaped(out, e.detail);
      out.push_back('}');
    }
    out += "]}";
    return out;
  }

  std::string out = "{\"alertsEnabled\":";
  out += (alertsEnabled_.load() ? "true" : "false");
  size_t total = 0;
  std::vector<HistoryEvent> rows;

  if (db_.isOpen()) {
    db_.withLock([&](sqlite3* db) {
      std::string where = " WHERE 1=1";
      if (!severityFilter.empty()) where += " AND severity = ?";
      if (!kindFilter.empty()) where += " AND kind = ?";

      std::string cntSql = "SELECT COUNT(*) FROM events" + where + ";";
      SqliteStmt cnt(db, cntSql.c_str());
      int idx = 1;
      if (!severityFilter.empty()) cnt.bindText(idx++, severityFilter);
      if (!kindFilter.empty()) cnt.bindText(idx++, kindFilter);
      if (cnt.valid() && cnt.step() == SQLITE_ROW) {
        total = static_cast<size_t>(cnt.colInt64(0));
      }

      std::string selSql = "SELECT ts_ms, severity, kind, title, detail FROM events" + where + " ORDER BY ts_ms DESC, id DESC LIMIT ? OFFSET ?;";
      SqliteStmt sel(db, selSql.c_str());
      idx = 1;
      if (!severityFilter.empty()) sel.bindText(idx++, severityFilter);
      if (!kindFilter.empty()) sel.bindText(idx++, kindFilter);
      sel.bindInt64(idx++, static_cast<int64_t>(std::clamp<size_t>(maxItems, 1, 500)));
      sel.bindInt64(idx++, static_cast<int64_t>(offset));
      while (sel.valid() && sel.step() == SQLITE_ROW) {
        rows.push_back(HistoryEvent{
            static_cast<uint64_t>(sel.colInt64(0)),
            sel.colText(1),
            sel.colText(2),
            sel.colText(3),
            sel.colText(4),
        });
      }
      return true;
    });
  }

  out += ",\"total\":";
  out += std::to_string(total);
  out += ",\"events\":[";
  for (size_t i = 0; i < rows.size(); ++i) {
    const auto& e = rows[i];
    if (i > 0) out.push_back(',');
    out += "{\"ts\":";
    out += std::to_string(e.tsMs);
    out += ",\"sev\":";
    appendJsonEscaped(out, e.severity);
    out += ",\"kind\":";
    appendJsonEscaped(out, e.kind);
    out += ",\"title\":";
    appendJsonEscaped(out, e.title);
    out += ",\"detail\":";
    appendJsonEscaped(out, e.detail);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

std::string HistoryStore::getServiceHistoryJson(const std::string& serviceId, size_t maxPoints) const {
  std::lock_guard lock(cacheMutex_);
  std::string out = "{\"serviceId\":";
  appendJsonEscaped(out, serviceId);
  out += ",\"points\":[";

  auto it = serviceSeries_.find(serviceId);
  if (it != serviceSeries_.end() && !it->second.empty()) {
    const auto& q = it->second;
    const size_t start = (q.size() > maxPoints) ? (q.size() - maxPoints) : 0;
    char numBuf[32];
    for (size_t i = start; i < q.size(); ++i) {
      if (i > start) out.push_back(',');
      out += "{\"ts\":";
      out += std::to_string(q[i].tsMs);
      out += ",\"status\":";
      appendJsonEscaped(out, q[i].status);
      std::snprintf(numBuf, sizeof(numBuf), "%.1f", q[i].latencyMs);
      out += ",\"ms\":";
      out += numBuf;
      out.push_back('}');
    }
  }
  out += "]}";
  return out;
}

std::string HistoryStore::queryConnectionsJson(const ConnectionQuery& q) {
  drainAndWriteBatch();
  const size_t lim = std::clamp<size_t>(q.limit, 1, 250);
  const size_t off = q.offset;

  size_t total = 0;
  std::string itemsJson;
  itemsJson.reserve(lim * 256);

  if (db_.isOpen()) {
    db_.withLock([&](sqlite3* db) {
      std::string where = " WHERE 1=1";
      enum class BindKind { Text, Int64 };
      struct BindParam {
        BindKind kind;
        std::string str;
        int64_t num = 0;
      };
      std::vector<BindParam> params;

      if (!q.process.empty()) {
        where += " AND LOWER(process_name) LIKE LOWER(?)";
        params.push_back({BindKind::Text, "%" + q.process + "%", 0});
      }
      if (!q.remoteIp.empty()) {
        where += " AND remote_ip = ?";
        params.push_back({BindKind::Text, q.remoteIp, 0});
      }
      if (!q.country.empty()) {
        where += " AND (LOWER(country) LIKE LOWER(?) OR LOWER(country_code) = LOWER(?))";
        params.push_back({BindKind::Text, "%" + q.country + "%", 0});
        params.push_back({BindKind::Text, q.country, 0});
      }
      if (!q.protocol.empty()) {
        where += " AND LOWER(protocol) = LOWER(?)";
        params.push_back({BindKind::Text, q.protocol, 0});
      }
      if (!q.scope.empty()) {
        where += " AND LOWER(scope) = LOWER(?)";
        params.push_back({BindKind::Text, q.scope, 0});
      }
      if (q.fromMs > 0) {
        where += " AND started_at_ms >= ?";
        params.push_back({BindKind::Int64, {}, static_cast<int64_t>(q.fromMs)});
      }
      if (q.toMs > 0) {
        where += " AND started_at_ms <= ?";
        params.push_back({BindKind::Int64, {}, static_cast<int64_t>(q.toMs)});
      }
      if (!q.search.empty()) {
        where += " AND (LOWER(process_name) LIKE LOWER(?) OR remote_ip LIKE ? OR LOWER(dns_name) LIKE LOWER(?) OR LOWER(country) LIKE LOWER(?) OR CAST(remote_port AS TEXT) = ?)";
        std::string pat = "%" + q.search + "%";
        params.push_back({BindKind::Text, pat, 0});
        params.push_back({BindKind::Text, pat, 0});
        params.push_back({BindKind::Text, pat, 0});
        params.push_back({BindKind::Text, pat, 0});
        params.push_back({BindKind::Text, q.search, 0});
      }

      auto bindAll = [&](SqliteStmt& st, int startIdx) {
        int idx = startIdx;
        for (const auto& p : params) {
          if (p.kind == BindKind::Text) st.bindText(idx++, p.str);
          else st.bindInt64(idx++, p.num);
        }
        return idx;
      };

      std::string cntSql = "SELECT COUNT(*) FROM connection_history" + where + ";";
      SqliteStmt cnt(db, cntSql.c_str());
      bindAll(cnt, 1);
      if (cnt.valid() && cnt.step() == SQLITE_ROW) {
        total = static_cast<size_t>(cnt.colInt64(0));
      }

      std::string selSql =
          "SELECT conn_key, process_name, pid, exe_path, local_ip, remote_ip, local_port, remote_port,"
          " protocol, ip_version, state, scope, started_at_ms, ended_at_ms, duration_ms,"
          " country, country_code, city, asn, isp, dns_name, rx_bytes, tx_bytes "
          "FROM connection_history" + where + " ORDER BY started_at_ms DESC, id DESC LIMIT ? OFFSET ?;";
      SqliteStmt sel(db, selSql.c_str());
      int nextIdx = bindAll(sel, 1);
      sel.bindInt64(nextIdx++, static_cast<int64_t>(lim));
      sel.bindInt64(nextIdx++, static_cast<int64_t>(off));

      bool first = true;
      while (sel.valid() && sel.step() == SQLITE_ROW) {
        if (!first) itemsJson.push_back(',');
        first = false;
        itemsJson += "{\"key\":";
        appendJsonEscaped(itemsJson, sel.colText(0));
        itemsJson += ",\"process\":";
        appendJsonEscaped(itemsJson, sel.colText(1));
        itemsJson += ",\"pid\":";
        itemsJson += std::to_string(sel.colInt64(2));
        itemsJson += ",\"exePath\":";
        appendJsonEscaped(itemsJson, sel.colText(3));
        itemsJson += ",\"localIp\":";
        appendJsonEscaped(itemsJson, sel.colText(4));
        itemsJson += ",\"remoteIp\":";
        appendJsonEscaped(itemsJson, sel.colText(5));
        itemsJson += ",\"localPort\":";
        itemsJson += std::to_string(sel.colInt64(6));
        itemsJson += ",\"remotePort\":";
        itemsJson += std::to_string(sel.colInt64(7));
        itemsJson += ",\"protocol\":";
        appendJsonEscaped(itemsJson, sel.colText(8));
        itemsJson += ",\"ipVersion\":";
        itemsJson += std::to_string(sel.colInt64(9));
        itemsJson += ",\"state\":";
        appendJsonEscaped(itemsJson, sel.colText(10));
        itemsJson += ",\"scope\":";
        appendJsonEscaped(itemsJson, sel.colText(11));
        itemsJson += ",\"startedAt\":";
        itemsJson += std::to_string(sel.colInt64(12));
        itemsJson += ",\"endedAt\":";
        itemsJson += std::to_string(sel.colInt64(13));
        itemsJson += ",\"durationMs\":";
        itemsJson += std::to_string(sel.colInt64(14));
        itemsJson += ",\"country\":";
        appendJsonEscaped(itemsJson, sel.colText(15));
        itemsJson += ",\"cc\":";
        appendJsonEscaped(itemsJson, sel.colText(16));
        itemsJson += ",\"city\":";
        appendJsonEscaped(itemsJson, sel.colText(17));
        itemsJson += ",\"asn\":";
        appendJsonEscaped(itemsJson, sel.colText(18));
        itemsJson += ",\"isp\":";
        appendJsonEscaped(itemsJson, sel.colText(19));
        itemsJson += ",\"dns\":";
        appendJsonEscaped(itemsJson, sel.colText(20));
        itemsJson += ",\"rxBytes\":";
        itemsJson += std::to_string(sel.colInt64(21));
        itemsJson += ",\"txBytes\":";
        itemsJson += std::to_string(sel.colInt64(22));
        itemsJson.push_back('}');
      }
      return true;
    });
  }

  std::string out = "{\"total\":";
  out += std::to_string(total);
  out += ",\"limit\":";
  out += std::to_string(lim);
  out += ",\"offset\":";
  out += std::to_string(off);
  out += ",\"items\":[";
  out += itemsJson;
  out += "]}";
  return out;
}

std::string HistoryStore::queryProcessesJson(const std::string& range,
                                             size_t limit,
                                             size_t offset,
                                             const std::string& procFilter) {
  drainAndWriteBatch();
  const uint64_t now = nowEpochMs();
  const uint64_t dur = rangeToDurationMs(range);
  const uint64_t cutoff = (now > dur) ? (now - dur) : 0ULL;
  const size_t lim = std::clamp<size_t>(limit, 1, 200);

  std::string itemsJson;
  size_t total = 0;

  if (db_.isOpen()) {
    db_.withLock([&](sqlite3* db) {
      std::string where = " WHERE started_at_ms >= ?";
      if (!procFilter.empty()) where += " AND LOWER(process_name) LIKE LOWER(?)";

      std::string cntSql = "SELECT COUNT(DISTINCT process_name) FROM connection_history" + where + ";";
      SqliteStmt cnt(db, cntSql.c_str());
      cnt.bindInt64(1, static_cast<int64_t>(cutoff));
      if (!procFilter.empty()) cnt.bindText(2, "%" + procFilter + "%");
      if (cnt.valid() && cnt.step() == SQLITE_ROW) {
        total = static_cast<size_t>(cnt.colInt64(0));
      }

      std::string sql =
          "SELECT process_name, MAX(exe_path), COUNT(*), COUNT(DISTINCT remote_ip),"
          " COUNT(DISTINCT CASE WHEN country_code<>'' THEN country_code END),"
          " COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0),"
          " COALESCE(AVG(duration_ms),0), MAX(started_at_ms) "
          "FROM connection_history" + where +
          " GROUP BY process_name ORDER BY (COALESCE(SUM(rx_bytes),0)+COALESCE(SUM(tx_bytes),0)) DESC, COUNT(*) DESC "
          "LIMIT ? OFFSET ?;";
      SqliteStmt st(db, sql.c_str());
      int idx = 1;
      st.bindInt64(idx++, static_cast<int64_t>(cutoff));
      if (!procFilter.empty()) st.bindText(idx++, "%" + procFilter + "%");
      st.bindInt64(idx++, static_cast<int64_t>(lim));
      st.bindInt64(idx++, static_cast<int64_t>(offset));

      bool first = true;
      char numBuf[32];
      while (st.valid() && st.step() == SQLITE_ROW) {
        if (!first) itemsJson.push_back(',');
        first = false;
        itemsJson += "{\"process\":";
        appendJsonEscaped(itemsJson, st.colText(0));
        itemsJson += ",\"exePath\":";
        appendJsonEscaped(itemsJson, st.colText(1));
        itemsJson += ",\"connections\":";
        itemsJson += std::to_string(st.colInt64(2));
        itemsJson += ",\"uniqueDestinations\":";
        itemsJson += std::to_string(st.colInt64(3));
        itemsJson += ",\"countriesCount\":";
        itemsJson += std::to_string(st.colInt64(4));
        itemsJson += ",\"rxBytes\":";
        itemsJson += std::to_string(st.colInt64(5));
        itemsJson += ",\"txBytes\":";
        itemsJson += std::to_string(st.colInt64(6));
        std::snprintf(numBuf, sizeof(numBuf), "%.1f", st.colDouble(7));
        itemsJson += ",\"avgDurationMs\":";
        itemsJson += numBuf;
        itemsJson += ",\"lastSeenAt\":";
        itemsJson += std::to_string(st.colInt64(8));
        itemsJson.push_back('}');
      }
      return true;
    });
  }

  std::string out = "{\"range\":";
  appendJsonEscaped(out, range.empty() ? "7d" : range);
  out += ",\"total\":";
  out += std::to_string(total);
  out += ",\"items\":[";
  out += itemsJson;
  out += "]}";
  return out;
}

std::string HistoryStore::queryAnalyticsJson(const std::string& range) {
  drainAndWriteBatch();
  const uint64_t now = nowEpochMs();
  const uint64_t dur = rangeToDurationMs(range);
  const uint64_t cutoff = (now > dur) ? (now - dur) : 0ULL;

  int64_t nicRx = 0, nicTx = 0, totalConns = 0, uniqProcs = 0, uniqDests = 0, uniqCountries = 0;
  double avgDurationMs = 0.0;
  std::string topProcsJson, topDestsJson, topCountriesJson, dailyJson;

  if (db_.isOpen()) {
    db_.withLock([&](sqlite3* db) {
      {
        SqliteStmt st(db, "SELECT COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0) FROM nic_traffic_samples WHERE bucket_start_ms >= ?;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        if (st.valid() && st.step() == SQLITE_ROW) {
          nicRx = st.colInt64(0);
          nicTx = st.colInt64(1);
        }
      }
      {
        SqliteStmt st(
            db,
            "SELECT COUNT(*), COUNT(DISTINCT process_name), COUNT(DISTINCT remote_ip),"
            " COUNT(DISTINCT CASE WHEN country_code<>'' THEN country_code END), COALESCE(AVG(duration_ms),0) "
            "FROM connection_history WHERE started_at_ms >= ?;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        if (st.valid() && st.step() == SQLITE_ROW) {
          totalConns = st.colInt64(0);
          uniqProcs = st.colInt64(1);
          uniqDests = st.colInt64(2);
          uniqCountries = st.colInt64(3);
          avgDurationMs = st.colDouble(4);
        }
      }
      {
        SqliteStmt st(
            db,
            "SELECT process_name, COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0), COUNT(*), COALESCE(AVG(duration_ms),0) "
            "FROM connection_history WHERE started_at_ms >= ? "
            "GROUP BY process_name ORDER BY (COALESCE(SUM(rx_bytes),0)+COALESCE(SUM(tx_bytes),0)) DESC, COUNT(*) DESC LIMIT 10;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        bool first = true;
        while (st.valid() && st.step() == SQLITE_ROW) {
          if (!first) topProcsJson.push_back(',');
          first = false;
          topProcsJson += "{\"process\":";
          appendJsonEscaped(topProcsJson, st.colText(0));
          topProcsJson += ",\"rxBytes\":";
          topProcsJson += std::to_string(st.colInt64(1));
          topProcsJson += ",\"txBytes\":";
          topProcsJson += std::to_string(st.colInt64(2));
          topProcsJson += ",\"connections\":";
          topProcsJson += std::to_string(st.colInt64(3));
          topProcsJson.push_back('}');
        }
      }
      {
        SqliteStmt st(
            db,
            "SELECT remote_ip, MAX(dns_name), MAX(country), MAX(country_code), COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0), COUNT(*) "
            "FROM connection_history WHERE started_at_ms >= ? AND scope='public' "
            "GROUP BY remote_ip ORDER BY COUNT(*) DESC, (COALESCE(SUM(rx_bytes),0)+COALESCE(SUM(tx_bytes),0)) DESC LIMIT 10;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        bool first = true;
        while (st.valid() && st.step() == SQLITE_ROW) {
          if (!first) topDestsJson.push_back(',');
          first = false;
          topDestsJson += "{\"remoteIp\":";
          appendJsonEscaped(topDestsJson, st.colText(0));
          topDestsJson += ",\"dns\":";
          appendJsonEscaped(topDestsJson, st.colText(1));
          topDestsJson += ",\"country\":";
          appendJsonEscaped(topDestsJson, st.colText(2));
          topDestsJson += ",\"cc\":";
          appendJsonEscaped(topDestsJson, st.colText(3));
          topDestsJson += ",\"rxBytes\":";
          topDestsJson += std::to_string(st.colInt64(4));
          topDestsJson += ",\"txBytes\":";
          topDestsJson += std::to_string(st.colInt64(5));
          topDestsJson += ",\"connections\":";
          topDestsJson += std::to_string(st.colInt64(6));
          topDestsJson.push_back('}');
        }
      }
      {
        SqliteStmt st(
            db,
            "SELECT country, country_code, COUNT(*), COUNT(DISTINCT remote_ip), COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0) "
            "FROM connection_history WHERE started_at_ms >= ? AND country_code<>'' "
            "GROUP BY country_code, country ORDER BY COUNT(*) DESC LIMIT 10;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        bool first = true;
        while (st.valid() && st.step() == SQLITE_ROW) {
          if (!first) topCountriesJson.push_back(',');
          first = false;
          topCountriesJson += "{\"country\":";
          appendJsonEscaped(topCountriesJson, st.colText(0));
          topCountriesJson += ",\"cc\":";
          appendJsonEscaped(topCountriesJson, st.colText(1));
          topCountriesJson += ",\"connections\":";
          topCountriesJson += std::to_string(st.colInt64(2));
          topCountriesJson += ",\"uniqueIps\":";
          topCountriesJson += std::to_string(st.colInt64(3));
          topCountriesJson += ",\"rxBytes\":";
          topCountriesJson += std::to_string(st.colInt64(4));
          topCountriesJson += ",\"txBytes\":";
          topCountriesJson += std::to_string(st.colInt64(5));
          topCountriesJson.push_back('}');
        }
      }
      {
        SqliteStmt st(
            db,
            "SELECT (bucket_start_ms / 86400000) * 86400000 AS day_ms, COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0), MAX(max_rx_bps), MAX(max_tx_bps) "
            "FROM nic_traffic_samples WHERE bucket_start_ms >= ? "
            "GROUP BY day_ms ORDER BY day_ms ASC;");
        st.bindInt64(1, static_cast<int64_t>(cutoff));
        bool first = true;
        char numBuf[32];
        while (st.valid() && st.step() == SQLITE_ROW) {
          if (!first) dailyJson.push_back(',');
          first = false;
          dailyJson += "{\"dayMs\":";
          dailyJson += std::to_string(st.colInt64(0));
          dailyJson += ",\"rxBytes\":";
          dailyJson += std::to_string(st.colInt64(1));
          dailyJson += ",\"txBytes\":";
          dailyJson += std::to_string(st.colInt64(2));
          std::snprintf(numBuf, sizeof(numBuf), "%.1f", st.colDouble(3));
          dailyJson += ",\"peakRxBps\":";
          dailyJson += numBuf;
          std::snprintf(numBuf, sizeof(numBuf), "%.1f", st.colDouble(4));
          dailyJson += ",\"peakTxBps\":";
          dailyJson += numBuf;
          dailyJson.push_back('}');
        }
      }
      return true;
    });
  }

  char avgBuf[32];
  std::snprintf(avgBuf, sizeof(avgBuf), "%.1f", avgDurationMs);

  std::string out = "{\"range\":";
  appendJsonEscaped(out, range.empty() ? "7d" : range);
  out += ",\"summary\":{\"rxBytes\":";
  out += std::to_string(nicRx);
  out += ",\"txBytes\":";
  out += std::to_string(nicTx);
  out += ",\"totalConnections\":";
  out += std::to_string(totalConns);
  out += ",\"avgDurationMs\":";
  out += avgBuf;
  out += ",\"uniqueProcesses\":";
  out += std::to_string(uniqProcs);
  out += ",\"uniqueDestinations\":";
  out += std::to_string(uniqDests);
  out += ",\"uniqueCountries\":";
  out += std::to_string(uniqCountries);
  out += "},\"topProcesses\":[";
  out += topProcsJson;
  out += "],\"topDestinations\":[";
  out += topDestsJson;
  out += "],\"topCountries\":[";
  out += topCountriesJson;
  out += "],\"dailySeries\":[";
  out += dailyJson;
  out += "]}";
  return out;
}

std::string HistoryStore::getStorageStatsJson() {
  drainAndWriteBatch();
  int64_t evCnt = 0, metCnt = 0, connCnt = 0, rollCnt = 0, nicCnt = 0, qsCnt = 0;
  std::string journalMode = "unknown";
  bool integrity = false;

  if (db_.isOpen()) {
    integrity = db_.quickCheckOk();
    db_.withLock([&](sqlite3* db) {
      auto countTbl = [&](const char* sql) -> int64_t {
        SqliteStmt st(db, sql);
        return (st.valid() && st.step() == SQLITE_ROW) ? st.colInt64(0) : 0;
      };
      evCnt = countTbl("SELECT COUNT(*) FROM events;");
      metCnt = countTbl("SELECT COUNT(*) FROM service_metrics;");
      connCnt = countTbl("SELECT COUNT(*) FROM connection_history;");
      rollCnt = countTbl("SELECT COUNT(*) FROM traffic_rollups;");
      nicCnt = countTbl("SELECT COUNT(*) FROM nic_traffic_samples;");
      qsCnt = countTbl("SELECT COUNT(*) FROM quality_samples;");
      SqliteStmt jm(db, "PRAGMA journal_mode;");
      if (jm.valid() && jm.step() == SQLITE_ROW) journalMode = jm.colText(0);
      return true;
    });
  }
  int64_t traceCnt = 0;
  int64_t ifSampleCnt = 0;
  int64_t lanDevCnt = 0;
  int64_t secAlertCnt = 0;
  int64_t secRuleCnt = 0;
  if (db_.isOpen()) {
    db_.withLock([&](sqlite3* db) {
      SqliteStmt st(db, "SELECT COUNT(*) FROM trace_runs;");
      if (st.valid() && st.step() == SQLITE_ROW) traceCnt = st.colInt64(0);
      SqliteStmt st2(db, "SELECT COUNT(*) FROM interface_samples;");
      if (st2.valid() && st2.step() == SQLITE_ROW) ifSampleCnt = st2.colInt64(0);
      SqliteStmt st3(db, "SELECT COUNT(*) FROM lan_devices;");
      if (st3.valid() && st3.step() == SQLITE_ROW) lanDevCnt = st3.colInt64(0);
      SqliteStmt st4(db, "SELECT COUNT(*) FROM security_alerts;");
      if (st4.valid() && st4.step() == SQLITE_ROW) secAlertCnt = st4.colInt64(0);
      SqliteStmt st5(db, "SELECT COUNT(*) FROM security_rules;");
      if (st5.valid() && st5.step() == SQLITE_ROW) secRuleCnt = st5.colInt64(0);
      return true;
    });
  }

  std::string out = "{\"engine\":\"sqlite3\",\"sqliteVersion\":";
  appendJsonEscaped(out, sqlite3_libversion());
  out += ",\"schemaVersion\":";
  out += std::to_string(db_.currentSchemaVersion());
  out += ",\"journalMode\":";
  appendJsonEscaped(out, journalMode);
  out += ",\"integrityOk\":";
  out += (integrity ? "true" : "false");
  out += ",\"sizeBytes\":";
  out += std::to_string(db_.fileSizeBytes());
  out += ",\"retentionDays\":";
  out += std::to_string(retentionDays_.load());
  out += ",\"maxDbSizeMb\":";
  out += std::to_string(maxDbSizeMb_.load());
  out += ",\"tables\":{\"events\":";
  out += std::to_string(evCnt);
  out += ",\"serviceMetrics\":";
  out += std::to_string(metCnt);
  out += ",\"connectionHistory\":";
  out += std::to_string(connCnt);
  out += ",\"trafficRollups\":";
  out += std::to_string(rollCnt);
  out += ",\"nicSamples\":";
  out += std::to_string(nicCnt);
  out += ",\"qualitySamples\":";
  out += std::to_string(qsCnt);
  out += ",\"traceRuns\":";
  out += std::to_string(traceCnt);
  out += ",\"interfaceSamples\":";
  out += std::to_string(ifSampleCnt);
  out += ",\"lanDevices\":";
  out += std::to_string(lanDevCnt);
  out += ",\"securityAlerts\":";
  out += std::to_string(secAlertCnt);
  out += ",\"securityRules\":";
  out += std::to_string(secRuleCnt);
  out += "}}";
  return out;
}

std::vector<QualityTargetRecord> HistoryStore::loadQualityTargets() {
  std::vector<QualityTargetRecord> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT id, name, host, port, category, probe_mode, interval_sec, enabled, is_auto, created_at_ms "
        "FROM quality_targets ORDER BY is_auto DESC, created_at_ms ASC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      QualityTargetRecord t;
      t.id = st.colText(0);
      t.name = st.colText(1);
      t.host = st.colText(2);
      t.port = static_cast<uint16_t>(std::clamp<int64_t>(st.colInt64(3), 0, 65535));
      t.category = st.colText(4);
      t.probeMode = st.colText(5);
      t.intervalSec = static_cast<int>(std::clamp<int64_t>(st.colInt64(6), 5, 300));
      t.enabled = (st.colInt64(7) != 0);
      t.isAuto = (st.colInt64(8) != 0);
      t.createdAtMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(9)));
      out.push_back(std::move(t));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertQualityTarget(const QualityTargetRecord& t) {
  if (!db_.isOpen() || t.id.empty() || t.host.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO quality_targets(id, name, host, port, category, probe_mode, interval_sec, enabled, is_auto, created_at_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  name=excluded.name, host=excluded.host, port=excluded.port, category=excluded.category,"
        "  probe_mode=excluded.probe_mode, interval_sec=excluded.interval_sec, enabled=excluded.enabled, is_auto=excluded.is_auto;");
    st.bindText(1, t.id);
    st.bindText(2, t.name);
    st.bindText(3, t.host);
    st.bindInt64(4, static_cast<int64_t>(t.port));
    st.bindText(5, t.category);
    st.bindText(6, t.probeMode);
    st.bindInt64(7, static_cast<int64_t>(std::clamp(t.intervalSec, 5, 300)));
    st.bindInt64(8, t.enabled ? 1 : 0);
    st.bindInt64(9, t.isAuto ? 1 : 0);
    st.bindInt64(10, static_cast<int64_t>(t.createdAtMs > 0 ? t.createdAtMs : nowEpochMs()));
    return st.stepDone();
  });
}

bool HistoryStore::deleteQualityTarget(const std::string& id) {
  if (!db_.isOpen() || id.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt d1(db, "DELETE FROM quality_targets WHERE id = ?;");
    d1.bindText(1, id);
    if (!d1.stepDone()) return false;
    SqliteStmt d2(db, "DELETE FROM quality_samples WHERE target_id = ?;");
    d2.bindText(1, id);
    d2.stepDone();
    return true;
  });
}

std::vector<QualitySampleRecord> HistoryStore::loadRecentQualitySamples(const std::string& targetId, size_t maxCount) {
  std::vector<QualitySampleRecord> out;
  if (!db_.isOpen() || targetId.empty()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT ts_ms, target_id, ok, rtt_ms, dns_ms, jitter_ms, method, error "
        "FROM quality_samples WHERE target_id = ? ORDER BY ts_ms DESC LIMIT ?;");
    st.bindText(1, targetId);
    st.bindInt64(2, static_cast<int64_t>(std::clamp<size_t>(maxCount, 1, 1000)));
    while (st.valid() && st.step() == SQLITE_ROW) {
      QualitySampleRecord s;
      s.tsMs = static_cast<uint64_t>(st.colInt64(0));
      s.targetId = st.colText(1);
      s.ok = (st.colInt64(2) != 0);
      s.rttMs = st.colDouble(3);
      s.dnsMs = st.colDouble(4);
      s.jitterMs = st.colDouble(5);
      s.method = st.colText(6);
      s.error = st.colText(7);
      out.push_back(std::move(s));
    }
    return true;
  });
  std::reverse(out.begin(), out.end());
  return out;
}

std::string HistoryStore::queryQualityHistoryJson(const std::string& targetId, const std::string& range) {
  drainAndWriteBatch();
  const uint64_t now = nowEpochMs();
  const uint64_t dur = rangeToDurationMs(range.empty() ? "1h" : range);
  const uint64_t cutoff = (now > dur) ? (now - dur) : 0ULL;

  // Choose bucket width for compact, responsive graphs (at most ~120 buckets)
  uint64_t bucketMs = 60000ULL; // 1h -> 60s
  if (range == "15m") bucketMs = 15000ULL;
  else if (range == "24h" || range == "1d") bucketMs = 600000ULL; // 10 min
  else if (range == "7d") bucketMs = 3600000ULL; // 1 hour

  struct BucketAgg {
    uint64_t bucketTs = 0;
    size_t total = 0;
    size_t okCount = 0;
    std::vector<double> rtts;
    double jitterSum = 0.0;
    double dnsSum = 0.0;
    size_t dnsCount = 0;
  };

  std::vector<double> allRtts;
  std::vector<BucketAgg> buckets;
  size_t totalSamples = 0;
  size_t okSamples = 0;
  double jitterSumAll = 0.0;
  size_t jitterCountAll = 0;
  double dnsSumAll = 0.0;
  size_t dnsCountAll = 0;
  double minRtt = 0.0;
  double maxRtt = 0.0;
  double rttSum = 0.0;

  if (db_.isOpen() && !targetId.empty()) {
    db_.withLock([&](sqlite3* db) {
      SqliteStmt st(
          db,
          "SELECT ts_ms, ok, rtt_ms, dns_ms, jitter_ms "
          "FROM quality_samples WHERE target_id = ? AND ts_ms >= ? ORDER BY ts_ms ASC;");
      st.bindText(1, targetId);
      st.bindInt64(2, static_cast<int64_t>(cutoff));

      BucketAgg cur;
      bool hasCur = false;
      while (st.valid() && st.step() == SQLITE_ROW) {
        uint64_t ts = static_cast<uint64_t>(st.colInt64(0));
        bool ok = (st.colInt64(1) != 0);
        double rtt = st.colDouble(2);
        double dns = st.colDouble(3);
        double jit = st.colDouble(4);

        totalSamples++;
        if (ok) {
          okSamples++;
          allRtts.push_back(rtt);
          if (allRtts.size() == 1 || rtt < minRtt) minRtt = rtt;
          if (allRtts.size() == 1 || rtt > maxRtt) maxRtt = rtt;
          rttSum += rtt;
          if (jit > 0.0) {
            jitterSumAll += jit;
            jitterCountAll++;
          }
        }
        if (dns > 0.0) {
          dnsSumAll += dns;
          dnsCountAll++;
        }

        uint64_t bTs = floorBucket(ts, bucketMs);
        if (!hasCur || cur.bucketTs != bTs) {
          if (hasCur) buckets.push_back(std::move(cur));
          cur = BucketAgg{};
          cur.bucketTs = bTs;
          hasCur = true;
        }
        cur.total++;
        if (ok) {
          cur.okCount++;
          cur.rtts.push_back(rtt);
          cur.jitterSum += jit;
        }
        if (dns > 0.0) {
          cur.dnsSum += dns;
          cur.dnsCount++;
        }
      }
      if (hasCur) buckets.push_back(std::move(cur));
      return true;
    });
  }

  auto percentileOf = [](std::vector<double>& vals, double pct) -> double {
    if (vals.empty()) return 0.0;
    std::sort(vals.begin(), vals.end());
    double pos = (pct / 100.0) * static_cast<double>(vals.size() - 1);
    size_t lo = static_cast<size_t>(pos);
    size_t hi = std::min(vals.size() - 1, lo + 1);
    double frac = pos - static_cast<double>(lo);
    return vals[lo] * (1.0 - frac) + vals[hi] * frac;
  };

  const double p50 = percentileOf(allRtts, 50.0);
  const double p90 = percentileOf(allRtts, 90.0);
  const double p95 = percentileOf(allRtts, 95.0);
  const double p99 = percentileOf(allRtts, 99.0);
  const double avg = okSamples > 0 ? (rttSum / static_cast<double>(okSamples)) : 0.0;
  const double avgJit = jitterCountAll > 0 ? (jitterSumAll / static_cast<double>(jitterCountAll)) : 0.0;
  const double avgDns = dnsCountAll > 0 ? (dnsSumAll / static_cast<double>(dnsCountAll)) : 0.0;
  const double lossPct = totalSamples > 0 ? (100.0 * static_cast<double>(totalSamples - okSamples) / static_cast<double>(totalSamples)) : 0.0;
  const double availPct = totalSamples > 0 ? (100.0 * static_cast<double>(okSamples) / static_cast<double>(totalSamples)) : 0.0;

  char num[32];
  auto appendNum = [&](std::string& dst, double v) {
    std::snprintf(num, sizeof(num), "%.2f", v);
    dst += num;
  };

  std::string out = "{\"targetId\":";
  appendJsonEscaped(out, targetId);
  out += ",\"range\":";
  appendJsonEscaped(out, range.empty() ? "1h" : range);
  out += ",\"summary\":{\"samples\":";
  out += std::to_string(totalSamples);
  out += ",\"okSamples\":";
  out += std::to_string(okSamples);
  out += ",\"minMs\":";
  appendNum(out, minRtt);
  out += ",\"maxMs\":";
  appendNum(out, maxRtt);
  out += ",\"avgMs\":";
  appendNum(out, avg);
  out += ",\"p50Ms\":";
  appendNum(out, p50);
  out += ",\"p90Ms\":";
  appendNum(out, p90);
  out += ",\"p95Ms\":";
  appendNum(out, p95);
  out += ",\"p99Ms\":";
  appendNum(out, p99);
  out += ",\"jitterMs\":";
  appendNum(out, avgJit);
  out += ",\"lossPct\":";
  appendNum(out, lossPct);
  out += ",\"availabilityPct\":";
  appendNum(out, availPct);
  out += ",\"dnsMs\":";
  appendNum(out, avgDns);
  out += "},\"series\":[";

  for (size_t i = 0; i < buckets.size(); ++i) {
    auto& b = buckets[i];
    if (i > 0) out.push_back(',');
    double bMin = 0.0, bMax = 0.0, bAvg = 0.0, bP95 = 0.0, bJit = 0.0, bDns = 0.0;
    if (!b.rtts.empty()) {
      bP95 = percentileOf(b.rtts, 95.0); // sorts b.rtts ascending
      bMin = b.rtts.front();
      bMax = b.rtts.back();
      double s = 0.0;
      for (double v : b.rtts) s += v;
      bAvg = s / static_cast<double>(b.rtts.size());
      bJit = b.jitterSum / static_cast<double>(b.rtts.size());
    }
    if (b.dnsCount > 0) bDns = b.dnsSum / static_cast<double>(b.dnsCount);
    double bLoss = b.total > 0 ? (100.0 * static_cast<double>(b.total - b.okCount) / static_cast<double>(b.total)) : 0.0;

    out += "{\"ts\":";
    out += std::to_string(b.bucketTs);
    out += ",\"avgMs\":";
    appendNum(out, bAvg);
    out += ",\"minMs\":";
    appendNum(out, bMin);
    out += ",\"maxMs\":";
    appendNum(out, bMax);
    out += ",\"p95Ms\":";
    appendNum(out, bP95);
    out += ",\"jitterMs\":";
    appendNum(out, bJit);
    out += ",\"lossPct\":";
    appendNum(out, bLoss);
    out += ",\"dnsMs\":";
    appendNum(out, bDns);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

int64_t HistoryStore::saveTraceRun(TraceRunRecord& run) {
  if (!db_.isOpen() || run.targetIp.empty()) return 0;

  bool changedFromPrev = false;
  int64_t insertedId = 0;

  db_.withTransaction([&](sqlite3* db) {
    SqliteStmt prevSt(db, "SELECT path_hash FROM trace_runs WHERE target_ip = ? ORDER BY started_at_ms DESC, id DESC LIMIT 1;");
    if (prevSt.valid()) {
      prevSt.bindText(1, run.targetIp);
      if (prevSt.step() == SQLITE_ROW) {
        const std::string prevHash = prevSt.colText(0);
        if (!prevHash.empty() && !run.pathHash.empty() && prevHash != run.pathHash) {
          changedFromPrev = true;
        }
      }
    }
    run.changedFromPrev = changedFromPrev;

    SqliteStmt ins(
        db,
        "INSERT INTO trace_runs("
        "  target_ip, target_label, trigger_kind, started_at_ms, completed_at_ms,"
        "  reached, hop_count, total_rtt_ms, path_hash, changed_from_prev, error"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?);");
    if (!ins.valid()) return false;
    ins.bindText(1, run.targetIp);
    ins.bindText(2, run.targetLabel);
    ins.bindText(3, run.triggerKind.empty() ? "manual" : run.triggerKind);
    ins.bindInt64(4, static_cast<int64_t>(run.startedAtMs));
    ins.bindInt64(5, static_cast<int64_t>(run.completedAtMs));
    ins.bindInt64(6, run.reached ? 1 : 0);
    ins.bindInt64(7, static_cast<int64_t>(run.hops.size()));
    ins.bindDouble(8, run.totalRttMs);
    ins.bindText(9, run.pathHash);
    ins.bindInt64(10, run.changedFromPrev ? 1 : 0);
    ins.bindText(11, run.error);
    if (!ins.stepDone()) return false;

    insertedId = sqlite3_last_insert_rowid(db);
    run.id = insertedId;

    SqliteStmt hopIns(
        db,
        "INSERT INTO trace_hops("
        "  run_id, ttl, timed_out, ip, rtt_ms, hostname, asn, country, country_code, city, lat, lon"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?);");
    if (hopIns.valid()) {
      for (const auto& h : run.hops) {
        hopIns.reset();
        hopIns.bindInt64(1, insertedId);
        hopIns.bindInt64(2, static_cast<int64_t>(h.ttl));
        hopIns.bindInt64(3, h.timedOut ? 1 : 0);
        hopIns.bindText(4, h.ip);
        hopIns.bindDouble(5, h.rttMs);
        hopIns.bindText(6, h.hostname);
        hopIns.bindText(7, h.asn);
        hopIns.bindText(8, h.country);
        hopIns.bindText(9, h.countryCode);
        hopIns.bindText(10, h.city);
        hopIns.bindDouble(11, h.lat);
        hopIns.bindDouble(12, h.lon);
        hopIns.stepDone();
      }
    }
    return true;
  });

  if (insertedId > 0 && changedFromPrev) {
    enqueueEvent(
        HistoryEvent{
            nowEpochMs(),
            "warn",
            "route_changed",
            "Variação de rota detectada: " + (run.targetLabel.empty() ? run.targetIp : run.targetLabel),
            "IP " + run.targetIp + " · saltos " + std::to_string(run.hops.size()) + " · hash " + run.pathHash,
        },
        false);
  }
  return insertedId;
}

std::vector<TraceRunRecord> HistoryStore::loadTraceRuns(const std::string& targetIp, size_t limit) {
  std::vector<TraceRunRecord> out;
  if (!db_.isOpen()) return out;
  const size_t lim = std::clamp<size_t>(limit, 1, 100);

  db_.withLock([&](sqlite3* db) {
    std::string sql =
        "SELECT id, target_ip, target_label, trigger_kind, started_at_ms, completed_at_ms,"
        " reached, total_rtt_ms, path_hash, changed_from_prev, error "
        "FROM trace_runs";
    if (!targetIp.empty()) sql += " WHERE target_ip = ?";
    sql += " ORDER BY started_at_ms DESC, id DESC LIMIT ?;";

    SqliteStmt st(db, sql.c_str());
    int idx = 1;
    if (!targetIp.empty()) st.bindText(idx++, targetIp);
    st.bindInt64(idx++, static_cast<int64_t>(lim));

    while (st.valid() && st.step() == SQLITE_ROW) {
      TraceRunRecord r;
      r.id = st.colInt64(0);
      r.targetIp = st.colText(1);
      r.targetLabel = st.colText(2);
      r.triggerKind = st.colText(3);
      r.startedAtMs = static_cast<uint64_t>(st.colInt64(4));
      r.completedAtMs = static_cast<uint64_t>(st.colInt64(5));
      r.reached = (st.colInt64(6) != 0);
      r.totalRttMs = st.colDouble(7);
      r.pathHash = st.colText(8);
      r.changedFromPrev = (st.colInt64(9) != 0);
      r.error = st.colText(10);
      out.push_back(std::move(r));
    }

    SqliteStmt hopSt(
        db,
        "SELECT ttl, timed_out, ip, rtt_ms, hostname, asn, country, country_code, city, lat, lon "
        "FROM trace_hops WHERE run_id = ? ORDER BY ttl ASC;");
    if (hopSt.valid()) {
      for (auto& r : out) {
        hopSt.reset();
        hopSt.bindInt64(1, r.id);
        while (hopSt.step() == SQLITE_ROW) {
          TraceHopRecord h;
          h.ttl = static_cast<int>(hopSt.colInt64(0));
          h.timedOut = (hopSt.colInt64(1) != 0);
          h.ip = hopSt.colText(2);
          h.rttMs = hopSt.colDouble(3);
          h.hostname = hopSt.colText(4);
          h.asn = hopSt.colText(5);
          h.country = hopSt.colText(6);
          h.countryCode = hopSt.colText(7);
          h.city = hopSt.colText(8);
          h.lat = hopSt.colDouble(9);
          h.lon = hopSt.colDouble(10);
          r.hops.push_back(std::move(h));
        }
      }
    }
    return true;
  });
  return out;
}

bool HistoryStore::getTraceRunById(int64_t runId, TraceRunRecord& out) {
  if (!db_.isOpen() || runId <= 0) return false;
  bool found = false;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT id, target_ip, target_label, trigger_kind, started_at_ms, completed_at_ms,"
        " reached, total_rtt_ms, path_hash, changed_from_prev, error "
        "FROM trace_runs WHERE id = ?;");
    st.bindInt64(1, runId);
    if (st.valid() && st.step() == SQLITE_ROW) {
      out = TraceRunRecord{};
      out.id = st.colInt64(0);
      out.targetIp = st.colText(1);
      out.targetLabel = st.colText(2);
      out.triggerKind = st.colText(3);
      out.startedAtMs = static_cast<uint64_t>(st.colInt64(4));
      out.completedAtMs = static_cast<uint64_t>(st.colInt64(5));
      out.reached = (st.colInt64(6) != 0);
      out.totalRttMs = st.colDouble(7);
      out.pathHash = st.colText(8);
      out.changedFromPrev = (st.colInt64(9) != 0);
      out.error = st.colText(10);
      found = true;

      SqliteStmt hopSt(
          db,
          "SELECT ttl, timed_out, ip, rtt_ms, hostname, asn, country, country_code, city, lat, lon "
          "FROM trace_hops WHERE run_id = ? ORDER BY ttl ASC;");
      hopSt.bindInt64(1, out.id);
      while (hopSt.valid() && hopSt.step() == SQLITE_ROW) {
        TraceHopRecord h;
        h.ttl = static_cast<int>(hopSt.colInt64(0));
        h.timedOut = (hopSt.colInt64(1) != 0);
        h.ip = hopSt.colText(2);
        h.rttMs = hopSt.colDouble(3);
        h.hostname = hopSt.colText(4);
        h.asn = hopSt.colText(5);
        h.country = hopSt.colText(6);
        h.countryCode = hopSt.colText(7);
        h.city = hopSt.colText(8);
        h.lat = hopSt.colDouble(9);
        h.lon = hopSt.colDouble(10);
        out.hops.push_back(std::move(h));
      }
    }
    return true;
  });
  return found;
}

std::string HistoryStore::queryTraceHistoryJson(const std::string& targetIp, size_t limit) {
  auto runs = loadTraceRuns(targetIp, limit);
  char num[32];
  std::string out = "{\"targetIp\":";
  appendJsonEscaped(out, targetIp);
  out += ",\"runs\":[";

  for (size_t i = 0; i < runs.size(); ++i) {
    const auto& r = runs[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    out += std::to_string(r.id);
    out += ",\"targetIp\":";
    appendJsonEscaped(out, r.targetIp);
    out += ",\"targetLabel\":";
    appendJsonEscaped(out, r.targetLabel);
    out += ",\"triggerKind\":";
    appendJsonEscaped(out, r.triggerKind);
    out += ",\"startedAt\":";
    out += std::to_string(r.startedAtMs);
    out += ",\"completedAt\":";
    out += std::to_string(r.completedAtMs);
    out += ",\"reached\":";
    out += (r.reached ? "true" : "false");
    out += ",\"hopCount\":";
    out += std::to_string(r.hops.size());
    std::snprintf(num, sizeof(num), "%.1f", r.totalRttMs);
    out += ",\"totalRttMs\":";
    out += num;
    out += ",\"pathHash\":";
    appendJsonEscaped(out, r.pathHash);
    out += ",\"changedFromPrev\":";
    out += (r.changedFromPrev ? "true" : "false");
    out += ",\"error\":";
    appendJsonEscaped(out, r.error);
    out += ",\"hops\":[";
    for (size_t j = 0; j < r.hops.size(); ++j) {
      const auto& h = r.hops[j];
      if (j > 0) out.push_back(',');
      out += "{\"ttl\":";
      out += std::to_string(h.ttl);
      out += ",\"timedOut\":";
      out += (h.timedOut ? "true" : "false");
      out += ",\"ip\":";
      appendJsonEscaped(out, h.ip);
      std::snprintf(num, sizeof(num), "%.1f", h.rttMs);
      out += ",\"rttMs\":";
      out += num;
      out += ",\"host\":";
      appendJsonEscaped(out, h.hostname);
      out += ",\"asn\":";
      appendJsonEscaped(out, h.asn);
      out += ",\"country\":";
      appendJsonEscaped(out, h.country);
      out += ",\"cc\":";
      appendJsonEscaped(out, h.countryCode);
      out += ",\"city\":";
      appendJsonEscaped(out, h.city);
      out.push_back('}');
    }
    out += "]}";
  }
  out += "]}";
  return out;
}

std::vector<TraceMonitorRecord> HistoryStore::loadTraceMonitors() {
  std::vector<TraceMonitorRecord> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT target_ip, label, interval_sec, enabled, created_at_ms, last_run_ms "
        "FROM trace_monitors ORDER BY created_at_ms ASC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      TraceMonitorRecord m;
      m.targetIp = st.colText(0);
      m.label = st.colText(1);
      m.intervalSec = static_cast<int>(std::clamp<int64_t>(st.colInt64(2), 30, 3600));
      m.enabled = (st.colInt64(3) != 0);
      m.createdAtMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(4)));
      m.lastRunMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(5)));
      out.push_back(std::move(m));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertTraceMonitor(const TraceMonitorRecord& mon) {
  if (!db_.isOpen() || mon.targetIp.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO trace_monitors(target_ip, label, interval_sec, enabled, created_at_ms, last_run_ms) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(target_ip) DO UPDATE SET "
        "  label=excluded.label, interval_sec=excluded.interval_sec, enabled=excluded.enabled;");
    st.bindText(1, mon.targetIp);
    st.bindText(2, mon.label);
    st.bindInt64(3, static_cast<int64_t>(std::clamp(mon.intervalSec, 30, 3600)));
    st.bindInt64(4, mon.enabled ? 1 : 0);
    st.bindInt64(5, static_cast<int64_t>(mon.createdAtMs > 0 ? mon.createdAtMs : nowEpochMs()));
    st.bindInt64(6, static_cast<int64_t>(mon.lastRunMs));
    return st.stepDone();
  });
}

bool HistoryStore::deleteTraceMonitor(const std::string& targetIp) {
  if (!db_.isOpen() || targetIp.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "DELETE FROM trace_monitors WHERE target_ip = ?;");
    st.bindText(1, targetIp);
    return st.stepDone();
  });
}

bool HistoryStore::updateTraceMonitorLastRun(const std::string& targetIp, uint64_t lastRunMs) {
  if (!db_.isOpen() || targetIp.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "UPDATE trace_monitors SET last_run_ms = ? WHERE target_ip = ?;");
    st.bindInt64(1, static_cast<int64_t>(lastRunMs));
    st.bindText(2, targetIp);
    return st.stepDone();
  });
}

std::string HistoryStore::queryInterfaceHistoryJson(const std::string& ifId, const std::string& range) {
  drainAndWriteBatch();
  const uint64_t now = nowEpochMs();
  const uint64_t dur = rangeToDurationMs(range.empty() ? "1h" : range);
  const uint64_t cutoff = (now > dur) ? (now - dur) : 0ULL;

  uint64_t bucketMs = 60000ULL; // 1h -> 60s
  if (range == "15m") bucketMs = 15000ULL;
  else if (range == "24h" || range == "1d") bucketMs = 600000ULL;
  else if (range == "7d") bucketMs = 3600000ULL;

  struct IfBucket {
    uint64_t ts = 0;
    double rxSum = 0.0;
    double txSum = 0.0;
    double maxRx = 0.0;
    double maxTx = 0.0;
    size_t cnt = 0;
    int64_t rxErr = 0;
    int64_t txErr = 0;
  };
  std::vector<IfBucket> buckets;

  if (db_.isOpen() && !ifId.empty()) {
    db_.withLock([&](sqlite3* db) {
      SqliteStmt st(
          db,
          "SELECT ts_ms, rx_bps, tx_bps, rx_errors, tx_errors "
          "FROM interface_samples WHERE if_id = ? AND ts_ms >= ? ORDER BY ts_ms ASC;");
      st.bindText(1, ifId);
      st.bindInt64(2, static_cast<int64_t>(cutoff));

      IfBucket cur;
      bool hasCur = false;
      int64_t prevRxErr = -1;
      int64_t prevTxErr = -1;
      while (st.valid() && st.step() == SQLITE_ROW) {
        const uint64_t ts = static_cast<uint64_t>(st.colInt64(0));
        const double rx = st.colDouble(1);
        const double tx = st.colDouble(2);
        const int64_t rErr = st.colInt64(3);
        const int64_t tErr = st.colInt64(4);
        const int64_t dRxErr = (prevRxErr >= 0 && rErr >= prevRxErr) ? (rErr - prevRxErr) : 0;
        const int64_t dTxErr = (prevTxErr >= 0 && tErr >= prevTxErr) ? (tErr - prevTxErr) : 0;
        prevRxErr = rErr;
        prevTxErr = tErr;

        const uint64_t bTs = floorBucket(ts, bucketMs);
        if (!hasCur || cur.ts != bTs) {
          if (hasCur) buckets.push_back(cur);
          cur = IfBucket{};
          cur.ts = bTs;
          hasCur = true;
        }
        cur.rxSum += rx;
        cur.txSum += tx;
        cur.maxRx = std::max(cur.maxRx, rx);
        cur.maxTx = std::max(cur.maxTx, tx);
        cur.rxErr += dRxErr;
        cur.txErr += dTxErr;
        cur.cnt++;
      }
      if (hasCur) buckets.push_back(cur);
      return true;
    });
  }

  char num[32];
  auto appendNum = [&](std::string& dst, double v) {
    std::snprintf(num, sizeof(num), "%.1f", v);
    dst += num;
  };

  std::string out = "{\"ifId\":";
  appendJsonEscaped(out, ifId);
  out += ",\"range\":";
  appendJsonEscaped(out, range.empty() ? "1h" : range);
  out += ",\"series\":[";
  for (size_t i = 0; i < buckets.size(); ++i) {
    const auto& b = buckets[i];
    if (i > 0) out.push_back(',');
    const double avgRx = b.cnt > 0 ? (b.rxSum / static_cast<double>(b.cnt)) : 0.0;
    const double avgTx = b.cnt > 0 ? (b.txSum / static_cast<double>(b.cnt)) : 0.0;
    out += "{\"ts\":";
    out += std::to_string(b.ts);
    out += ",\"avgRxBps\":";
    appendNum(out, avgRx);
    out += ",\"avgTxBps\":";
    appendNum(out, avgTx);
    out += ",\"maxRxBps\":";
    appendNum(out, b.maxRx);
    out += ",\"maxTxBps\":";
    appendNum(out, b.maxTx);
    out += ",\"errors\":";
    out += std::to_string(b.rxErr + b.txErr);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

std::vector<LanDeviceRecord> HistoryStore::loadLanDevices() {
  std::vector<LanDeviceRecord> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT device_key, ip, mac, vendor, hostname, device_type, interface_name, subnet,"
        " is_gateway, is_local_host, online, latency_ms, open_ports, custom_label, first_seen_ms, last_seen_ms, seen_count "
        "FROM lan_devices ORDER BY online DESC, is_local_host DESC, is_gateway DESC, last_seen_ms DESC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      LanDeviceRecord d;
      d.deviceKey = st.colText(0);
      d.ip = st.colText(1);
      d.mac = st.colText(2);
      d.vendor = st.colText(3);
      d.hostname = st.colText(4);
      d.deviceType = st.colText(5);
      d.interfaceName = st.colText(6);
      d.subnet = st.colText(7);
      d.isGateway = (st.colInt64(8) != 0);
      d.isLocalHost = (st.colInt64(9) != 0);
      d.online = (st.colInt64(10) != 0);
      d.latencyMs = st.colDouble(11);
      d.openPorts = st.colText(12);
      d.customLabel = st.colText(13);
      d.firstSeenMs = static_cast<uint64_t>(st.colInt64(14));
      d.lastSeenMs = static_cast<uint64_t>(st.colInt64(15));
      d.seenCount = static_cast<uint64_t>(std::max<int64_t>(1, st.colInt64(16)));
      out.push_back(std::move(d));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertLanDevices(const std::vector<LanDeviceRecord>& devices, bool markOthersOffline) {
  if (!db_.isOpen()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    if (markOthersOffline) {
      SqliteStmt off(db, "UPDATE lan_devices SET online = 0;");
      if (off.valid()) off.stepDone();
    }

    SqliteStmt st(
        db,
        "INSERT INTO lan_devices("
        "  device_key, ip, mac, vendor, hostname, device_type, interface_name, subnet,"
        "  is_gateway, is_local_host, online, latency_ms, open_ports, custom_label, first_seen_ms, last_seen_ms, seen_count"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(device_key) DO UPDATE SET "
        "  ip=excluded.ip,"
        "  mac=CASE WHEN excluded.mac<>'' THEN excluded.mac ELSE lan_devices.mac END,"
        "  vendor=CASE WHEN excluded.vendor<>'' THEN excluded.vendor ELSE lan_devices.vendor END,"
        "  hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE lan_devices.hostname END,"
        "  device_type=CASE WHEN excluded.device_type NOT IN ('','unknown','Dispositivo LAN') OR lan_devices.device_type IN ('','unknown') THEN excluded.device_type ELSE lan_devices.device_type END,"
        "  interface_name=CASE WHEN excluded.interface_name<>'' THEN excluded.interface_name ELSE lan_devices.interface_name END,"
        "  subnet=CASE WHEN excluded.subnet<>'' THEN excluded.subnet ELSE lan_devices.subnet END,"
        "  is_gateway=excluded.is_gateway,"
        "  is_local_host=excluded.is_local_host,"
        "  online=excluded.online,"
        "  latency_ms=CASE WHEN excluded.latency_ms>0 THEN excluded.latency_ms ELSE lan_devices.latency_ms END,"
        "  open_ports=CASE WHEN excluded.open_ports<>'' THEN excluded.open_ports ELSE lan_devices.open_ports END,"
        "  last_seen_ms=MAX(lan_devices.last_seen_ms, excluded.last_seen_ms),"
        "  seen_count=lan_devices.seen_count + 1;");
    if (!st.valid()) return false;
    for (const auto& d : devices) {
      if (d.deviceKey.empty() || d.ip.empty()) continue;
      st.reset();
      st.bindText(1, d.deviceKey);
      st.bindText(2, d.ip);
      st.bindText(3, d.mac);
      st.bindText(4, d.vendor);
      st.bindText(5, d.hostname);
      st.bindText(6, d.deviceType);
      st.bindText(7, d.interfaceName);
      st.bindText(8, d.subnet);
      st.bindInt64(9, d.isGateway ? 1 : 0);
      st.bindInt64(10, d.isLocalHost ? 1 : 0);
      st.bindInt64(11, d.online ? 1 : 0);
      st.bindDouble(12, d.latencyMs);
      st.bindText(13, d.openPorts);
      st.bindText(14, d.customLabel);
      st.bindInt64(15, static_cast<int64_t>(d.firstSeenMs > 0 ? d.firstSeenMs : nowEpochMs()));
      st.bindInt64(16, static_cast<int64_t>(d.lastSeenMs > 0 ? d.lastSeenMs : nowEpochMs()));
      st.bindInt64(17, static_cast<int64_t>(d.seenCount));
      st.stepDone();
    }
    return true;
  });
}

bool HistoryStore::setLanDeviceLabel(const std::string& deviceKey, const std::string& label) {
  if (!db_.isOpen() || deviceKey.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "UPDATE lan_devices SET custom_label = ? WHERE device_key = ?;");
    st.bindText(1, label);
    st.bindText(2, deviceKey);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

bool HistoryStore::deleteLanDevice(const std::string& deviceKey) {
  if (!db_.isOpen() || deviceKey.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "DELETE FROM lan_devices WHERE device_key = ?;");
    st.bindText(1, deviceKey);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

std::vector<SecurityRuleRecord> HistoryStore::loadSecurityRules() {
  std::vector<SecurityRuleRecord> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT id, name, kind, enabled, risk_weight, threshold_num, match_country, match_port, match_process, description, is_builtin, updated_at_ms "
        "FROM security_rules ORDER BY is_builtin DESC, updated_at_ms ASC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      SecurityRuleRecord r;
      r.id = st.colText(0);
      r.name = st.colText(1);
      r.kind = st.colText(2);
      r.enabled = (st.colInt64(3) != 0);
      r.riskWeight = static_cast<int>(std::clamp<int64_t>(st.colInt64(4), 1, 100));
      r.thresholdNum = st.colDouble(5);
      r.matchCountry = st.colText(6);
      r.matchPort = static_cast<uint16_t>(std::clamp<int64_t>(st.colInt64(7), 0, 65535));
      r.matchProcess = st.colText(8);
      r.description = st.colText(9);
      r.isBuiltin = (st.colInt64(10) != 0);
      r.updatedAtMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(11)));
      out.push_back(std::move(r));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertSecurityRule(const SecurityRuleRecord& rule) {
  if (!db_.isOpen() || rule.id.empty() || rule.kind.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO security_rules("
        "  id, name, kind, enabled, risk_weight, threshold_num, match_country, match_port, match_process, description, is_builtin, updated_at_ms"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  name=excluded.name, kind=excluded.kind, enabled=excluded.enabled, risk_weight=excluded.risk_weight,"
        "  threshold_num=excluded.threshold_num, match_country=excluded.match_country, match_port=excluded.match_port,"
        "  match_process=excluded.match_process, description=excluded.description, updated_at_ms=excluded.updated_at_ms;");
    st.bindText(1, rule.id);
    st.bindText(2, rule.name);
    st.bindText(3, rule.kind);
    st.bindInt64(4, rule.enabled ? 1 : 0);
    st.bindInt64(5, static_cast<int64_t>(std::clamp(rule.riskWeight, 1, 100)));
    st.bindDouble(6, rule.thresholdNum);
    st.bindText(7, rule.matchCountry);
    st.bindInt64(8, static_cast<int64_t>(rule.matchPort));
    st.bindText(9, rule.matchProcess);
    st.bindText(10, rule.description);
    st.bindInt64(11, rule.isBuiltin ? 1 : 0);
    st.bindInt64(12, static_cast<int64_t>(rule.updatedAtMs > 0 ? rule.updatedAtMs : nowEpochMs()));
    return st.stepDone();
  });
}

bool HistoryStore::deleteSecurityRule(const std::string& id) {
  if (!db_.isOpen() || id.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "DELETE FROM security_rules WHERE id = ? AND is_builtin = 0;");
    st.bindText(1, id);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

int64_t HistoryStore::saveSecurityAlert(const SecurityAlertRecord& alert) {
  if (!db_.isOpen() || alert.ruleId.empty()) return 0;
  int64_t id = 0;
  db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO security_alerts("
        "  ts_ms, rule_id, rule_name, risk_score, risk_level, process_name, pid, exe_path,"
        "  destination, country_code, what_happened, evidences_json, classification_reason, possible_actions_json, acknowledged"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    st.bindInt64(1, static_cast<int64_t>(alert.tsMs > 0 ? alert.tsMs : nowEpochMs()));
    st.bindText(2, alert.ruleId);
    st.bindText(3, alert.ruleName);
    st.bindInt64(4, static_cast<int64_t>(std::clamp(alert.riskScore, 0, 100)));
    st.bindText(5, alert.riskLevel);
    st.bindText(6, alert.processName);
    st.bindInt64(7, static_cast<int64_t>(alert.pid));
    st.bindText(8, alert.exePath);
    st.bindText(9, alert.destination);
    st.bindText(10, alert.countryCode);
    st.bindText(11, alert.whatHappened);
    st.bindText(12, alert.evidencesJson.empty() ? "[]" : alert.evidencesJson);
    st.bindText(13, alert.classificationReason);
    st.bindText(14, alert.possibleActionsJson.empty() ? "[]" : alert.possibleActionsJson);
    st.bindInt64(15, alert.acknowledged ? 1 : 0);
    if (!st.stepDone()) return false;
    id = sqlite3_last_insert_rowid(db);
    return true;
  });
  return id;
}

std::vector<SecurityAlertRecord> HistoryStore::loadSecurityAlerts(size_t limit,
                                                                    const std::string& levelFilter,
                                                                    bool unackOnly) {
  std::vector<SecurityAlertRecord> out;
  if (!db_.isOpen()) return out;
  const size_t lim = std::clamp<size_t>(limit, 1, 500);
  db_.withLock([&](sqlite3* db) {
    std::string sql =
        "SELECT id, ts_ms, rule_id, rule_name, risk_score, risk_level, process_name, pid, exe_path,"
        " destination, country_code, what_happened, evidences_json, classification_reason, possible_actions_json, acknowledged "
        "FROM security_alerts WHERE 1=1";
    if (!levelFilter.empty()) sql += " AND risk_level = ?";
    if (unackOnly) sql += " AND acknowledged = 0";
    sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?;";

    SqliteStmt st(db, sql.c_str());
    int idx = 1;
    if (!levelFilter.empty()) st.bindText(idx++, levelFilter);
    st.bindInt64(idx++, static_cast<int64_t>(lim));

    while (st.valid() && st.step() == SQLITE_ROW) {
      SecurityAlertRecord a;
      a.id = st.colInt64(0);
      a.tsMs = static_cast<uint64_t>(st.colInt64(1));
      a.ruleId = st.colText(2);
      a.ruleName = st.colText(3);
      a.riskScore = static_cast<int>(st.colInt64(4));
      a.riskLevel = st.colText(5);
      a.processName = st.colText(6);
      a.pid = static_cast<uint32_t>(std::max<int64_t>(0, st.colInt64(7)));
      a.exePath = st.colText(8);
      a.destination = st.colText(9);
      a.countryCode = st.colText(10);
      a.whatHappened = st.colText(11);
      a.evidencesJson = st.colText(12);
      a.classificationReason = st.colText(13);
      a.possibleActionsJson = st.colText(14);
      a.acknowledged = (st.colInt64(15) != 0);
      out.push_back(std::move(a));
    }
    return true;
  });
  return out;
}

bool HistoryStore::acknowledgeSecurityAlert(int64_t alertId) {
  if (!db_.isOpen() || alertId <= 0) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "UPDATE security_alerts SET acknowledged = 1 WHERE id = ?;");
    st.bindInt64(1, alertId);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

std::vector<SecurityListEntry> HistoryStore::loadSecurityLists() {
  std::vector<SecurityListEntry> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT id, list_kind, target_type, target_value, reason, created_by, created_at_ms "
        "FROM security_lists ORDER BY created_at_ms DESC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      SecurityListEntry e;
      e.id = st.colText(0);
      e.listKind = st.colText(1);
      e.targetType = st.colText(2);
      e.targetValue = st.colText(3);
      e.reason = st.colText(4);
      e.createdBy = st.colText(5);
      e.createdAtMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(6)));
      out.push_back(std::move(e));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertSecurityListEntry(const SecurityListEntry& entry) {
  if (!db_.isOpen() || entry.id.empty() || entry.targetValue.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO security_lists(id, list_kind, target_type, target_value, reason, created_by, created_at_ms) "
        "VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET list_kind=excluded.list_kind, reason=excluded.reason;");
    st.bindText(1, entry.id);
    st.bindText(2, entry.listKind);
    st.bindText(3, entry.targetType);
    st.bindText(4, entry.targetValue);
    st.bindText(5, entry.reason);
    st.bindText(6, entry.createdBy);
    st.bindInt64(7, static_cast<int64_t>(entry.createdAtMs > 0 ? entry.createdAtMs : nowEpochMs()));
    return st.stepDone();
  });
}

bool HistoryStore::deleteSecurityListEntry(const std::string& id) {
  if (!db_.isOpen() || id.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "DELETE FROM security_lists WHERE id = ?;");
    st.bindText(1, id);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

std::vector<FirewallRuleRecord> HistoryStore::loadFirewallRules() {
  std::vector<FirewallRuleRecord> out;
  if (!db_.isOpen()) return out;
  db_.withLock([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "SELECT id, rule_name, direction, action, protocol, remote_ip, remote_port, program_path, os_applied, enabled, created_by, created_at_ms "
        "FROM firewall_rules ORDER BY created_at_ms DESC;");
    while (st.valid() && st.step() == SQLITE_ROW) {
      FirewallRuleRecord f;
      f.id = st.colText(0);
      f.ruleName = st.colText(1);
      f.direction = st.colText(2);
      f.action = st.colText(3);
      f.protocol = st.colText(4);
      f.remoteIp = st.colText(5);
      f.remotePort = static_cast<uint16_t>(std::clamp<int64_t>(st.colInt64(6), 0, 65535));
      f.programPath = st.colText(7);
      f.osApplied = (st.colInt64(8) != 0);
      f.enabled = (st.colInt64(9) != 0);
      f.createdBy = st.colText(10);
      f.createdAtMs = static_cast<uint64_t>(std::max<int64_t>(0, st.colInt64(11)));
      out.push_back(std::move(f));
    }
    return true;
  });
  return out;
}

bool HistoryStore::upsertFirewallRule(const FirewallRuleRecord& fw) {
  if (!db_.isOpen() || fw.id.empty() || fw.ruleName.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(
        db,
        "INSERT INTO firewall_rules(id, rule_name, direction, action, protocol, remote_ip, remote_port, program_path, os_applied, enabled, created_by, created_at_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET os_applied=excluded.os_applied, enabled=excluded.enabled;");
    st.bindText(1, fw.id);
    st.bindText(2, fw.ruleName);
    st.bindText(3, fw.direction);
    st.bindText(4, fw.action);
    st.bindText(5, fw.protocol);
    st.bindText(6, fw.remoteIp);
    st.bindInt64(7, static_cast<int64_t>(fw.remotePort));
    st.bindText(8, fw.programPath);
    st.bindInt64(9, fw.osApplied ? 1 : 0);
    st.bindInt64(10, fw.enabled ? 1 : 0);
    st.bindText(11, fw.createdBy);
    st.bindInt64(12, static_cast<int64_t>(fw.createdAtMs > 0 ? fw.createdAtMs : nowEpochMs()));
    return st.stepDone();
  });
}

bool HistoryStore::deleteFirewallRule(const std::string& id) {
  if (!db_.isOpen() || id.empty()) return false;
  return db_.withTransaction([&](sqlite3* db) {
    SqliteStmt st(db, "DELETE FROM firewall_rules WHERE id = ?;");
    st.bindText(1, id);
    if (!st.stepDone()) return false;
    return sqlite3_changes(db) > 0;
  });
}

} // namespace netpulse
