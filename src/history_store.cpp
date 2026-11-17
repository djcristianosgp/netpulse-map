#include "history_store.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr uint64_t kRetentionMs = 7ULL * 24ULL * 3600ULL * 1000ULL;

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string sanitizeTsv(std::string s) {
  for (char& c : s) {
    if (c == '\t' || c == '\r' || c == '\n') c = ' ';
  }
  return s;
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

HistoryStore::HistoryStore(std::filesystem::path dataDir)
    : eventsPath_(dataDir / "events_history.tsv"),
      metricsPath_(dataDir / "service_metrics.tsv"),
      startupWarmupEndMs_(nowEpochMs() + 6000) {
  loadFromDisk();
}

void HistoryStore::setAlertCallback(AlertCallback cb) {
  std::lock_guard lock(mutex_);
  alertCb_ = std::move(cb);
}

void HistoryStore::setNotificationCategories(const NotificationCategories& cats) {
  std::lock_guard lock(mutex_);
  categories_ = cats;
}

bool HistoryStore::shouldNotifyKind(const std::string& kind) const {
  if (!alertsEnabled_.load()) return false;
  std::lock_guard lock(mutex_);
  if (kind == "service_down" || kind == "service_up") return categories_.serviceDown;
  if (kind == "service_degraded") return categories_.serviceDegraded;
  if (kind == "sensitive_port") return categories_.sensitivePort;
  if (kind == "new_country") return categories_.newCountry;
  return true;
}

void HistoryStore::loadFromDisk() {
  const uint64_t cutoff = (nowEpochMs() > kRetentionMs) ? (nowEpochMs() - kRetentionMs) : 0;

  std::error_code ec;
  if (std::filesystem::exists(eventsPath_, ec)) {
    std::ifstream in(eventsPath_);
    std::string line;
    while (std::getline(in, line)) {
      if (line.empty()) continue;
      std::vector<std::string> cols;
      std::stringstream ss(line);
      std::string item;
      while (std::getline(ss, item, '\t')) cols.push_back(item);
      if (cols.size() < 5) continue;
      uint64_t ts = std::strtoull(cols[0].c_str(), nullptr, 10);
      if (ts < cutoff) continue;
      events_.push_back(HistoryEvent{ts, cols[1], cols[2], cols[3], cols[4]});
      if (events_.size() > 400) events_.pop_front();
    }
  }

  if (std::filesystem::exists(metricsPath_, ec)) {
    std::ifstream in(metricsPath_);
    std::string line;
    while (std::getline(in, line)) {
      if (line.empty()) continue;
      std::vector<std::string> cols;
      std::stringstream ss(line);
      std::string item;
      while (std::getline(ss, item, '\t')) cols.push_back(item);
      if (cols.size() < 4) continue;
      uint64_t ts = std::strtoull(cols[0].c_str(), nullptr, 10);
      if (ts < cutoff) continue;
      auto& q = serviceSeries_[cols[1]];
      q.push_back(ServiceMetricPoint{ts, cols[1], cols[2], std::strtod(cols[3].c_str(), nullptr)});
      if (q.size() > 120) q.pop_front();
    }
  }
}

void HistoryStore::appendEvent(HistoryEvent ev, bool notifyTray) {
  AlertCallback cb;
  {
    std::lock_guard lock(mutex_);
    events_.push_front(ev);
    while (events_.size() > 400) events_.pop_back();
    cb = alertCb_;
  }

  std::error_code ec;
  std::filesystem::create_directories(eventsPath_.parent_path(), ec);
  std::ofstream out(eventsPath_, std::ios::app);
  if (out.is_open()) {
    out << ev.tsMs << '\t'
        << sanitizeTsv(ev.severity) << '\t'
        << sanitizeTsv(ev.kind) << '\t'
        << sanitizeTsv(ev.title) << '\t'
        << sanitizeTsv(ev.detail) << '\n';
  }

  if (notifyTray && alertsEnabled_.load() && cb) {
    cb(ev.title, ev.detail, ev.severity != "info");
  }
}

void HistoryStore::appendServicePoint(const ServiceMetricPoint& pt) {
  {
    std::lock_guard lock(mutex_);
    auto& q = serviceSeries_[pt.serviceId];
    q.push_back(pt);
    while (q.size() > 120) q.pop_front();
  }

  std::error_code ec;
  std::filesystem::create_directories(metricsPath_.parent_path(), ec);
  std::ofstream out(metricsPath_, std::ios::app);
  if (out.is_open()) {
    out << pt.tsMs << '\t'
        << sanitizeTsv(pt.serviceId) << '\t'
        << sanitizeTsv(pt.status) << '\t'
        << pt.latencyMs << '\n';
  }
}

void HistoryStore::processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns) {
  const uint64_t now = snap.timestampMs;
  const bool warmedUp = (now >= startupWarmupEndMs_);

  std::vector<HistoryEvent> pendingEvents;

  {
    std::lock_guard lock(mutex_);
    // Prune cooldown map occasionally
    if (alertCooldownMs_.size() > 512) {
      for (auto it = alertCooldownMs_.begin(); it != alertCooldownMs_.end();) {
        if (now > it->second && (now - it->second) > 300000) it = alertCooldownMs_.erase(it);
        else ++it;
      }
    }

    for (const auto& c : snap.connections) {
      if (c.scope != IpScope::Public || c.lifecycle != Lifecycle::New) continue;

      if (isSensitivePort(c.remotePort)) {
        std::string cdKey = "port:" + c.processName + ":" + c.remoteIp + ":" + std::to_string(c.remotePort);
        auto cdIt = alertCooldownMs_.find(cdKey);
        if (cdIt == alertCooldownMs_.end() || (now - cdIt->second) > 120000) {
          alertCooldownMs_[cdKey] = now;
          pendingEvents.push_back(HistoryEvent{
              now,
              "warn",
              "sensitive_port",
              "Porta sensível detectada (" + std::to_string(c.remotePort) + ")",
              c.processName + " -> " + c.remoteIp + ":" + std::to_string(c.remotePort),
          });
        }
      }

      if (auto g = geoDns.getGeo(c.remoteIp); g.has_value() && !g->countryCode.empty()) {
        if (seenCountries_.insert(g->countryCode).second && warmedUp) {
          pendingEvents.push_back(HistoryEvent{
              now,
              "info",
              "new_country",
              "Novo país acessado: " + g->country + " (" + g->countryCode + ")",
              c.processName + " conectou em " + (g->city.empty() ? g->country : g->city) + " (" + c.remoteIp + ")",
          });
        }
      }
    }
  }

  for (auto& ev : pendingEvents) {
    const bool notify = shouldNotifyKind(ev.kind);
    appendEvent(std::move(ev), notify);
  }
}

void HistoryStore::processServices(const std::vector<ServiceStatus>& services) {
  const uint64_t now = nowEpochMs();
  std::vector<HistoryEvent> transitions;

  for (const auto& s : services) {
    if (s.checksTotal == 0 || s.lastCheckedMs == 0) continue;

    bool shouldSample = false;
    {
      std::lock_guard lock(mutex_);
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
    }

    if (shouldSample) {
      appendServicePoint(ServiceMetricPoint{s.lastCheckedMs, s.target.id, s.status, s.latencyMs});
    }
  }

  for (auto& ev : transitions) {
    const bool notify = shouldNotifyKind(ev.kind);
    appendEvent(std::move(ev), notify);
  }
}

void HistoryStore::recordManualAction(const std::string& severity,
                                      const std::string& title,
                                      const std::string& detail) {
  appendEvent(HistoryEvent{nowEpochMs(), severity, "action", title, detail}, false);
}

std::string HistoryStore::getEventsJson(size_t maxItems) const {
  std::lock_guard lock(mutex_);
  std::string out = "{\"alertsEnabled\":";
  out += (alertsEnabled_.load() ? "true" : "false");
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

std::string HistoryStore::getServiceHistoryJson(const std::string& serviceId, size_t maxPoints) const {
  std::lock_guard lock(mutex_);
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

} // namespace netpulse
