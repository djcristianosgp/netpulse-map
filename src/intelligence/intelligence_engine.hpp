#pragma once

#include "../geo_dns.hpp"
#include "../history_store.hpp"
#include "../models.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace netpulse {

struct ProcessBehaviorBaseline {
  double ewmaBps = 0.0;
  double ewmaPublicConns = 0.0;
  uint64_t sampleCount = 0;
  uint64_t lastSeenMs = 0;
};

// Pure deterministic helpers exposed for unit testing
std::string riskLevelFromScore(int score);
bool isUnusualExecutablePath(const std::string& exePath);
std::string buildJsonStringArray(const std::vector<std::string>& items);

class IntelligenceEngine {
public:
  explicit IntelligenceEngine(HistoryStore& history);

  void processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns);

  std::string getOverviewJson(size_t maxAlerts = 120,
                              const std::string& levelFilter = {},
                              bool unackOnly = false) const;

  bool upsertRule(SecurityRuleRecord& rule);
  bool deleteRule(const std::string& id);
  bool acknowledgeAlert(int64_t alertId);

  bool addListEntry(const std::string& listKind,
                    const std::string& targetType,
                    const std::string& targetValue,
                    const std::string& reason,
                    const std::string& actor,
                    SecurityListEntry& outEntry,
                    std::string& outError);
  bool removeListEntry(const std::string& id);

  bool createFirewallRule(const std::string& ruleName,
                          const std::string& direction,
                          const std::string& action,
                          const std::string& protocol,
                          const std::string& remoteIp,
                          uint16_t remotePort,
                          const std::string& programPath,
                          bool applyToOs,
                          bool isElevated,
                          const std::string& actor,
                          FirewallRuleRecord& outRule,
                          std::string& outError);
  bool removeFirewallRuleById(const std::string& id, bool isElevated, std::string& outError);

  std::vector<SecurityAlertRecord> getRecentAlertsSnapshot(size_t limit = 60) const;

private:
  void seedDefaultRulesLocked();
  bool isAllowlistedLocked(const std::string& proc, const std::string& ip, uint16_t port) const;
  bool matchesBlocklistLocked(const std::string& proc,
                              const std::string& ip,
                              uint16_t port,
                              std::string& outReason) const;
  bool shouldEmitWithCooldownLocked(const std::string& dedupKey, uint64_t nowMs, uint64_t cooldownMs = 120000ULL);
  void emitAlert(const SecurityAlertRecord& alert);

  HistoryStore& history_;
  mutable std::mutex mutex_;

  std::vector<SecurityRuleRecord> rules_;
  std::vector<SecurityListEntry> lists_;
  std::vector<FirewallRuleRecord> firewallRules_;
  std::vector<SecurityAlertRecord> recentAlerts_;

  std::unordered_map<std::string, ProcessBehaviorBaseline> procBaselines_;
  double nicEwmaBps_ = 0.0;
  uint64_t evalTickCount_ = 0;

  std::unordered_set<std::string> seenCountries_;
  std::unordered_set<std::string> seenExternalProcs_;
  std::unordered_set<std::string> seenDestinations_;
  std::unordered_map<std::string, uint64_t> alertCooldownMs_;
};

} // namespace netpulse
