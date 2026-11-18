#include "intelligence_engine.hpp"
#include "../actions.hpp"
#include "../core/json_lite.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <sstream>

namespace netpulse {
namespace {

std::string toLowerCopy(std::string s) {
  for (char& ch : s) {
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    }
  }
  return s;
}

uint64_t currentEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string makeShortId(const std::string& prefix, uint64_t tsMs) {
  static uint64_t counter = 0;
  ++counter;
  return prefix + "-" + std::to_string(tsMs) + "-" + std::to_string(counter);
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) {
    return true;
  }
  return toLowerCopy(haystack).find(toLowerCopy(needle)) != std::string::npos;
}

std::string formatMbps(double bps) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.2f Mbps", (bps * 8.0) / 1000000.0);
  return std::string(buf);
}

std::string formatBytesSec(double bps) {
  char buf[64];
  if (bps >= 1000000.0) {
    std::snprintf(buf, sizeof(buf), "%.2f MB/s", bps / 1000000.0);
  } else if (bps >= 1000.0) {
    std::snprintf(buf, sizeof(buf), "%.1f KB/s", bps / 1000.0);
  } else {
    std::snprintf(buf, sizeof(buf), "%.0f B/s", bps);
  }
  return std::string(buf);
}

int clampScore(int s) {
  if (s < 0) return 0;
  if (s > 100) return 100;
  return s;
}

} // namespace

std::string riskLevelFromScore(int score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "moderate";
  if (score >= 20) return "low";
  return "informative";
}

bool isUnusualExecutablePath(const std::string& exePath) {
  if (exePath.empty()) {
    return false;
  }
  std::string lower = toLowerCopy(exePath);
  std::replace(lower.begin(), lower.end(), '/', '\\');
  static const char* const kUnusualMarkers[] = {
      "\\temp\\",
      "\\tmp\\",
      "\\appdata\\local\\temp\\",
      "\\users\\public\\",
      "\\downloads\\",
      "\\perflogs\\",
      "\\dev\\shm\\",
      "\\var\\tmp\\",
  };
  for (const char* marker : kUnusualMarkers) {
    if (lower.find(marker) != std::string::npos) {
      return true;
    }
  }
  if (lower.rfind("\\tmp\\", 0) == 0 || lower.rfind("\\var\\tmp\\", 0) == 0 || lower.rfind("\\dev\\shm\\", 0) == 0) {
    return true;
  }
  return false;
}

std::string buildJsonStringArray(const std::vector<std::string>& items) {
  std::string out = "[";
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      out += ",";
    }
    appendJsonEscaped(out, items[i]);
  }
  out += "]";
  return out;
}

static std::string safeJsonArrayOrFallback(const std::string& raw) {
  if (raw.empty()) return "[]";
  JsonValue parsed;
  std::string err;
  if (JsonValue::parse(raw, parsed, err) && parsed.isArray()) {
    return raw;
  }
  return buildJsonStringArray({raw});
}

IntelligenceEngine::IntelligenceEngine(HistoryStore& history) : history_(history) {
  std::lock_guard<std::mutex> lock(mutex_);
  rules_ = history_.loadSecurityRules();
  seedDefaultRulesLocked();
  lists_ = history_.loadSecurityLists();
  firewallRules_ = history_.loadFirewallRules();
  recentAlerts_ = history_.loadSecurityAlerts(150);
  for (const auto& a : recentAlerts_) {
    if (!a.countryCode.empty()) {
      seenCountries_.insert(a.countryCode);
    }
    if (!a.processName.empty()) {
      seenExternalProcs_.insert(toLowerCopy(a.processName));
    }
  }
}

void IntelligenceEngine::seedDefaultRulesLocked() {
  if (!rules_.empty()) {
    return;
  }
  const uint64_t now = currentEpochMs();
  const std::vector<SecurityRuleRecord> defaults = {
      {"builtin-high-conn-rate", "Alta Taxa de Conexoes por Processo", "high_connection_rate", true, 50, 25.0, "", 0, "",
       "Detecta processos abrindo quantidade elevada de sockets externos ou pico acima da linha base EWMA.", true, now},
      {"builtin-unseen-country", "Pais Ainda Nao Acessado", "unseen_country", true, 22, 1.0, "", 0, "",
       "Registra primeiro contato observado com um codigo de pais (geolocalizacao isolada nao indica malicia).", true, now},
      {"builtin-unknown-dest", "Destino Sem Identificacao DNS/ASN", "unknown_destination", true, 32, 1.0, "", 0, "",
       "Conexao externa em porta nao-HTTP/HTTPS sem rDNS e sem ASN/Geo conhecido.", true, now},
      {"builtin-abnormal-traffic", "Consumo Anormal de Banda (EWMA)", "abnormal_traffic_volume", true, 58, 3.5, "", 0, "",
       "Dispara quando o trafego do processo excede 3.5x a media movel exponencial (EWMA) + margem minima.", true, now},
      {"builtin-persistent-conn", "Conexao Externa Persistente", "persistent_connection", true, 28, 1800.0, "", 0, "",
       "Identifica conexoes ESTABLISHED externas mantidas ativas por periodo prolongado (>= threshold s).", true, now},
      {"builtin-traffic-shift", "Mudanca Abrupta no Padrao de Trafego", "traffic_pattern_shift", true, 48, 4.0, "", 0, "",
       "Detecta variacao brusca global na banda ou salto subito de destinos unicos por processo.", true, now},
      {"builtin-failed-conns", "Tentativas Repetidas em SYN_SENT", "repeated_failed_connections", true, 55, 4.0, "", 0, "",
       "Muitas conexoes em estado SYN_SENT simultaneamente indicam falhas de handshake ou varredura.", true, now},
      {"builtin-sensitive-port", "Uso de Porta Sensivel", "sensitive_port_usage", true, 42, 1.0, "", 0, "",
       "Monitora trafego para portas administrativas ou de banco/transferencia (21,22,23,25,135,139,445,1433,3306,3389,4444,5432,5900,6379).", true, now},
      {"builtin-unusual-path", "Executavel em Caminho Incomum", "unusual_process_path", true, 65, 1.0, "", 0, "",
       "Processo comunicando externamente a partir de diretorios temporarios, Downloads ou Public.", true, now},
      {"custom-tpl-country-watch", "Regra Exemplo: Monitorar Pais Especifico", "country_watch", false, 35, 1.0, "RU", 0, "",
       "Template personalizavel: alerta quando o processo configurado conectar ao pais indicado.", false, now},
      {"custom-tpl-bandwidth-cap", "Regra Exemplo: Limite de Banda (Mbps)", "bandwidth_threshold", false, 50, 50.0, "", 0, "",
       "Template personalizavel: alerta quando um processo ultrapassar threshold_num Mbps.", false, now},
      {"custom-tpl-new-proc", "Regra Exemplo: Novo Processo Externo", "new_external_process", false, 25, 1.0, "", 0, "",
       "Template personalizavel: alerta quando um executavel estabelece conexao externa pela primeira vez na sessao.", false, now},
  };
  for (const auto& r : defaults) {
    history_.upsertSecurityRule(r);
    rules_.push_back(r);
  }
}

bool IntelligenceEngine::isAllowlistedLocked(const std::string& proc, const std::string& ip, uint16_t port) const {
  const std::string procLower = toLowerCopy(proc);
  for (const auto& entry : lists_) {
    if (entry.listKind != "allowlist") {
      continue;
    }
    if (entry.targetType == "ip" && !ip.empty() && entry.targetValue == ip) {
      return true;
    }
    if (entry.targetType == "process" && !procLower.empty() && toLowerCopy(entry.targetValue) == procLower) {
      return true;
    }
    if (entry.targetType == "port" && port != 0 && entry.targetValue == std::to_string(port)) {
      return true;
    }
  }
  return false;
}

bool IntelligenceEngine::matchesBlocklistLocked(const std::string& proc,
                                                  const std::string& ip,
                                                  uint16_t port,
                                                  std::string& outReason) const {
  const std::string procLower = toLowerCopy(proc);
  for (const auto& entry : lists_) {
    if (entry.listKind != "blocklist") {
      continue;
    }
    if (entry.targetType == "ip" && !ip.empty() && entry.targetValue == ip) {
      outReason = entry.reason.empty() ? "IP presente na blocklist configurada" : entry.reason;
      return true;
    }
    if (entry.targetType == "process" && !procLower.empty() && toLowerCopy(entry.targetValue) == procLower) {
      outReason = entry.reason.empty() ? "Processo presente na blocklist configurada" : entry.reason;
      return true;
    }
    if (entry.targetType == "port" && port != 0 && entry.targetValue == std::to_string(port)) {
      outReason = entry.reason.empty() ? "Porta presente na blocklist configurada" : entry.reason;
      return true;
    }
  }
  return false;
}

bool IntelligenceEngine::shouldEmitWithCooldownLocked(const std::string& dedupKey,
                                                        uint64_t nowMs,
                                                        uint64_t cooldownMs) {
  auto it = alertCooldownMs_.find(dedupKey);
  if (it != alertCooldownMs_.end() && nowMs >= it->second && (nowMs - it->second) < cooldownMs) {
    return false;
  }
  alertCooldownMs_[dedupKey] = nowMs;
  if (alertCooldownMs_.size() > 2048) {
    for (auto p = alertCooldownMs_.begin(); p != alertCooldownMs_.end();) {
      if (nowMs > p->second && (nowMs - p->second) > cooldownMs * 4) {
        p = alertCooldownMs_.erase(p);
      } else {
        ++p;
      }
    }
  }
  return true;
}

void IntelligenceEngine::setAlertEmitCallback(AlertEmitCallback cb) {
  std::lock_guard<std::mutex> lock(mutex_);
  alertEmitCb_ = std::move(cb);
}

void IntelligenceEngine::emitAlert(const SecurityAlertRecord& alert) {
  SecurityAlertRecord persisted = alert;
  persisted.riskScore = clampScore(persisted.riskScore);
  persisted.riskLevel = riskLevelFromScore(persisted.riskScore);
  if (persisted.tsMs == 0) {
    persisted.tsMs = currentEpochMs();
  }
  const int64_t newId = history_.saveSecurityAlert(persisted);
  persisted.id = newId;

  AlertEmitCallback cb;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    recentAlerts_.insert(recentAlerts_.begin(), persisted);
    if (recentAlerts_.size() > 200) {
      recentAlerts_.resize(200);
    }
    cb = alertEmitCb_;
  }
  if (cb) {
    cb(persisted);
  }
}

void IntelligenceEngine::processTelemetry(const TelemetrySnapshot& snap, const GeoDnsService& geoDns) {
  const uint64_t now = snap.timestampMs > 0 ? snap.timestampMs : currentEpochMs();
  std::vector<SecurityAlertRecord> pendingAlerts;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    ++evalTickCount_;

    auto findEnabledRules = [&](const std::string& kind) {
      std::vector<SecurityRuleRecord> matches;
      for (const auto& r : rules_) {
        if (r.enabled && r.kind == kind) {
          matches.push_back(r);
        }
      }
      return matches;
    };

    const auto rulesHighConn = findEnabledRules("high_connection_rate");
    const auto rulesUnseenCountry = findEnabledRules("unseen_country");
    const auto rulesUnknownDest = findEnabledRules("unknown_destination");
    const auto rulesAbnormalTraffic = findEnabledRules("abnormal_traffic_volume");
    const auto rulesPersistent = findEnabledRules("persistent_connection");
    const auto rulesTrafficShift = findEnabledRules("traffic_pattern_shift");
    const auto rulesFailedConns = findEnabledRules("repeated_failed_connections");
    const auto rulesSensitivePort = findEnabledRules("sensitive_port_usage");
    const auto rulesUnusualPath = findEnabledRules("unusual_process_path");

    const auto rulesCountryWatch = findEnabledRules("country_watch");
    const auto rulesBwThreshold = findEnabledRules("bandwidth_threshold");
    const auto rulesConnDuration = findEnabledRules("connection_duration");
    const auto rulesPortWatch = findEnabledRules("sensitive_port_watch");
    const auto rulesNewProc = findEnabledRules("new_external_process");
    const auto rulesConnBurst = findEnabledRules("connection_burst");

    struct ProcAgg {
      uint32_t pid = 0;
      std::string procName;
      std::string exePath;
      uint32_t publicConns = 0;
      uint32_t synSentCount = 0;
      double totalBps = 0.0;
      std::unordered_set<std::string> uniqueRemoteIps;
      std::vector<const SocketEntry*> publicSockets;
    };

    std::unordered_map<std::string, ProcAgg> procMap;
    for (const auto& c : snap.connections) {
      if (c.scope != IpScope::Public) {
        continue;
      }
      const std::string procKey = toLowerCopy(c.processName.empty() ? ("pid-" + std::to_string(c.pid)) : c.processName);
      auto& agg = procMap[procKey];
      if (agg.procName.empty()) {
        agg.pid = c.pid;
        agg.procName = c.processName;
        agg.exePath = c.processPath;
      }
      ++agg.publicConns;
      if (c.state == "SYN_SENT") {
        ++agg.synSentCount;
      }
      if (!c.remoteIp.empty()) {
        agg.uniqueRemoteIps.insert(c.remoteIp);
      }
      agg.publicSockets.push_back(&c);
    }

    for (const auto& ps : snap.processStats) {
      const std::string procKey = toLowerCopy(ps.processName.empty() ? ("pid-" + std::to_string(ps.pid)) : ps.processName);
      auto& agg = procMap[procKey];
      if (agg.procName.empty()) {
        agg.pid = ps.pid;
        agg.procName = ps.processName;
        agg.exePath = ps.processPath;
      }
      agg.totalBps = std::max(agg.totalBps, ps.rxBps + ps.txBps);
      if (agg.publicConns == 0 && ps.publicConnections > 0) {
        agg.publicConns = ps.publicConnections;
      }
    }

    const double globalBps = snap.nic.rxBytesPerSec + snap.nic.txBytesPerSec;
    const bool baselineReady = evalTickCount_ >= 10 && nicEwmaBps_ > 25000.0;
    if (baselineReady && !rulesTrafficShift.empty()) {
      const double ratioThreshold = std::max(2.0, rulesTrafficShift.front().thresholdNum);
      if (globalBps > nicEwmaBps_ * ratioThreshold && globalBps > 500000.0) {
        if (shouldEmitWithCooldownLocked("shift|global", now, 120000ULL)) {
          const auto& rule = rulesTrafficShift.front();
          int score = clampScore(rule.riskWeight + (globalBps > nicEwmaBps_ * 8.0 ? 18 : 8));
          SecurityAlertRecord a;
          a.tsMs = now;
          a.ruleId = rule.id;
          a.ruleName = rule.name;
          a.riskScore = score;
          a.riskLevel = riskLevelFromScore(score);
          a.processName = "Host NIC";
          a.destination = "NIC agregada (" + std::to_string(snap.nic.activeInterfaces) + " interfaces)";
          a.whatHappened = "Salto abrupto no trafego agregado da interface: " + formatMbps(globalBps) +
                           " contra media base EWMA de " + formatMbps(nicEwmaBps_) + ".";
          a.evidencesJson = buildJsonStringArray({
              "Interfaces ativas: " + std::to_string(snap.nic.activeInterfaces),
              "Taxa atual: " + formatMbps(globalBps),
              "Linha base EWMA: " + formatMbps(nicEwmaBps_),
              "Conexoes publicas ativas: " + std::to_string(snap.publicConnections),
          });
          a.classificationReason = "Score " + std::to_string(score) + " (base regra=" +
                                   std::to_string(rule.riskWeight) + " + multiplicador EWMA) -> " + a.riskLevel;
          a.possibleActionsJson = buildJsonStringArray({"Inspecionar Top Processos", "Abrir Analytics de Trafego"});
          pendingAlerts.push_back(std::move(a));
        }
      }
    }
    nicEwmaBps_ = (evalTickCount_ <= 1) ? globalBps : (0.15 * globalBps + 0.85 * nicEwmaBps_);

    for (const auto& [procKey, agg] : procMap) {
      const std::string procDisplay = agg.procName.empty() ? ("pid-" + std::to_string(agg.pid)) : agg.procName;
      auto& base = procBaselines_[procKey];
      const bool procHasHistory = base.sampleCount >= 5;

      // 1) Blocklist check first (takes priority even if anything else exists)
      for (const SocketEntry* c : agg.publicSockets) {
        std::string blkReason;
        if (matchesBlocklistLocked(procDisplay, c->remoteIp, c->remotePort, blkReason)) {
          if (shouldEmitWithCooldownLocked("blocklist|" + procKey + "|" + c->remoteIp + "|" + std::to_string(c->remotePort),
                                           now, 60000ULL)) {
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = "sys-blocklist-hit";
            a.ruleName = "Correspondencia em Blocklist";
            a.riskScore = 90;
            a.riskLevel = riskLevelFromScore(90);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
            a.whatHappened = "Atividade detectada envolvendo alvo explicitamente listado na Blocklist (" + blkReason + ").";
            a.evidencesJson = buildJsonStringArray({
                "Processo: " + procDisplay + " (PID " + std::to_string(agg.pid) + ")",
                "Destino: " + a.destination,
                "Motivo da lista: " + blkReason,
            });
            a.classificationReason = "Score 90 -> critical: politica explicita de blocklist acionada.";
            a.possibleActionsJson = buildJsonStringArray({"Criar Regra Firewall BLOCK", "Encerrar Processo"});
            pendingAlerts.push_back(std::move(a));
          }
        }
      }

      const bool procAllowlisted = isAllowlistedLocked(procDisplay, "", 0);

      // 2) Unusual executable path
      if (!procAllowlisted && !rulesUnusualPath.empty() && agg.publicConns > 0 && isUnusualExecutablePath(agg.exePath)) {
        if (shouldEmitWithCooldownLocked("unusual_path|" + procKey, now, 180000ULL)) {
          const auto& rule = rulesUnusualPath.front();
          int score = clampScore(rule.riskWeight + (agg.publicConns > 5 ? 12 : 0));
          SecurityAlertRecord a;
          a.tsMs = now;
          a.ruleId = rule.id;
          a.ruleName = rule.name;
          a.riskScore = score;
          a.riskLevel = riskLevelFromScore(score);
          a.processName = procDisplay;
          a.pid = agg.pid;
          a.exePath = agg.exePath;
          a.destination = agg.publicSockets.empty() ? "" : agg.publicSockets.front()->remoteIp;
          a.whatHappened = "Executavel em caminho incomum (" + agg.exePath + ") realizou conexoes externas.";
          a.evidencesJson = buildJsonStringArray({
              "Executavel: " + agg.exePath,
              "Conexoes publicas: " + std::to_string(agg.publicConns),
              "Banda estimada: " + formatBytesSec(agg.totalBps),
          });
          a.classificationReason = "Score " + std::to_string(score) + " (peso regra=" +
                                   std::to_string(rule.riskWeight) + ") -> " + a.riskLevel;
          a.possibleActionsJson = buildJsonStringArray({"Bloquear Executavel no Firewall", "Adicionar a Allowlist"});
          pendingAlerts.push_back(std::move(a));
        }
      }

      // 3) High connection rate & connection burst
      if (!procAllowlisted) {
        const auto evaluateRate = [&](const SecurityRuleRecord& rule, const std::string& keyPrefix) {
          if (!rule.matchProcess.empty() && !containsCaseInsensitive(procDisplay, rule.matchProcess)) {
            return;
          }
          const double limit = rule.thresholdNum > 0 ? rule.thresholdNum : 25.0;
          const bool ewmaSpike = procHasHistory && base.ewmaPublicConns >= 3.0 &&
                                 agg.publicConns >= static_cast<uint32_t>(std::ceil(base.ewmaPublicConns * 3.0)) &&
                                 agg.publicConns >= 10;
          if (static_cast<double>(agg.publicConns) >= limit || ewmaSpike) {
            if (shouldEmitWithCooldownLocked(keyPrefix + "|" + rule.id + "|" + procKey, now, 120000ULL)) {
              const int bonus = agg.publicConns >= static_cast<uint32_t>(limit * 2.0) ? 18 : 8;
              const int score = clampScore(rule.riskWeight + bonus);
              SecurityAlertRecord a;
              a.tsMs = now;
              a.ruleId = rule.id;
              a.ruleName = rule.name;
              a.riskScore = score;
              a.riskLevel = riskLevelFromScore(score);
              a.processName = procDisplay;
              a.pid = agg.pid;
              a.exePath = agg.exePath;
              a.destination = std::to_string(agg.uniqueRemoteIps.size()) + " IPs unicos";
              a.whatHappened = "Processo " + procDisplay + " manteve " + std::to_string(agg.publicConns) +
                               " conexoes publicas simultaneas (limite=" + std::to_string(static_cast<int>(limit)) + ").";
              a.evidencesJson = buildJsonStringArray({
                  "Sockets publicos: " + std::to_string(agg.publicConns),
                  "IPs remotos distintos: " + std::to_string(agg.uniqueRemoteIps.size()),
                  "Media base EWMA sockets: " + std::to_string(static_cast<int>(std::round(base.ewmaPublicConns))),
              });
              a.classificationReason = "Score " + std::to_string(score) + " (base=" +
                                       std::to_string(rule.riskWeight) + " + excesso=" + std::to_string(bonus) +
                                       ") -> " + a.riskLevel;
              a.possibleActionsJson = buildJsonStringArray({"Adicionar Processo a Allowlist", "Criar Regra Firewall"});
              pendingAlerts.push_back(std::move(a));
            }
          }
        };
        for (const auto& r : rulesHighConn) evaluateRate(r, "rate");
        for (const auto& r : rulesConnBurst) evaluateRate(r, "burst");
      }

      // 4) Repeated failed connections (SYN_SENT)
      if (!procAllowlisted && !rulesFailedConns.empty()) {
        const auto& rule = rulesFailedConns.front();
        const uint32_t minFailed = static_cast<uint32_t>(std::max(2.0, rule.thresholdNum));
        if (agg.synSentCount >= minFailed) {
          if (shouldEmitWithCooldownLocked("synsent|" + procKey, now, 120000ULL)) {
            const int score = clampScore(rule.riskWeight + (agg.synSentCount >= minFailed * 2 ? 15 : 5));
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = rule.id;
            a.ruleName = rule.name;
            a.riskScore = score;
            a.riskLevel = riskLevelFromScore(score);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = std::to_string(agg.synSentCount) + " sockets SYN_SENT";
            a.whatHappened = "Processo " + procDisplay + " acumulou " + std::to_string(agg.synSentCount) +
                             " tentativas simultaneas sem conclusao de handshake (SYN_SENT).";
            a.evidencesJson = buildJsonStringArray({
                "Sockets em SYN_SENT: " + std::to_string(agg.synSentCount),
                "Limiar configurado: " + std::to_string(minFailed),
                "IPs distintos: " + std::to_string(agg.uniqueRemoteIps.size()),
            });
            a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                     ": multiplas tentativas SYN_SENT simultaneas.";
            a.possibleActionsJson = buildJsonStringArray({"Investigar Destinos", "Bloquear Processo"});
            pendingAlerts.push_back(std::move(a));
          }
        }
      }

      // 5) Abnormal traffic volume (EWMA) + user bandwidth_threshold
      if (!procAllowlisted && agg.totalBps > 0.0) {
        if (!rulesAbnormalTraffic.empty() && procHasHistory) {
          const auto& rule = rulesAbnormalTraffic.front();
          const double mult = std::max(2.0, rule.thresholdNum);
          if (base.ewmaBps > 10000.0 && agg.totalBps > base.ewmaBps * mult && agg.totalBps > 250000.0) {
            if (shouldEmitWithCooldownLocked("ewma_bw|" + procKey, now, 120000ULL)) {
              const int score = clampScore(rule.riskWeight + (agg.totalBps > base.ewmaBps * 6.0 ? 14 : 6));
              SecurityAlertRecord a;
              a.tsMs = now;
              a.ruleId = rule.id;
              a.ruleName = rule.name;
              a.riskScore = score;
              a.riskLevel = riskLevelFromScore(score);
              a.processName = procDisplay;
              a.pid = agg.pid;
              a.exePath = agg.exePath;
              a.destination = formatBytesSec(agg.totalBps);
              a.whatHappened = "Consumo de " + procDisplay + " (" + formatMbps(agg.totalBps) +
                               ") superou a linha base EWMA (" + formatMbps(base.ewmaBps) + ").";
              a.evidencesJson = buildJsonStringArray({
                  "Taxa atual: " + formatMbps(agg.totalBps),
                  "Media EWMA do processo: " + formatMbps(base.ewmaBps),
                  "Amostras na linha base: " + std::to_string(base.sampleCount),
              });
              a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                       ": desvio estatistico acima da media EWMA do proprio processo.";
              a.possibleActionsJson = buildJsonStringArray({"Inspecionar Sockets do Processo", "Adicionar a Allowlist"});
              pendingAlerts.push_back(std::move(a));
            }
          }
        }

        const double actualMbps = (agg.totalBps * 8.0) / 1000000.0;
        for (const auto& rule : rulesBwThreshold) {
          if (!rule.matchProcess.empty() && !containsCaseInsensitive(procDisplay, rule.matchProcess)) {
            continue;
          }
          if (rule.thresholdNum > 0.0 && actualMbps >= rule.thresholdNum) {
            if (shouldEmitWithCooldownLocked("bwcap|" + rule.id + "|" + procKey, now, 120000ULL)) {
              const int score = clampScore(rule.riskWeight);
              SecurityAlertRecord a;
              a.tsMs = now;
              a.ruleId = rule.id;
              a.ruleName = rule.name;
              a.riskScore = score;
              a.riskLevel = riskLevelFromScore(score);
              a.processName = procDisplay;
              a.pid = agg.pid;
              a.exePath = agg.exePath;
              a.destination = formatMbps(agg.totalBps);
              a.whatHappened = "Processo " + procDisplay + " atingiu " + formatMbps(agg.totalBps) +
                               " (limite regra: " + std::to_string(static_cast<int>(rule.thresholdNum)) + " Mbps).";
              a.evidencesJson = buildJsonStringArray({
                  "Throughput observado: " + formatMbps(agg.totalBps),
                  "Limite configurado: " + std::to_string(rule.thresholdNum) + " Mbps",
              });
              a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                       ": regra de consumo maximo acionada.";
              a.possibleActionsJson = buildJsonStringArray({"Criar Regra Firewall", "Desativar Regra"});
              pendingAlerts.push_back(std::move(a));
            }
          }
        }
      }

      // 6) New external process (Session-level + user rule)
      if (!procAllowlisted && agg.publicConns > 0 && seenExternalProcs_.find(procKey) == seenExternalProcs_.end()) {
        seenExternalProcs_.insert(procKey);
        for (const auto& rule : rulesNewProc) {
          if (!rule.matchProcess.empty() && !containsCaseInsensitive(procDisplay, rule.matchProcess)) {
            continue;
          }
          if (shouldEmitWithCooldownLocked("newproc|" + rule.id + "|" + procKey, now, 300000ULL)) {
            const int score = clampScore(rule.riskWeight);
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = rule.id;
            a.ruleName = rule.name;
            a.riskScore = score;
            a.riskLevel = riskLevelFromScore(score);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = agg.publicSockets.empty() ? "" : agg.publicSockets.front()->remoteIp;
            a.whatHappened = "Novo processo estabeleceu conexoes externas pela primeira vez: " + procDisplay + ".";
            a.evidencesJson = buildJsonStringArray({
                "Executavel: " + (agg.exePath.empty() ? procDisplay : agg.exePath),
                "Conexoes publicas: " + std::to_string(agg.publicConns),
            });
            a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                     ": processo inedito acessando internet.";
            a.possibleActionsJson = buildJsonStringArray({"Adicionar a Allowlist", "Criar Regra Firewall"});
            pendingAlerts.push_back(std::move(a));
          }
        }
      }

      // 7) Per-socket evaluations (unseen country, unknown destination, sensitive port, persistent connection, country_watch)
      for (const SocketEntry* c : agg.publicSockets) {
        if (procAllowlisted || isAllowlistedLocked(procDisplay, c->remoteIp, c->remotePort)) {
          continue;
        }
        const auto geoOpt = geoDns.getGeo(c->remoteIp);
        const auto hostOpt = geoDns.getHostname(c->remoteIp);
        const std::string cc = geoOpt.has_value() ? geoOpt->countryCode : "";
        const std::string countryName = geoOpt.has_value() ? geoOpt->country : "";

        // 7a) Unseen country (explicitly neutral on malice!)
        if (!cc.empty() && cc != "LOCAL" && seenCountries_.find(cc) == seenCountries_.end()) {
          seenCountries_.insert(cc);
          if (!rulesUnseenCountry.empty() && shouldEmitWithCooldownLocked("country|" + cc, now, 300000ULL)) {
            const auto& rule = rulesUnseenCountry.front();
            const int score = clampScore(rule.riskWeight);
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = rule.id;
            a.ruleName = rule.name;
            a.riskScore = score;
            a.riskLevel = riskLevelFromScore(score);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
            a.countryCode = cc;
            a.whatHappened = "Primeira comunicacao observada com destino geolocalizado em " +
                             (countryName.empty() ? cc : countryName) + " (" + cc +
                             "). Geolocalizacao isolada nao indica malicia.";
            a.evidencesJson = buildJsonStringArray({
                "IP destino: " + c->remoteIp + ":" + std::to_string(c->remotePort),
                "Pais / Codigo: " + (countryName.empty() ? cc : countryName) + " (" + cc + ")",
                "Nota: pais ou geolocalizacao por si so nao constitui evidencia de comportamento malicioso.",
            });
            a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                     ": evento informativo de novo pais sem presuncao de malicia.";
            a.possibleActionsJson = buildJsonStringArray({"Reconhecer Alerta", "Inspecionar Destino"});
            pendingAlerts.push_back(std::move(a));
          }
        }

        // 7b) Custom country_watch
        for (const auto& rule : rulesCountryWatch) {
          if (cc.empty() || rule.matchCountry.empty()) {
            continue;
          }
          if (toLowerCopy(cc) == toLowerCopy(rule.matchCountry) &&
              (rule.matchProcess.empty() || containsCaseInsensitive(procDisplay, rule.matchProcess))) {
            if (shouldEmitWithCooldownLocked("cwatch|" + rule.id + "|" + procKey + "|" + cc, now, 180000ULL)) {
              const int score = clampScore(rule.riskWeight);
              SecurityAlertRecord a;
              a.tsMs = now;
              a.ruleId = rule.id;
              a.ruleName = rule.name;
              a.riskScore = score;
              a.riskLevel = riskLevelFromScore(score);
              a.processName = procDisplay;
              a.pid = agg.pid;
              a.exePath = agg.exePath;
              a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
              a.countryCode = cc;
              a.whatHappened = "Regra configurada pelo usuario detectou conexao de " + procDisplay + " para pais monitorado " +
                               cc + " (geolocalizacao apenas informativa).";
              a.evidencesJson = buildJsonStringArray({
                  "Processo: " + procDisplay,
                  "Destino: " + a.destination,
                  "Pais monitorado: " + cc,
              });
              a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                       ": regra personalizada country_watch acionada.";
              a.possibleActionsJson = buildJsonStringArray({"Reconhecer Alerta", "Criar Regra Firewall"});
              pendingAlerts.push_back(std::move(a));
            }
          }
        }

        // 7c) Unknown destination (no rDNS and no Geo/ASN, non-80/443)
        if (!rulesUnknownDest.empty() && c->remotePort != 80 && c->remotePort != 443 && !hostOpt.has_value() &&
            (!geoOpt.has_value() || (geoOpt->asn.empty() && geoOpt->isp.empty() && geoOpt->countryCode.empty()))) {
          if (shouldEmitWithCooldownLocked("unkdest|" + procKey + "|" + c->remoteIp, now, 240000ULL)) {
            const auto& rule = rulesUnknownDest.front();
            const int score = clampScore(rule.riskWeight);
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = rule.id;
            a.ruleName = rule.name;
            a.riskScore = score;
            a.riskLevel = riskLevelFromScore(score);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
            a.whatHappened = "Conexao para IP publico sem rDNS e sem identificacao Geo/ASN na porta " +
                             std::to_string(c->remotePort) + ".";
            a.evidencesJson = buildJsonStringArray({
                "Destino: " + a.destination,
                "rDNS: ausente",
                "Geo/ASN: indisponivel",
            });
            a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                     ": destino externo nao resolvido fora de portas web padrao.";
            a.possibleActionsJson = buildJsonStringArray({"Bloquear IP", "Adicionar a Allowlist"});
            pendingAlerts.push_back(std::move(a));
          }
        }

        // 7d) Sensitive port usage & custom sensitive_port_watch
        auto emitPortAlert = [&](const SecurityRuleRecord& rule, const std::string& prefix) {
          if (!rule.matchProcess.empty() && !containsCaseInsensitive(procDisplay, rule.matchProcess)) {
            return;
          }
          if (shouldEmitWithCooldownLocked(prefix + "|" + rule.id + "|" + procKey + "|" + std::to_string(c->remotePort),
                                           now, 180000ULL)) {
            const int score = clampScore(rule.riskWeight);
            SecurityAlertRecord a;
            a.tsMs = now;
            a.ruleId = rule.id;
            a.ruleName = rule.name;
            a.riskScore = score;
            a.riskLevel = riskLevelFromScore(score);
            a.processName = procDisplay;
            a.pid = agg.pid;
            a.exePath = agg.exePath;
            a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
            a.countryCode = cc;
            a.whatHappened = "Processo " + procDisplay + " comunicou com porta sensivel/monitorada " +
                             std::to_string(c->remotePort) + " em " + c->remoteIp + ".";
            a.evidencesJson = buildJsonStringArray({
                "Porta remota: " + std::to_string(c->remotePort),
                "Protocolo: " + c->protocol,
                "Destino: " + c->remoteIp,
            });
            a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                     ": comunicacao em porta sensivel configurada.";
            a.possibleActionsJson = buildJsonStringArray({"Criar Regra Firewall Porta", "Adicionar Porta a Allowlist"});
            pendingAlerts.push_back(std::move(a));
          }
        };
        if (!rulesSensitivePort.empty() && isSensitivePort(c->remotePort)) {
          emitPortAlert(rulesSensitivePort.front(), "sensport");
        }
        for (const auto& rule : rulesPortWatch) {
          if (rule.matchPort != 0 && c->remotePort == rule.matchPort) {
            emitPortAlert(rule, "watchport");
          }
        }

        // 7e) Persistent connection (builtin & custom connection_duration)
        if (c->state == "ESTABLISHED" && c->firstSeenMs > 0 && now > c->firstSeenMs) {
          const double durationSec = static_cast<double>(now - c->firstSeenMs) / 1000.0;
          auto evalPersistent = [&](const SecurityRuleRecord& rule, const std::string& prefix) {
            if (!rule.matchProcess.empty() && !containsCaseInsensitive(procDisplay, rule.matchProcess)) {
              return;
            }
            const double minSec = rule.thresholdNum > 0.0 ? rule.thresholdNum : 1800.0;
            if (durationSec >= minSec) {
              if (shouldEmitWithCooldownLocked(prefix + "|" + rule.id + "|" + c->key, now, 300000ULL)) {
                const int score = clampScore(rule.riskWeight);
                SecurityAlertRecord a;
                a.tsMs = now;
                a.ruleId = rule.id;
                a.ruleName = rule.name;
                a.riskScore = score;
                a.riskLevel = riskLevelFromScore(score);
                a.processName = procDisplay;
                a.pid = agg.pid;
                a.exePath = agg.exePath;
                a.destination = c->remoteIp + ":" + std::to_string(c->remotePort);
                a.countryCode = cc;
                a.whatHappened = "Conexao persistente de " + procDisplay + " ativa ha " +
                                 std::to_string(static_cast<int>(durationSec)) + "s (limiar=" +
                                 std::to_string(static_cast<int>(minSec)) + "s).";
                a.evidencesJson = buildJsonStringArray({
                    "Duracao observada: " + std::to_string(static_cast<int>(durationSec)) + "s",
                    "Destino: " + a.destination,
                    "Estado: " + c->state,
                });
                a.classificationReason = "Score " + std::to_string(score) + " -> " + a.riskLevel +
                                         ": sessao mantida continuamente alem do limite.";
                a.possibleActionsJson = buildJsonStringArray({"Reconhecer Alerta", "Adicionar a Allowlist"});
                pendingAlerts.push_back(std::move(a));
              }
            }
          };
          for (const auto& r : rulesPersistent) evalPersistent(r, "persist");
          for (const auto& r : rulesConnDuration) evalPersistent(r, "durwatch");
        }
      }

      // Update per-process EWMA baseline at end of evaluation
      if (base.sampleCount == 0) {
        base.ewmaBps = agg.totalBps;
        base.ewmaPublicConns = static_cast<double>(agg.publicConns);
      } else {
        base.ewmaBps = 0.2 * agg.totalBps + 0.8 * base.ewmaBps;
        base.ewmaPublicConns = 0.2 * static_cast<double>(agg.publicConns) + 0.8 * base.ewmaPublicConns;
      }
      base.sampleCount += 1;
      base.lastSeenMs = now;
    }

    // Periodically prune stale baselines (>30m inactive)
    if (procBaselines_.size() > 512) {
      for (auto it = procBaselines_.begin(); it != procBaselines_.end();) {
        if (now > it->second.lastSeenMs && (now - it->second.lastSeenMs) > 1800000ULL) {
          it = procBaselines_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  for (const auto& alert : pendingAlerts) {
    emitAlert(alert);
  }
}

std::string IntelligenceEngine::getOverviewJson(size_t maxAlerts,
                                                const std::string& levelFilter,
                                                bool unackOnly) const {
  std::vector<SecurityAlertRecord> alertsSnapshot = history_.loadSecurityAlerts(maxAlerts, levelFilter, unackOnly);
  std::lock_guard<std::mutex> lock(mutex_);

  int highestScore = 0;
  int unackCount = 0;
  int counts[5] = {0, 0, 0, 0, 0}; // info, low, mod, high, crit
  for (const auto& a : recentAlerts_) {
    if (!a.acknowledged) {
      ++unackCount;
      highestScore = std::max(highestScore, a.riskScore);
    }
    if (a.riskLevel == "critical") ++counts[4];
    else if (a.riskLevel == "high") ++counts[3];
    else if (a.riskLevel == "moderate") ++counts[2];
    else if (a.riskLevel == "low") ++counts[1];
    else ++counts[0];
  }

  std::string out = "{\"engineMode\":\"deterministic\",\"aiUsed\":false";
  out += ",\"overallRiskScore\":" + std::to_string(highestScore);
  out += ",\"overallRiskLevel\":\"" + riskLevelFromScore(highestScore) + "\"";
  out += ",\"unacknowledgedCount\":" + std::to_string(unackCount);
  out += ",\"trackedProcessBaselines\":" + std::to_string(procBaselines_.size());
  out += ",\"summary\":{\"informative\":" + std::to_string(counts[0]) +
         ",\"low\":" + std::to_string(counts[1]) +
         ",\"moderate\":" + std::to_string(counts[2]) +
         ",\"high\":" + std::to_string(counts[3]) +
         ",\"critical\":" + std::to_string(counts[4]) + "}";

  out += ",\"alerts\":[";
  for (size_t i = 0; i < alertsSnapshot.size(); ++i) {
    const auto& a = alertsSnapshot[i];
    if (i > 0) out += ",";
    out += "{\"id\":" + std::to_string(a.id);
    out += ",\"tsMs\":" + std::to_string(a.tsMs);
    out += ",\"ruleId\":"; appendJsonEscaped(out, a.ruleId);
    out += ",\"ruleName\":"; appendJsonEscaped(out, a.ruleName);
    out += ",\"riskScore\":" + std::to_string(a.riskScore);
    out += ",\"riskLevel\":"; appendJsonEscaped(out, a.riskLevel);
    out += ",\"processName\":"; appendJsonEscaped(out, a.processName);
    out += ",\"pid\":" + std::to_string(a.pid);
    out += ",\"exePath\":"; appendJsonEscaped(out, a.exePath);
    out += ",\"destination\":"; appendJsonEscaped(out, a.destination);
    out += ",\"countryCode\":"; appendJsonEscaped(out, a.countryCode);
    out += ",\"whatHappened\":"; appendJsonEscaped(out, a.whatHappened);
    out += ",\"evidences\":" + safeJsonArrayOrFallback(a.evidencesJson);
    out += ",\"classificationReason\":"; appendJsonEscaped(out, a.classificationReason);
    out += ",\"possibleActions\":" + safeJsonArrayOrFallback(a.possibleActionsJson);
    out += ",\"acknowledged\":" + std::string(a.acknowledged ? "true" : "false") + "}";
  }
  out += "],\"rules\":[";
  for (size_t i = 0; i < rules_.size(); ++i) {
    const auto& r = rules_[i];
    if (i > 0) out += ",";
    out += "{\"id\":"; appendJsonEscaped(out, r.id);
    out += ",\"name\":"; appendJsonEscaped(out, r.name);
    out += ",\"kind\":"; appendJsonEscaped(out, r.kind);
    out += ",\"enabled\":" + std::string(r.enabled ? "true" : "false");
    out += ",\"riskWeight\":" + std::to_string(r.riskWeight);
    out += ",\"thresholdNum\":" + std::to_string(r.thresholdNum);
    out += ",\"matchCountry\":"; appendJsonEscaped(out, r.matchCountry);
    out += ",\"matchPort\":" + std::to_string(r.matchPort);
    out += ",\"matchProcess\":"; appendJsonEscaped(out, r.matchProcess);
    out += ",\"description\":"; appendJsonEscaped(out, r.description);
    out += ",\"isBuiltin\":" + std::string(r.isBuiltin ? "true" : "false");
    out += ",\"updatedAtMs\":" + std::to_string(r.updatedAtMs) + "}";
  }
  out += "],\"lists\":[";
  for (size_t i = 0; i < lists_.size(); ++i) {
    const auto& e = lists_[i];
    if (i > 0) out += ",";
    out += "{\"id\":"; appendJsonEscaped(out, e.id);
    out += ",\"listKind\":"; appendJsonEscaped(out, e.listKind);
    out += ",\"targetType\":"; appendJsonEscaped(out, e.targetType);
    out += ",\"targetValue\":"; appendJsonEscaped(out, e.targetValue);
    out += ",\"reason\":"; appendJsonEscaped(out, e.reason);
    out += ",\"createdBy\":"; appendJsonEscaped(out, e.createdBy);
    out += ",\"createdAtMs\":" + std::to_string(e.createdAtMs) + "}";
  }
  out += "],\"firewallRules\":[";
  for (size_t i = 0; i < firewallRules_.size(); ++i) {
    const auto& fw = firewallRules_[i];
    if (i > 0) out += ",";
    out += "{\"id\":"; appendJsonEscaped(out, fw.id);
    out += ",\"ruleName\":"; appendJsonEscaped(out, fw.ruleName);
    out += ",\"direction\":"; appendJsonEscaped(out, fw.direction);
    out += ",\"action\":"; appendJsonEscaped(out, fw.action);
    out += ",\"protocol\":"; appendJsonEscaped(out, fw.protocol);
    out += ",\"remoteIp\":"; appendJsonEscaped(out, fw.remoteIp);
    out += ",\"remotePort\":" + std::to_string(fw.remotePort);
    out += ",\"programPath\":"; appendJsonEscaped(out, fw.programPath);
    out += ",\"osApplied\":" + std::string(fw.osApplied ? "true" : "false");
    out += ",\"enabled\":" + std::string(fw.enabled ? "true" : "false");
    out += ",\"createdBy\":"; appendJsonEscaped(out, fw.createdBy);
    out += ",\"createdAtMs\":" + std::to_string(fw.createdAtMs) + "}";
  }
  out += "]}";
  return out;
}

bool IntelligenceEngine::upsertRule(SecurityRuleRecord& rule) {
  if (rule.name.empty() || rule.kind.empty()) {
    return false;
  }
  rule.riskWeight = clampScore(rule.riskWeight);
  rule.updatedAtMs = currentEpochMs();
  if (rule.id.empty()) {
    rule.id = makeShortId("rule", rule.updatedAtMs);
    rule.isBuiltin = false;
  } else {
    std::lock_guard<std::mutex> lock(mutex_);
    bool found = false;
    for (const auto& existing : rules_) {
      if (existing.id == rule.id) {
        rule.isBuiltin = existing.isBuiltin;
        found = true;
        break;
      }
    }
    if (!found) {
      rule.isBuiltin = false;
    }
  }
  if (!history_.upsertSecurityRule(rule)) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& existing : rules_) {
    if (existing.id == rule.id) {
      existing = rule;
      return true;
    }
  }
  rules_.push_back(rule);
  return true;
}

bool IntelligenceEngine::deleteRule(const std::string& id) {
  if (id.empty()) {
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : rules_) {
      if (r.id == id && r.isBuiltin) {
        return false;
      }
    }
  }
  if (!history_.deleteSecurityRule(id)) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  rules_.erase(std::remove_if(rules_.begin(), rules_.end(), [&](const SecurityRuleRecord& r) { return r.id == id; }),
               rules_.end());
  return true;
}

bool IntelligenceEngine::acknowledgeAlert(int64_t alertId) {
  if (alertId <= 0) {
    return false;
  }
  if (!history_.acknowledgeSecurityAlert(alertId)) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& a : recentAlerts_) {
    if (a.id == alertId) {
      a.acknowledged = true;
    }
  }
  return true;
}

bool IntelligenceEngine::addListEntry(const std::string& listKind,
                                        const std::string& targetType,
                                        const std::string& targetValue,
                                        const std::string& reason,
                                        const std::string& actor,
                                        SecurityListEntry& outEntry,
                                        std::string& outError) {
  if (listKind != "allowlist" && listKind != "blocklist") {
    outError = "listKind must be allowlist or blocklist";
    return false;
  }
  if (targetType != "ip" && targetType != "process" && targetType != "port") {
    outError = "targetType must be ip, process or port";
    return false;
  }
  if (targetValue.empty() || targetValue.size() > 160) {
    outError = "targetValue invalid";
    return false;
  }
  if (targetType == "ip" && !isValidIpAddress(targetValue)) {
    outError = "IP invalido";
    return false;
  }
  if (targetType == "ip" && listKind == "blocklist" && isLoopbackOrUnspecifiedIp(targetValue)) {
    outError = "Bloqueio de loopback/unspecified nao permitido";
    return false;
  }
  if (targetType == "port") {
    try {
      const int p = std::stoi(targetValue);
      if (p < 1 || p > 65535) {
        outError = "Porta fora do intervalo 1-65535";
        return false;
      }
    } catch (...) {
      outError = "Porta invalida";
      return false;
    }
  }

  outEntry.id = makeShortId("lst", currentEpochMs());
  outEntry.listKind = listKind;
  outEntry.targetType = targetType;
  outEntry.targetValue = targetValue;
  outEntry.reason = reason;
  outEntry.createdBy = actor;
  outEntry.createdAtMs = currentEpochMs();

  if (!history_.upsertSecurityListEntry(outEntry)) {
    outError = "Falha ao persistir entrada na lista";
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  lists_.insert(lists_.begin(), outEntry);
  return true;
}

bool IntelligenceEngine::removeListEntry(const std::string& id) {
  if (id.empty() || !history_.deleteSecurityListEntry(id)) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  lists_.erase(std::remove_if(lists_.begin(), lists_.end(), [&](const SecurityListEntry& e) { return e.id == id; }),
               lists_.end());
  return true;
}

bool IntelligenceEngine::createFirewallRule(const std::string& ruleName,
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
                                              std::string& outError) {
  if (ruleName.empty() || ruleName.size() > 64) {
    outError = "ruleName obrigatorio (1-64 caracteres)";
    return false;
  }
  if (direction != "out" && direction != "in") {
    outError = "direction deve ser 'out' ou 'in'";
    return false;
  }
  if (action != "block" && action != "allow") {
    outError = "action deve ser 'block' ou 'allow'";
    return false;
  }
  if (protocol != "ANY" && protocol != "TCP" && protocol != "UDP") {
    outError = "protocol deve ser ANY, TCP ou UDP";
    return false;
  }
  if (remoteIp.empty() && remotePort == 0 && programPath.empty()) {
    outError = "Informe ao menos IP remoto, porta remota ou caminho de programa";
    return false;
  }
  if (!remoteIp.empty() && (!isValidIpAddress(remoteIp) || isLoopbackOrUnspecifiedIp(remoteIp))) {
    outError = "IP remoto invalido ou loopback protegido";
    return false;
  }
  if (remotePort != 0 && protocol == "ANY") {
    outError = "Regras com porta exigem protocolo TCP ou UDP";
    return false;
  }

  const uint64_t now = currentEpochMs();
  const std::string safeName = "NetPulse_" + ruleName;
  bool osApplied = false;
  if (applyToOs) {
    if (!applyOsFirewallRule(safeName, direction, action, protocol, remoteIp, remotePort, programPath, isElevated,
                             outError)) {
      return false;
    }
    osApplied = true;
  }

  outRule.id = makeShortId("fw", now);
  outRule.ruleName = safeName;
  outRule.direction = direction;
  outRule.action = action;
  outRule.protocol = protocol;
  outRule.remoteIp = remoteIp;
  outRule.remotePort = remotePort;
  outRule.programPath = programPath;
  outRule.osApplied = osApplied;
  outRule.enabled = true;
  outRule.createdBy = actor;
  outRule.createdAtMs = now;

  if (!history_.upsertFirewallRule(outRule)) {
    if (osApplied) {
      std::string ignored;
      removeOsFirewallRule(safeName, isElevated, ignored);
    }
    outError = "Falha ao salvar regra de firewall no banco";
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  firewallRules_.insert(firewallRules_.begin(), outRule);
  return true;
}

bool IntelligenceEngine::removeFirewallRuleById(const std::string& id, bool isElevated, std::string& outError) {
  FirewallRuleRecord target;
  bool found = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& fw : firewallRules_) {
      if (fw.id == id) {
        target = fw;
        found = true;
        break;
      }
    }
  }
  if (!found) {
    outError = "Regra de firewall nao encontrada";
    return false;
  }
  if (target.osApplied) {
    if (!removeOsFirewallRule(target.ruleName, isElevated, outError)) {
      return false;
    }
  }
  if (!history_.deleteFirewallRule(id)) {
    outError = "Falha ao remover regra do SQLite";
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  firewallRules_.erase(
      std::remove_if(firewallRules_.begin(), firewallRules_.end(), [&](const FirewallRuleRecord& fw) { return fw.id == id; }),
      firewallRules_.end());
  return true;
}

std::vector<SecurityAlertRecord> IntelligenceEngine::getRecentAlertsSnapshot(size_t limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const size_t n = std::min(limit, recentAlerts_.size());
  return std::vector<SecurityAlertRecord>(recentAlerts_.begin(), recentAlerts_.begin() + n);
}

} // namespace netpulse
