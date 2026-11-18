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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#endif

#include "actions.hpp"
#include "models.hpp"
#include "net_monitor.hpp"
#include "traceroute.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

} // namespace

std::string computeTracePathHash(const std::vector<TraceHopRecord>& hops) {
  uint64_t hash = 14695981039346656037ULL;
  auto mixStr = [&](const std::string& s) {
    for (unsigned char c : s) {
      hash ^= c;
      hash *= 1099511628211ULL;
    }
  };

  size_t validCount = 0;
  for (const auto& h : hops) {
    if (!h.timedOut && !h.ip.empty()) {
      mixStr(std::to_string(h.ttl));
      mixStr(":");
      mixStr(h.ip);
      mixStr("|");
      validCount++;
    }
  }
  if (validCount == 0) return {};
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(hash));
  return std::string(buf);
}

TraceRouteDiff computeTraceRouteDiff(const TraceRunRecord& runA, const TraceRunRecord& runB) {
  TraceRouteDiff diff;
  diff.runAId = runA.id;
  diff.runBId = runB.id;
  diff.targetIp = !runB.targetIp.empty() ? runB.targetIp : runA.targetIp;
  diff.hopCountA = runA.hops.size();
  diff.hopCountB = runB.hops.size();
  diff.totalRttDeltaMs = runB.totalRttMs - runA.totalRttMs;

  std::unordered_map<int, const TraceHopRecord*> mapA;
  std::unordered_map<int, const TraceHopRecord*> mapB;
  int maxTtl = 0;
  for (const auto& h : runA.hops) {
    mapA[h.ttl] = &h;
    maxTtl = std::max(maxTtl, h.ttl);
  }
  for (const auto& h : runB.hops) {
    mapB[h.ttl] = &h;
    maxTtl = std::max(maxTtl, h.ttl);
  }

  for (int ttl = 1; ttl <= maxTtl; ++ttl) {
    auto itA = mapA.find(ttl);
    auto itB = mapB.find(ttl);
    if (itA == mapA.end() && itB == mapB.end()) continue;

    TraceHopDiff hd;
    hd.ttl = ttl;
    const TraceHopRecord* a = (itA != mapA.end()) ? itA->second : nullptr;
    const TraceHopRecord* b = (itB != mapB.end()) ? itB->second : nullptr;

    if (a) {
      hd.ipA = a->timedOut ? "*" : a->ip;
      hd.rttMsA = a->rttMs;
      hd.asnA = a->asn;
    }
    if (b) {
      hd.ipB = b->timedOut ? "*" : b->ip;
      hd.rttMsB = b->rttMs;
      hd.asnB = b->asn;
    }

    if (a && !b) {
      hd.kind = "removed";
      diff.changedHopsCount++;
    } else if (!a && b) {
      hd.kind = "added";
      diff.changedHopsCount++;
    } else if (a && b) {
      if (a->timedOut != b->timedOut) {
        hd.kind = "timeout_change";
        diff.changedHopsCount++;
      } else if (!a->timedOut && a->ip != b->ip) {
        hd.kind = "changed";
        diff.changedHopsCount++;
      } else {
        hd.kind = "unchanged";
      }
      if (!a->timedOut && !b->timedOut) {
        hd.deltaRttMs = b->rttMs - a->rttMs;
      }
    }
    diff.diffs.push_back(std::move(hd));
  }

  const std::string hA = !runA.pathHash.empty() ? runA.pathHash : computeTracePathHash(runA.hops);
  const std::string hB = !runB.pathHash.empty() ? runB.pathHash : computeTracePathHash(runB.hops);
  diff.pathChanged = (!hA.empty() && !hB.empty() && hA != hB) || (diff.changedHopsCount > 0);
  return diff;
}

std::string serializeTraceDiffJson(const TraceRouteDiff& diff) {
  char num[32];
  std::string out = "{\"runAId\":";
  out += std::to_string(diff.runAId);
  out += ",\"runBId\":";
  out += std::to_string(diff.runBId);
  out += ",\"targetIp\":";
  appendJsonEscaped(out, diff.targetIp);
  out += ",\"pathChanged\":";
  out += (diff.pathChanged ? "true" : "false");
  out += ",\"hopCountA\":";
  out += std::to_string(diff.hopCountA);
  out += ",\"hopCountB\":";
  out += std::to_string(diff.hopCountB);
  out += ",\"changedHopsCount\":";
  out += std::to_string(diff.changedHopsCount);
  std::snprintf(num, sizeof(num), "%.1f", diff.totalRttDeltaMs);
  out += ",\"totalRttDeltaMs\":";
  out += num;
  out += ",\"diffs\":[";

  for (size_t i = 0; i < diff.diffs.size(); ++i) {
    const auto& d = diff.diffs[i];
    if (i > 0) out.push_back(',');
    out += "{\"ttl\":";
    out += std::to_string(d.ttl);
    out += ",\"kind\":";
    appendJsonEscaped(out, d.kind);
    out += ",\"ipA\":";
    appendJsonEscaped(out, d.ipA);
    out += ",\"ipB\":";
    appendJsonEscaped(out, d.ipB);
    std::snprintf(num, sizeof(num), "%.1f", d.rttMsA);
    out += ",\"rttMsA\":";
    out += num;
    std::snprintf(num, sizeof(num), "%.1f", d.rttMsB);
    out += ",\"rttMsB\":";
    out += num;
    std::snprintf(num, sizeof(num), "%.1f", d.deltaRttMs);
    out += ",\"deltaRttMs\":";
    out += num;
    out += ",\"asnA\":";
    appendJsonEscaped(out, d.asnA);
    out += ",\"asnB\":";
    appendJsonEscaped(out, d.asnB);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

TracerouteService::TracerouteService(GeoDnsService& geoDns, HistoryStore* history)
    : geoDns_(geoDns), history_(history) {}

TracerouteService::~TracerouteService() {
  stop();
}

void TracerouteService::startScheduler() {
  if (!history_ || scheduler_.joinable()) return;
  scheduler_ = std::jthread([this](std::stop_token st) { schedulerLoop(st); });
}

void TracerouteService::stop() {
  if (scheduler_.joinable()) {
    scheduler_.request_stop();
    schedCv_.notify_all();
    scheduler_.join();
  }
  if (worker_.joinable()) {
    worker_.request_stop();
    worker_.join();
  }
}

bool TracerouteService::startTrace(const std::string& targetIp, const std::string& targetLabel) {
  struct in_addr in4{};
  struct in6_addr in6{};
  if (inet_pton(AF_INET, targetIp.c_str(), &in4) != 1 &&
      inet_pton(AF_INET6, targetIp.c_str(), &in6) != 1) {
    return false;
  }

  if (worker_.joinable()) {
    worker_.request_stop();
    worker_.join();
  }
  {
    std::lock_guard lock(mutex_);
    session_ = TraceSession{};
    session_.targetIp = targetIp;
    session_.targetLabel = targetLabel;
    session_.running = true;
  }

  worker_ = std::jthread([this, targetIp, targetLabel](std::stop_token st) {
    runInteractiveTrace(st, targetIp, targetLabel);
  });
  return true;
}

void TracerouteService::enrichHopsFromGeoDns(TraceRunRecord& run) const {
  for (auto& h : run.hops) {
    if (h.timedOut || h.ip.empty()) continue;
    if (auto g = geoDns_.getGeo(h.ip); g.has_value()) {
      h.country = g->country;
      h.countryCode = g->countryCode;
      h.city = g->city;
      h.asn = g->asn;
      h.lat = g->lat;
      h.lon = g->lon;
    }
    if (auto dns = geoDns_.getHostname(h.ip); dns.has_value()) {
      h.hostname = *dns;
    }
  }
}

TraceRunRecord TracerouteService::executeTraceBlocking(std::stop_token st,
                                                       const std::string& targetIp,
                                                       const std::string& targetLabel,
                                                       const std::string& triggerKind,
                                                       bool publishLiveSession) {
  TraceRunRecord run;
  run.targetIp = targetIp;
  run.targetLabel = targetLabel;
  run.triggerKind = triggerKind;
  run.startedAtMs = nowEpochMs();

#ifdef _WIN32
  IN_ADDR in4{};
  IN6_ADDR in6{};
  const bool isV4 = (inet_pton(AF_INET, targetIp.c_str(), &in4) == 1);
  const bool isV6 = (!isV4 && inet_pton(AF_INET6, targetIp.c_str(), &in6) == 1);

  if (!isV4 && !isV6) {
    run.completedAtMs = nowEpochMs();
    run.error = "Invalid IP address";
    return run;
  }

  HANDLE hIcmp = isV4 ? IcmpCreateFile() : Icmp6CreateFile();
  if (hIcmp == INVALID_HANDLE_VALUE) {
    run.completedAtMs = nowEpochMs();
    run.error = "Failed to open ICMP handle";
    return run;
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
      run.totalRttMs = hop.rttMs;
    } else {
      ++consecutiveTimeouts;
    }

    const bool reachedTarget = (!hop.timedOut && hop.ip == targetIp);
    if (reachedTarget) run.reached = true;

    TraceHopRecord hr;
    hr.ttl = hop.ttl;
    hr.timedOut = hop.timedOut;
    hr.ip = hop.ip;
    hr.rttMs = hop.rttMs;
    run.hops.push_back(std::move(hr));

    if (publishLiveSession) {
      std::lock_guard lock(mutex_);
      session_.hops.push_back(hop);
    }

    if (reachedTarget) break;
    if (ttl >= 12 && consecutiveTimeouts >= 4) break;
  }

  IcmpCloseHandle(hIcmp);
#else
  int pipeFd[2] = {-1, -1};
  if (pipe(pipeFd) != 0) {
    run.completedAtMs = nowEpochMs();
    run.error = "Falha ao criar pipe para traceroute";
    return run;
  }

  pid_t child = fork();
  if (child < 0) {
    close(pipeFd[0]);
    close(pipeFd[1]);
    run.completedAtMs = nowEpochMs();
    run.error = "Falha ao iniciar processo traceroute";
    return run;
  }

  if (child == 0) {
    close(pipeFd[0]);
    dup2(pipeFd[1], STDOUT_FILENO);
    dup2(pipeFd[1], STDERR_FILENO);
    close(pipeFd[1]);
    execlp("traceroute", "traceroute", "-n", "-q", "1", "-w", "1", "-m", "28", targetIp.c_str(), nullptr);
    _exit(127);
  }

  close(pipeFd[1]);
  FILE* pipeStream = fdopen(pipeFd[0], "r");
  if (!pipeStream) {
    close(pipeFd[0]);
    waitpid(child, nullptr, 0);
    run.completedAtMs = nowEpochMs();
    run.error = "Falha ao ler saida do traceroute";
    return run;
  }

  char lineBuf[512];
  int consecutiveTimeouts = 0;
  while (!st.stop_requested() && fgets(lineBuf, sizeof(lineBuf), pipeStream) != nullptr) {
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
      run.totalRttMs = hop.rttMs;
    }
    const bool reachedTarget = (!hop.timedOut && hop.ip == targetIp);
    if (reachedTarget) run.reached = true;

    TraceHopRecord hr;
    hr.ttl = hop.ttl;
    hr.timedOut = hop.timedOut;
    hr.ip = hop.ip;
    hr.rttMs = hop.rttMs;
    run.hops.push_back(std::move(hr));

    if (publishLiveSession) {
      std::lock_guard lock(mutex_);
      session_.hops.push_back(hop);
    }
    if (reachedTarget || (ttl >= 12 && consecutiveTimeouts >= 4)) break;
  }
  fclose(pipeStream);
  waitpid(child, nullptr, 0);
#endif

  run.completedAtMs = nowEpochMs();
  run.pathHash = computeTracePathHash(run.hops);
  return run;
}

void TracerouteService::runInteractiveTrace(std::stop_token st, std::string targetIp, std::string targetLabel) {
  auto run = executeTraceBlocking(st, targetIp, targetLabel, "manual", true);
  enrichHopsFromGeoDns(run);
  if (history_ && !st.stop_requested()) {
    history_->saveTraceRun(run);
  }

  std::lock_guard lock(mutex_);
  session_.runId = run.id;
  session_.pathHash = run.pathHash;
  session_.changedFromPrev = run.changedFromPrev;
  session_.error = run.error;
  session_.running = false;
  session_.completed = true;
}

void TracerouteService::schedulerLoop(std::stop_token st) {
  while (!st.stop_requested()) {
    const uint64_t now = nowEpochMs();
    std::vector<TraceMonitorRecord> due;
    if (history_) {
      auto all = history_->loadTraceMonitors();
      for (const auto& m : all) {
        if (!m.enabled) continue;
        const uint64_t ivMs = static_cast<uint64_t>(std::clamp(m.intervalSec, 30, 3600)) * 1000ULL;
        if (m.lastRunMs == 0 || now >= m.lastRunMs + ivMs) {
          due.push_back(m);
        }
      }
    }

    for (const auto& m : due) {
      if (st.stop_requested()) break;
      auto run = executeTraceBlocking(st, m.targetIp, m.label, "scheduled", false);
      enrichHopsFromGeoDns(run);
      if (history_ && !st.stop_requested()) {
        history_->saveTraceRun(run);
        history_->updateTraceMonitorLastRun(m.targetIp, nowEpochMs());
      }
    }

    std::unique_lock lk(schedMutex_);
    schedWake_.store(false);
    schedCv_.wait_for(lk, st, std::chrono::seconds(10), [this]() {
      return schedWake_.load();
    });
  }
}

std::string TracerouteService::getStatusJson() const {
  TraceSession snap;
  {
    std::lock_guard lock(mutex_);
    snap = session_;
  }

  std::string out = "{\"runId\":";
  out += std::to_string(snap.runId);
  out += ",\"targetIp\":";
  appendJsonEscaped(out, snap.targetIp);
  out += ",\"targetLabel\":";
  appendJsonEscaped(out, snap.targetLabel);
  out += ",\"running\":";
  out += (snap.running ? "true" : "false");
  out += ",\"completed\":";
  out += (snap.completed ? "true" : "false");
  out += ",\"changedFromPrev\":";
  out += (snap.changedFromPrev ? "true" : "false");
  out += ",\"pathHash\":";
  appendJsonEscaped(out, snap.pathHash);
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
        out += ",\"asn\":";
        appendJsonEscaped(out, g->asn);
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

std::string TracerouteService::getHistoryJson(const std::string& targetIp, size_t limit) const {
  if (!history_) return "{\"targetIp\":\"\",\"runs\":[]}";
  return history_->queryTraceHistoryJson(targetIp, limit);
}

std::string TracerouteService::getDiffJson(int64_t runAId, int64_t runBId, const std::string& targetIp) const {
  if (!history_) return "{\"error\":\"history_unavailable\"}";
  TraceRunRecord runA, runB;
  if (runAId > 0 && runBId > 0) {
    if (!history_->getTraceRunById(runAId, runA) || !history_->getTraceRunById(runBId, runB)) {
      return "{\"error\":\"run_not_found\"}";
    }
  } else if (!targetIp.empty()) {
    auto runs = history_->loadTraceRuns(targetIp, 2);
    if (runs.size() < 2) {
      return "{\"error\":\"insufficient_runs\",\"message\":\"Sao necessarias ao menos 2 execucoes para comparar rotas.\"}";
    }
    // runs[0] is newest, runs[1] is baseline
    runB = std::move(runs[0]);
    runA = std::move(runs[1]);
  } else {
    return "{\"error\":\"missing_parameters\"}";
  }

  auto diff = computeTraceRouteDiff(runA, runB);
  return serializeTraceDiffJson(diff);
}

std::string TracerouteService::getMonitorsJson() const {
  if (!history_) return "{\"monitors\":[]}";
  auto list = history_->loadTraceMonitors();
  std::string out = "{\"monitors\":[";
  for (size_t i = 0; i < list.size(); ++i) {
    const auto& m = list[i];
    if (i > 0) out.push_back(',');
    out += "{\"targetIp\":";
    appendJsonEscaped(out, m.targetIp);
    out += ",\"label\":";
    appendJsonEscaped(out, m.label);
    out += ",\"intervalSec\":";
    out += std::to_string(m.intervalSec);
    out += ",\"enabled\":";
    out += (m.enabled ? "true" : "false");
    out += ",\"lastRunMs\":";
    out += std::to_string(m.lastRunMs);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

bool TracerouteService::upsertMonitor(const std::string& targetIp, const std::string& label, int intervalSec, bool enabled) {
  if (!history_ || !isValidIpAddress(targetIp)) return false;
  TraceMonitorRecord m;
  m.targetIp = targetIp;
  m.label = label.empty() ? targetIp : label;
  m.intervalSec = std::clamp(intervalSec, 30, 3600);
  m.enabled = enabled;
  m.createdAtMs = nowEpochMs();
  if (!history_->upsertTraceMonitor(m)) return false;
  schedWake_.store(true);
  schedCv_.notify_all();
  return true;
}

bool TracerouteService::removeMonitor(const std::string& targetIp) {
  if (!history_ || targetIp.empty()) return false;
  return history_->deleteTraceMonitor(targetIp);
}

} // namespace netpulse
