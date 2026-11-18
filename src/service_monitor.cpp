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
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

#include "models.hpp"
#include "service_monitor.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

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

struct ProbeOutcome {
  bool ok = false;
  double latencyMs = 0.0;
  std::string resolvedIp;
  std::string error;
};

ProbeOutcome tcpProbeHost(const std::string& host, uint16_t port, int timeoutMs = 2500) {
  ProbeOutcome out;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string portStr = std::to_string(port);
  addrinfo* resList = nullptr;
  int gai = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &resList);
  if (gai != 0 || !resList) {
    out.error = "DNS error (" + std::to_string(gai) + ")";
    return out;
  }

  for (addrinfo* ai = resList; ai != nullptr; ai = ai->ai_next) {
    char ipBuf[INET6_ADDRSTRLEN] = {};
    if (ai->ai_family == AF_INET) {
      auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
      inet_ntop(AF_INET, &sa->sin_addr, ipBuf, sizeof(ipBuf));
    } else if (ai->ai_family == AF_INET6) {
      auto* sa6 = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
      inet_ntop(AF_INET6, &sa6->sin6_addr, ipBuf, sizeof(ipBuf));
    }
    out.resolvedIp = ipBuf;

#ifdef _WIN32
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) continue;

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);
#else
    int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s < 0) continue;

    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    const auto t0 = std::chrono::steady_clock::now();
    int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
    bool connected = false;
    std::string errMsg;

    if (rc == 0) {
      connected = true;
    } else {
#ifdef _WIN32
      int sockErr = WSAGetLastError();
      bool inProgress = (sockErr == WSAEWOULDBLOCK || sockErr == WSAEINPROGRESS);
#else
      int sockErr = errno;
      bool inProgress = (sockErr == EINPROGRESS || sockErr == EWOULDBLOCK);
#endif
      if (inProgress) {
        fd_set writeSet;
        fd_set errSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errSet);
        FD_SET(s, &writeSet);
        FD_SET(s, &errSet);

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

#ifdef _WIN32
        int sel = select(0, nullptr, &writeSet, &errSet, &tv);
        int optLen = sizeof(int);
#else
        int sel = select(s + 1, nullptr, &writeSet, &errSet, &tv);
        socklen_t optLen = sizeof(int);
#endif
        if (sel > 0 && FD_ISSET(s, &writeSet) && !FD_ISSET(s, &errSet)) {
          int soErr = 0;
          if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &optLen) == 0 && soErr == 0) {
            connected = true;
          } else {
            errMsg = "TCP err " + std::to_string(soErr);
          }
        } else if (sel == 0) {
          errMsg = "Timeout";
        } else {
          errMsg = "Connect failed";
        }
      } else {
        errMsg = "Socket err " + std::to_string(sockErr);
      }
    }

    const auto t1 = std::chrono::steady_clock::now();
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif

    if (connected) {
      out.ok = true;
      out.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
      out.error.clear();
      break;
    }
    out.error = std::move(errMsg);
  }

  freeaddrinfo(resList);
  return out;
}

} // namespace

bool parseCustomServiceLine(const std::string& line, ServiceTarget& out) {
  if (line.empty() || line[0] == '#') return false;
  std::vector<std::string> cols;
  std::stringstream ss(line);
  std::string item;
  while (std::getline(ss, item, '\t')) cols.push_back(item);
  if (cols.size() < 7) return false;

  int portInt = std::atoi(cols[3].c_str());
  if (portInt < 1 || portInt > 65535) return false;

  out.id = cols[0];
  out.name = cols[1];
  out.host = cols[2];
  out.port = static_cast<uint16_t>(portInt);
  out.category = "custom";
  out.continent = cols[4];
  out.regionLabel = cols[4];
  out.lat = std::strtod(cols[5].c_str(), nullptr);
  out.lon = std::strtod(cols[6].c_str(), nullptr);
  out.custom = true;
  return !out.id.empty() && !out.name.empty() && !out.host.empty();
}

ServiceMonitor::ServiceMonitor(std::filesystem::path customFilePath)
    : customFilePath_(std::move(customFilePath)) {
  loadDefaultTargets();
  loadCustomTargets();
}

ServiceMonitor::~ServiceMonitor() {
  stop();
}

void ServiceMonitor::loadDefaultTargets() {
  const std::vector<ServiceTarget> defaults = {
      // 6 Continental Backbone Anchors (real AWS regional endpoints on each continent)
      {"cont-sa", "América do Sul (São Paulo)", "ec2.sa-east-1.amazonaws.com", 443, "continent", "SA", "São Paulo, BR", -23.5505, -46.6333, false},
      {"cont-na", "América do Norte (Virginia)", "ec2.us-east-1.amazonaws.com", 443, "continent", "NA", "Virginia, US", 39.0438, -77.4874, false},
      {"cont-eu", "Europa (Frankfurt)", "ec2.eu-central-1.amazonaws.com", 443, "continent", "EU", "Frankfurt, DE", 50.1109, 8.6821, false},
      {"cont-af", "África (Cidade do Cabo)", "ec2.af-south-1.amazonaws.com", 443, "continent", "AF", "Cape Town, ZA", -33.9249, 18.4241, false},
      {"cont-as", "Ásia (Tóquio)", "ec2.ap-northeast-1.amazonaws.com", 443, "continent", "AS", "Tokyo, JP", 35.6762, 139.6503, false},
      {"cont-oc", "Oceania (Sydney)", "ec2.ap-southeast-2.amazonaws.com", 443, "continent", "OC", "Sydney, AU", -33.8688, 151.2093, false},

      // Global Services & Infrastructure
      {"svc-cf-dns", "Cloudflare DNS", "1.1.1.1", 443, "service", "GLOBAL", "Anycast Global", 37.7749, -122.4194, false},
      {"svc-gg-dns", "Google Public DNS", "8.8.8.8", 443, "service", "GLOBAL", "Anycast Global", 37.4220, -122.0841, false},
      {"svc-quad9", "Quad9 DNS", "9.9.9.9", 443, "service", "GLOBAL", "Anycast / CH", 47.3769, 8.5417, false},
      {"svc-github", "GitHub", "github.com", 443, "service", "NA", "San Francisco / US-East", 38.9072, -77.0369, false},
      {"svc-openai", "OpenAI API", "api.openai.com", 443, "service", "NA", "US Edge / Cloudflare", 37.7749, -122.4194, false},
      {"svc-msft", "Microsoft 365 / Azure", "login.microsoftonline.com", 443, "service", "NA", "Redmond / Global Edge", 47.6740, -122.1215, false},
      {"svc-google", "Google Search", "www.google.com", 443, "service", "GLOBAL", "Edge Global", -23.5505, -46.6333, false},
      {"svc-discord", "Discord", "discord.com", 443, "service", "NA", "US / Global Edge", 34.0522, -118.2437, false},
      {"svc-steam", "Steam Store", "store.steampowered.com", 443, "service", "NA", "Seattle, US", 47.6062, -122.3321, false},
      {"svc-aws-eu", "AWS Europa (Irlanda)", "ec2.eu-west-1.amazonaws.com", 443, "service", "EU", "Dublin, IE", 53.3498, -6.2603, false},
      {"svc-aws-sg", "AWS Ásia (Singapura)", "ec2.ap-southeast-1.amazonaws.com", 443, "service", "AS", "Singapore, SG", 1.3521, 103.8198, false},
  };

  std::lock_guard lock(mutex_);
  items_.clear();
  items_.reserve(defaults.size());
  for (const auto& t : defaults) {
    ServiceStatus st;
    st.target = t;
    items_.push_back(std::move(st));
  }
}

void ServiceMonitor::loadCustomTargets() {
  std::error_code ec;
  if (!std::filesystem::exists(customFilePath_, ec)) return;

  std::ifstream in(customFilePath_);
  if (!in.is_open()) return;

  std::lock_guard lock(mutex_);
  std::string line;
  while (std::getline(in, line)) {
    ServiceTarget t;
    if (parseCustomServiceLine(line, t)) {
      ServiceStatus st;
      st.target = std::move(t);
      items_.push_back(std::move(st));
    }
  }
}

void ServiceMonitor::saveCustomTargets() {
  std::vector<ServiceTarget> customs;
  {
    std::lock_guard lock(mutex_);
    for (const auto& item : items_) {
      if (item.target.custom) customs.push_back(item.target);
    }
  }

  std::error_code ec;
  std::filesystem::create_directories(customFilePath_.parent_path(), ec);
  std::ofstream out(customFilePath_, std::ios::trunc);
  if (!out.is_open()) return;

  for (const auto& t : customs) {
    out << sanitizeTsv(t.id) << '\t'
        << sanitizeTsv(t.name) << '\t'
        << sanitizeTsv(t.host) << '\t'
        << t.port << '\t'
        << sanitizeTsv(t.continent) << '\t'
        << t.lat << '\t'
        << t.lon << '\n';
  }
}

bool ServiceMonitor::addCustomService(const std::string& name,
                                      const std::string& host,
                                      uint16_t port,
                                      const std::string& continent,
                                      double lat,
                                      double lon) {
  if (name.empty() || host.empty() || port == 0) return false;
  ServiceTarget t;
  t.id = "custom-" + std::to_string(nowEpochMs());
  t.name = name;
  t.host = host;
  t.port = port;
  t.category = "custom";
  t.continent = continent.empty() ? "GLOBAL" : continent;
  t.regionLabel = t.continent;
  t.lat = lat;
  t.lon = lon;
  t.custom = true;

  {
    std::lock_guard lock(mutex_);
    ServiceStatus st;
    st.target = std::move(t);
    items_.push_back(std::move(st));
  }
  saveCustomTargets();
  probeNowAsync();
  return true;
}

bool ServiceMonitor::removeCustomService(const std::string& id) {
  bool removed = false;
  {
    std::lock_guard lock(mutex_);
    auto it = std::remove_if(items_.begin(), items_.end(), [&](const ServiceStatus& s) {
      return s.target.custom && s.target.id == id;
    });
    if (it != items_.end()) {
      items_.erase(it, items_.end());
      removed = true;
    }
  }
  if (removed) saveCustomTargets();
  return removed;
}

void ServiceMonitor::start() {
  if (running_.exchange(true)) return;
  workerThread_ = std::jthread([this](std::stop_token st) { workerLoop(st); });
}

void ServiceMonitor::stop() {
  if (!running_.exchange(false)) return;
  if (workerThread_.joinable()) {
    workerThread_.request_stop();
    wakeCv_.notify_all();
    workerThread_.join();
  }
}

void ServiceMonitor::probeNowAsync() {
  probeRequested_.store(true);
  wakeCv_.notify_all();
}

void ServiceMonitor::workerLoop(std::stop_token st) {
  while (!st.stop_requested()) {
    probeRequested_.store(false);
    probeAll();

    std::unique_lock lock(wakeMutex_);
    wakeCv_.wait_for(lock, st, std::chrono::seconds(8), [this]() {
      return probeRequested_.load();
    });
  }
}

void ServiceMonitor::probeAll() {
  std::vector<ServiceTarget> targets;
  {
    std::lock_guard lock(mutex_);
    targets.reserve(items_.size());
    for (const auto& it : items_) targets.push_back(it.target);
  }

  std::vector<ProbeOutcome> outcomes(targets.size());
  std::atomic<size_t> nextIdx{0};

  const size_t threadCount = std::min<size_t>(8, std::max<size_t>(1, targets.size()));
  std::vector<std::jthread> pool;
  pool.reserve(threadCount);
  for (size_t w = 0; w < threadCount; ++w) {
    pool.emplace_back([&]() {
      while (true) {
        size_t i = nextIdx.fetch_add(1);
        if (i >= targets.size()) break;
        outcomes[i] = tcpProbeHost(targets[i].host, targets[i].port, 2500);
      }
    });
  }
  pool.clear(); // joins all std::jthreads

  const uint64_t now = nowEpochMs();
  std::lock_guard lock(mutex_);
  for (size_t i = 0; i < targets.size(); ++i) {
    const std::string& id = targets[i].id;
    auto it = std::find_if(items_.begin(), items_.end(), [&](const ServiceStatus& s) {
      return s.target.id == id;
    });
    if (it == items_.end()) continue;

    const auto& res = outcomes[i];
    ++it->checksTotal;
    it->lastCheckedMs = now;
    if (!res.resolvedIp.empty()) it->resolvedIp = res.resolvedIp;

    if (res.ok) {
      ++it->checksOk;
      it->latencyMs = res.latencyMs;
      it->lastError.clear();
      if (it->minLatencyMs <= 0.0 || res.latencyMs < it->minLatencyMs) {
        it->minLatencyMs = res.latencyMs;
      }
      it->avgLatencyMs = (it->avgLatencyMs <= 0.0)
                             ? res.latencyMs
                             : (it->avgLatencyMs * 0.7 + res.latencyMs * 0.3);
      it->status = (res.latencyMs >= 380.0) ? "degraded" : "up";
    } else {
      it->latencyMs = 0.0;
      it->lastError = res.error;
      it->status = "down";
    }
  }
}

std::vector<ServiceStatus> ServiceMonitor::getSnapshot() const {
  std::lock_guard lock(mutex_);
  return items_;
}

std::string ServiceMonitor::getServicesJson() const {
  auto snap = getSnapshot();
  std::string out;
  out.reserve(snap.size() * 220 + 16);
  out.push_back('[');
  char numBuf[64];

  for (size_t i = 0; i < snap.size(); ++i) {
    const auto& s = snap[i];
    if (i > 0) out.push_back(',');

    double uptime = (s.checksTotal > 0)
                        ? (100.0 * static_cast<double>(s.checksOk) / static_cast<double>(s.checksTotal))
                        : 0.0;

    out += "{\"id\":";
    appendJsonEscaped(out, s.target.id);
    out += ",\"name\":";
    appendJsonEscaped(out, s.target.name);
    out += ",\"host\":";
    appendJsonEscaped(out, s.target.host);
    out += ",\"port\":";
    out += std::to_string(s.target.port);
    out += ",\"category\":";
    appendJsonEscaped(out, s.target.category);
    out += ",\"continent\":";
    appendJsonEscaped(out, s.target.continent);
    out += ",\"region\":";
    appendJsonEscaped(out, s.target.regionLabel);
    std::snprintf(numBuf, sizeof(numBuf), "%.4f", s.target.lat);
    out += ",\"lat\":";
    out += numBuf;
    std::snprintf(numBuf, sizeof(numBuf), "%.4f", s.target.lon);
    out += ",\"lon\":";
    out += numBuf;
    out += ",\"custom\":";
    out += (s.target.custom ? "true" : "false");
    out += ",\"status\":";
    appendJsonEscaped(out, s.status);
    std::snprintf(numBuf, sizeof(numBuf), "%.1f", s.latencyMs);
    out += ",\"latencyMs\":";
    out += numBuf;
    std::snprintf(numBuf, sizeof(numBuf), "%.1f", s.avgLatencyMs);
    out += ",\"avgLatencyMs\":";
    out += numBuf;
    std::snprintf(numBuf, sizeof(numBuf), "%.1f", uptime);
    out += ",\"uptimePct\":";
    out += numBuf;
    out += ",\"checksTotal\":";
    out += std::to_string(s.checksTotal);
    out += ",\"ip\":";
    appendJsonEscaped(out, s.resolvedIp);
    out += ",\"err\":";
    appendJsonEscaped(out, s.lastError);
    out += ",\"lastMs\":";
    out += std::to_string(s.lastCheckedMs);
    out.push_back('}');
  }

  out.push_back(']');
  return out;
}

} // namespace netpulse
