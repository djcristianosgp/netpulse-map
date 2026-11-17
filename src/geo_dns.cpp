#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include "geo_dns.hpp"

#include <algorithm>
#include <chrono>
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

// Finds `"field":` inside a single JSON object string (ignoring nested/escaped strings cleanly).
bool extractJsonString(const std::string& obj, const std::string& key, std::string& out) {
  size_t i = 0;
  const size_t n = obj.size();
  while (i < n) {
    if (obj[i] == '"') {
      size_t keyStart = i + 1;
      std::string parsedKey;
      ++i;
      while (i < n) {
        if (obj[i] == '\\' && i + 1 < n) {
          parsedKey.push_back(obj[i + 1]);
          i += 2;
        } else if (obj[i] == '"') {
          ++i;
          break;
        } else {
          parsedKey.push_back(obj[i]);
          ++i;
        }
      }
      while (i < n && (obj[i] == ' ' || obj[i] == '\t' || obj[i] == '\r' || obj[i] == '\n')) ++i;
      if (i < n && obj[i] == ':') {
        ++i;
        while (i < n && (obj[i] == ' ' || obj[i] == '\t' || obj[i] == '\r' || obj[i] == '\n')) ++i;
        if (parsedKey == key) {
          if (i < n && obj[i] == '"') {
            ++i;
            std::string val;
            while (i < n) {
              if (obj[i] == '\\' && i + 1 < n) {
                char esc = obj[i + 1];
                switch (esc) {
                  case '"': val.push_back('"'); break;
                  case '\\': val.push_back('\\'); break;
                  case '/': val.push_back('/'); break;
                  case 'b': val.push_back('\b'); break;
                  case 'f': val.push_back('\f'); break;
                  case 'n': val.push_back('\n'); break;
                  case 'r': val.push_back('\r'); break;
                  case 't': val.push_back('\t'); break;
                  default: val.push_back(esc); break;
                }
                i += 2;
              } else if (obj[i] == '"') {
                out = std::move(val);
                return true;
              } else {
                val.push_back(obj[i]);
                ++i;
              }
            }
          }
          return false;
        }
      }
      (void)keyStart;
    } else {
      ++i;
    }
  }
  return false;
}

bool extractJsonDouble(const std::string& obj, const std::string& key, double& out) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = 0;
  while ((pos = obj.find(needle, pos)) != std::string::npos) {
    size_t i = pos + needle.size();
    while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t')) ++i;
    if (i < obj.size() && obj[i] == ':') {
      ++i;
      while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t')) ++i;
      if (i < obj.size() && (obj[i] == '-' || (obj[i] >= '0' && obj[i] <= '9'))) {
        char* endPtr = nullptr;
        double val = std::strtod(obj.c_str() + i, &endPtr);
        if (endPtr != obj.c_str() + i) {
          out = val;
          return true;
        }
      }
      return false;
    }
    pos += needle.size();
  }
  return false;
}

std::vector<std::string> splitJsonArrayObjects(const std::string& body) {
  std::vector<std::string> objs;
  bool inString = false;
  int depth = 0;
  size_t objStart = std::string::npos;

  for (size_t i = 0; i < body.size(); ++i) {
    char c = body[i];
    if (inString) {
      if (c == '\\' && i + 1 < body.size()) {
        ++i;
      } else if (c == '"') {
        inString = false;
      }
      continue;
    }
    if (c == '"') {
      inString = true;
    } else if (c == '{') {
      if (depth == 0) objStart = i;
      ++depth;
    } else if (c == '}') {
      if (depth > 0) --depth;
      if (depth == 0 && objStart != std::string::npos) {
        objs.push_back(body.substr(objStart, i - objStart + 1));
        objStart = std::string::npos;
      }
    }
  }
  return objs;
}

struct HttpResult {
  DWORD statusCode = 0;
  std::string body;
  int rateRemaining = -1;
  int rateTtlSec = -1;
};

struct WinHttpHandle {
  HINTERNET h = nullptr;
  ~WinHttpHandle() {
    if (h) WinHttpCloseHandle(h);
  }
};

HttpResult winHttpRequest(const wchar_t* method,
                          const wchar_t* host,
                          INTERNET_PORT port,
                          const wchar_t* path,
                          const std::string* postBody) {
  HttpResult res;
  WinHttpHandle session{WinHttpOpen(L"NetPulseMap/1.0",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS,
                                    0)};
  if (!session.h) return res;

  WinHttpSetTimeouts(session.h, 3000, 3000, 5000, 5000);

  WinHttpHandle conn{WinHttpConnect(session.h, host, port, 0)};
  if (!conn.h) return res;

  WinHttpHandle req{WinHttpOpenRequest(conn.h, method, path, nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       0)};
  if (!req.h) return res;

  const wchar_t* headers = postBody
      ? L"Content-Type: application/json\r\n"
      : WINHTTP_NO_ADDITIONAL_HEADERS;

  BOOL ok = WinHttpSendRequest(
      req.h,
      headers,
      postBody ? static_cast<DWORD>(-1L) : 0,
      postBody ? const_cast<char*>(postBody->data()) : WINHTTP_NO_REQUEST_DATA,
      postBody ? static_cast<DWORD>(postBody->size()) : 0,
      postBody ? static_cast<DWORD>(postBody->size()) : 0,
      0);

  if (!ok || !WinHttpReceiveResponse(req.h, nullptr)) {
    return res;
  }

  DWORD statusSize = sizeof(res.statusCode);
  WinHttpQueryHeaders(req.h,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX,
                      &res.statusCode,
                      &statusSize,
                      WINHTTP_NO_HEADER_INDEX);

  auto queryIntHeader = [&](const wchar_t* name) -> int {
    wchar_t buf[32] = {};
    DWORD sz = sizeof(buf);
    if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_CUSTOM, name, buf, &sz, WINHTTP_NO_HEADER_INDEX)) {
      return _wtoi(buf);
    }
    return -1;
  };
  res.rateRemaining = queryIntHeader(L"X-Rl");
  res.rateTtlSec = queryIntHeader(L"X-Ttl");

  DWORD avail = 0;
  while (WinHttpQueryDataAvailable(req.h, &avail) && avail > 0) {
    std::string chunk(avail, '\0');
    DWORD read = 0;
    if (WinHttpReadData(req.h, chunk.data(), avail, &read) && read > 0) {
      res.body.append(chunk.data(), read);
    } else {
      break;
    }
  }
  return res;
}

} // namespace

std::vector<std::pair<std::string, GeoInfo>> parseIpApiBatchJson(const std::string& jsonBody) {
  std::vector<std::pair<std::string, GeoInfo>> results;
  auto objs = splitJsonArrayObjects(jsonBody);
  results.reserve(objs.size());

  for (const auto& obj : objs) {
    std::string query;
    std::string status;
    if (!extractJsonString(obj, "query", query) || query.empty()) continue;
    extractJsonString(obj, "status", status);

    GeoInfo info;
    if (status == "success") {
      info.resolved = true;
      extractJsonString(obj, "country", info.country);
      extractJsonString(obj, "countryCode", info.countryCode);
      extractJsonString(obj, "regionName", info.region);
      extractJsonString(obj, "city", info.city);
      extractJsonString(obj, "isp", info.isp);
      extractJsonString(obj, "org", info.org);
      extractJsonString(obj, "as", info.asn);
      extractJsonDouble(obj, "lat", info.lat);
      extractJsonDouble(obj, "lon", info.lon);
    } else {
      info.failed = true;
    }
    results.emplace_back(std::move(query), std::move(info));
  }
  return results;
}

HostGeo parseIpApiSelfJson(const std::string& jsonBody) {
  HostGeo host;
  auto objs = splitJsonArrayObjects(jsonBody);
  if (objs.empty()) return host;
  const auto& obj = objs[0];

  std::string status;
  extractJsonString(obj, "status", status);
  if (status != "success") return host;

  host.resolved = true;
  extractJsonString(obj, "query", host.publicIp);
  extractJsonString(obj, "country", host.country);
  extractJsonString(obj, "countryCode", host.countryCode);
  extractJsonString(obj, "regionName", host.region);
  extractJsonString(obj, "city", host.city);
  extractJsonString(obj, "isp", host.isp);
  extractJsonDouble(obj, "lat", host.lat);
  extractJsonDouble(obj, "lon", host.lon);
  return host;
}

GeoDnsService::GeoDnsService(std::filesystem::path cacheFilePath)
    : cachePath_(std::move(cacheFilePath)) {
  loadCache();
}

GeoDnsService::~GeoDnsService() {
  stop();
}

void GeoDnsService::loadCache() {
  std::error_code ec;
  if (!std::filesystem::exists(cachePath_, ec)) return;

  std::ifstream in(cachePath_, std::ios::in);
  if (!in.is_open()) return;

  std::unique_lock lock(geoMutex_);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, '\t')) {
      cols.push_back(item);
    }
    if (cols.size() < 10) continue;

    GeoInfo g;
    g.resolved = true;
    g.country = cols[1];
    g.countryCode = cols[2];
    g.region = cols[3];
    g.city = cols[4];
    g.lat = std::strtod(cols[5].c_str(), nullptr);
    g.lon = std::strtod(cols[6].c_str(), nullptr);
    g.isp = cols[7];
    g.org = cols[8];
    g.asn = cols[9];
    geoCache_[cols[0]] = std::move(g);
  }
}

void GeoDnsService::appendCacheRow(const std::string& ip, const GeoInfo& info) {
  if (!info.resolved) return;
  std::lock_guard lock(fileMutex_);
  std::error_code ec;
  std::filesystem::create_directories(cachePath_.parent_path(), ec);
  std::ofstream out(cachePath_, std::ios::app);
  if (!out.is_open()) return;

  out << sanitizeTsv(ip) << '\t'
      << sanitizeTsv(info.country) << '\t'
      << sanitizeTsv(info.countryCode) << '\t'
      << sanitizeTsv(info.region) << '\t'
      << sanitizeTsv(info.city) << '\t'
      << info.lat << '\t'
      << info.lon << '\t'
      << sanitizeTsv(info.isp) << '\t'
      << sanitizeTsv(info.org) << '\t'
      << sanitizeTsv(info.asn) << '\n';
}

void GeoDnsService::start() {
  if (running_.exchange(true)) return;
  geoThread_ = std::jthread([this](std::stop_token st) { geoWorkerLoop(st); });
  for (int i = 0; i < 4; ++i) {
    dnsThreads_.emplace_back([this](std::stop_token st) { dnsWorkerLoop(st); });
  }
}

void GeoDnsService::stop() {
  if (!running_.exchange(false)) return;
  if (geoThread_.joinable()) {
    geoThread_.request_stop();
    geoCv_.notify_all();
    geoThread_.join();
  }
  for (auto& t : dnsThreads_) {
    if (t.joinable()) t.request_stop();
  }
  dnsCv_.notify_all();
  for (auto& t : dnsThreads_) {
    if (t.joinable()) t.join();
  }
  dnsThreads_.clear();
}

void GeoDnsService::requestHostGeoRefresh() {
  refreshHostGeo_.store(true);
  geoCv_.notify_one();
}

void GeoDnsService::enqueueLookups(const std::vector<std::string>& publicIps) {
  const uint64_t now = nowEpochMs();
  std::vector<std::string> needGeo;
  std::vector<std::string> needDns;

  {
    std::shared_lock gLock(geoMutex_);
    for (const auto& ip : publicIps) {
      auto it = geoCache_.find(ip);
      if (it == geoCache_.end()) {
        needGeo.push_back(ip);
      } else if (!it->second.resolved && it->second.attempts < 3 && now >= it->second.nextRetryMs) {
        needGeo.push_back(ip);
      }
    }
  }

  {
    std::shared_lock dLock(dnsMutex_);
    for (const auto& ip : publicIps) {
      if (dnsCache_.find(ip) == dnsCache_.end()) {
        needDns.push_back(ip);
      }
    }
  }

  if (!needGeo.empty()) {
    std::lock_guard qLock(geoQueueMutex_);
    bool added = false;
    for (const auto& ip : needGeo) {
      if (geoQueuedSet_.insert(ip).second) {
        geoQueue_.push_back(ip);
        added = true;
      }
    }
    if (added) geoCv_.notify_one();
  }

  if (!needDns.empty()) {
    std::lock_guard dLock(dnsQueueMutex_);
    bool added = false;
    for (const auto& ip : needDns) {
      if (dnsQueue_.size() >= 512) break;
      if (dnsQueuedSet_.insert(ip).second) {
        dnsQueue_.push_back(ip);
        added = true;
      }
    }
    if (added) dnsCv_.notify_all();
  }
}

std::optional<GeoInfo> GeoDnsService::getGeo(const std::string& ip) const {
  std::shared_lock lock(geoMutex_);
  auto it = geoCache_.find(ip);
  if (it != geoCache_.end() && it->second.resolved) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<std::string> GeoDnsService::getHostname(const std::string& ip) const {
  std::shared_lock lock(dnsMutex_);
  auto it = dnsCache_.find(ip);
  if (it != dnsCache_.end() && !it->second.empty()) {
    return it->second;
  }
  return std::nullopt;
}

HostGeo GeoDnsService::getHostGeo() const {
  std::lock_guard lock(hostMutex_);
  return hostGeo_;
}

size_t GeoDnsService::cachedGeoCount() const {
  std::shared_lock lock(geoMutex_);
  return geoCache_.size();
}

size_t GeoDnsService::cachedDnsCount() const {
  std::shared_lock lock(dnsMutex_);
  return dnsCache_.size();
}

void GeoDnsService::fetchHostGeo() {
  HttpResult res = winHttpRequest(
      L"GET",
      L"ip-api.com",
      INTERNET_DEFAULT_HTTP_PORT,
      L"/json/?fields=status,country,countryCode,regionName,city,lat,lon,isp,query",
      nullptr);

  if (res.statusCode == 200 && !res.body.empty()) {
    HostGeo hg = parseIpApiSelfJson(res.body);
    if (hg.resolved) {
      std::lock_guard lock(hostMutex_);
      hostGeo_ = std::move(hg);
    }
  }
}

void GeoDnsService::fetchGeoBatch(const std::vector<std::string>& ips) {
  if (ips.empty()) return;

  std::string payload = "[";
  for (size_t i = 0; i < ips.size(); ++i) {
    if (i > 0) payload.push_back(',');
    appendJsonEscaped(payload, ips[i]);
  }
  payload.push_back(']');

  HttpResult res = winHttpRequest(
      L"POST",
      L"ip-api.com",
      INTERNET_DEFAULT_HTTP_PORT,
      L"/batch?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query",
      &payload);

  const uint64_t now = nowEpochMs();

  if (res.statusCode == 429) {
    int waitSec = (res.rateTtlSec > 0) ? res.rateTtlSec : 60;
    rateLimitResumeMs_ = now + static_cast<uint64_t>(waitSec) * 1000ULL;
    // Re-queue batch for retry after rate limit cools down.
    std::lock_guard qLock(geoQueueMutex_);
    for (const auto& ip : ips) {
      if (geoQueuedSet_.insert(ip).second) {
        geoQueue_.push_back(ip);
      }
    }
    return;
  }

  if (res.rateRemaining >= 0 && res.rateRemaining <= 1 && res.rateTtlSec > 0) {
    rateLimitResumeMs_ = now + static_cast<uint64_t>(res.rateTtlSec) * 1000ULL;
  }

  if (res.statusCode != 200 || res.body.empty()) {
    std::unique_lock gLock(geoMutex_);
    for (const auto& ip : ips) {
      auto& g = geoCache_[ip];
      ++g.attempts;
      g.nextRetryMs = now + 15000ULL * static_cast<uint64_t>(g.attempts);
    }
    return;
  }

  auto parsed = parseIpApiBatchJson(res.body);
  std::unordered_set<std::string> seenInResp;
  {
    std::unique_lock gLock(geoMutex_);
    for (auto& [ip, info] : parsed) {
      seenInResp.insert(ip);
      if (info.resolved) {
        geoCache_[ip] = info;
        appendCacheRow(ip, info);
      } else {
        auto& g = geoCache_[ip];
        g.failed = true;
        ++g.attempts;
        g.nextRetryMs = now + 30000ULL * static_cast<uint64_t>(g.attempts);
      }
    }
    for (const auto& ip : ips) {
      if (seenInResp.find(ip) == seenInResp.end()) {
        auto& g = geoCache_[ip];
        ++g.attempts;
        g.nextRetryMs = now + 20000ULL;
      }
    }
  }
}

void GeoDnsService::geoWorkerLoop(std::stop_token stopToken) {
  while (!stopToken.stop_requested()) {
    if (refreshHostGeo_.exchange(false)) {
      fetchHostGeo();
    }

    std::vector<std::string> batch;
    {
      std::unique_lock lock(geoQueueMutex_);
      geoCv_.wait(lock, stopToken, [this]() {
        return refreshHostGeo_.load() || !geoQueue_.empty();
      });
      if (stopToken.stop_requested()) break;

      if (geoQueue_.empty()) continue;

      // Coalesce burst of newly seen IPs for 80ms up to 100 items per batch.
      lock.unlock();
      std::this_thread::sleep_for(std::chrono::milliseconds(80));
      lock.lock();

      const uint64_t now = nowEpochMs();
      if (now < rateLimitResumeMs_) {
        uint64_t sleepMs = std::min<uint64_t>(rateLimitResumeMs_ - now, 2000);
        lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
        continue;
      }

      while (!geoQueue_.empty() && batch.size() < 100) {
        std::string ip = std::move(geoQueue_.front());
        geoQueue_.pop_front();
        geoQueuedSet_.erase(ip);
        batch.push_back(std::move(ip));
      }
    }

    if (!batch.empty()) {
      fetchGeoBatch(batch);
    }
  }
}

void GeoDnsService::dnsWorkerLoop(std::stop_token stopToken) {
  while (!stopToken.stop_requested()) {
    std::string ip;
    {
      std::unique_lock lock(dnsQueueMutex_);
      dnsCv_.wait(lock, stopToken, [this]() { return !dnsQueue_.empty(); });
      if (stopToken.stop_requested()) break;
      if (dnsQueue_.empty()) continue;
      ip = std::move(dnsQueue_.front());
      dnsQueue_.pop_front();
      dnsQueuedSet_.erase(ip);
    }

    std::string hostResult;
    sockaddr_storage ss{};
    int ssLen = 0;

    IN_ADDR in4{};
    IN6_ADDR in6{};
    if (inet_pton(AF_INET, ip.c_str(), &in4) == 1) {
      auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
      sa->sin_family = AF_INET;
      sa->sin_addr = in4;
      ssLen = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1) {
      auto* sa6 = reinterpret_cast<sockaddr_in6*>(&ss);
      sa6->sin6_family = AF_INET6;
      sa6->sin6_addr = in6;
      ssLen = sizeof(sockaddr_in6);
    }

    if (ssLen > 0) {
      char hostBuf[NI_MAXHOST] = {};
      if (getnameinfo(reinterpret_cast<const sockaddr*>(&ss), ssLen,
                      hostBuf, sizeof(hostBuf), nullptr, 0, NI_NAMEREQD) == 0) {
        hostResult = hostBuf;
      }
    }

    std::unique_lock lock(dnsMutex_);
    dnsCache_[ip] = std::move(hostResult);
  }
}

} // namespace netpulse
