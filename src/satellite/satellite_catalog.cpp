#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "orbital_propagator.hpp"
#include "satellite_catalog.hpp"
#include "../core/json_lite.hpp"
#include "../models.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

namespace netpulse::satellite {

namespace {

constexpr size_t kMaxPayloadBytes = 1024 * 1024;
constexpr uint64_t kManualCooldownMs = 30000;
constexpr uint64_t kRetryWaitMs = 400;

std::string trimCopy(const std::string& s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

std::string toLowerCopy(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

bool isLoopbackHost(const std::string& host) {
  const std::string h = toLowerCopy(host);
  return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]";
}

std::string replaceCatnr(std::string tpl, int noradId) {
  const std::string needle = "{CATNR}";
  const size_t pos = tpl.find(needle);
  if (pos != std::string::npos) {
    tpl.replace(pos, needle.size(), std::to_string(noradId));
  }
  return tpl;
}

bool extractJsonNumberField(const JsonValue& obj, const std::string& key, double& out) {
  const JsonValue* v = obj.get(key);
  if (!v) return false;
  if (v->isNumber()) {
    out = v->asDouble();
    return std::isfinite(out);
  }
  if (v->isString()) {
    const std::string s = trimCopy(v->asString());
    if (s.empty()) return false;
    char* endPtr = nullptr;
    double d = std::strtod(s.c_str(), &endPtr);
    if (endPtr == s.c_str() || *endPtr != '\0' || !std::isfinite(d)) return false;
    out = d;
    return true;
  }
  return false;
}

bool extractJsonIntField(const JsonValue& obj, const std::string& key, int& out) {
  const JsonValue* v = obj.get(key);
  if (!v) return false;
  if (v->isNumber()) {
    out = static_cast<int>(v->asInt());
    return true;
  }
  if (v->isString()) {
    const std::string s = trimCopy(v->asString());
    if (s.empty()) return false;
    char* endPtr = nullptr;
    long val = std::strtol(s.c_str(), &endPtr, 10);
    if (endPtr == s.c_str() || *endPtr != '\0') return false;
    out = static_cast<int>(val);
    return true;
  }
  return false;
}

bool parseTleImpliedDecimal(const std::string& field, double& out) {
  const std::string s = trimCopy(field);
  if (s.empty()) {
    out = 0.0;
    return true;
  }
  size_t idx = 0;
  double sign = 1.0;
  if (s[idx] == '-') {
    sign = -1.0;
    ++idx;
  } else if (s[idx] == '+') {
    ++idx;
  }
  std::string mantissa;
  while (idx < s.size() && std::isdigit(static_cast<unsigned char>(s[idx]))) {
    mantissa.push_back(s[idx]);
    ++idx;
  }
  if (mantissa.empty()) return false;

  int expSign = 1;
  int expVal = 0;
  if (idx < s.size()) {
    if (s[idx] == '-') {
      expSign = -1;
      ++idx;
    } else if (s[idx] == '+') {
      ++idx;
    } else {
      return false;
    }
    if (idx >= s.size() || !std::isdigit(static_cast<unsigned char>(s[idx]))) return false;
    while (idx < s.size()) {
      if (!std::isdigit(static_cast<unsigned char>(s[idx]))) return false;
      expVal = expVal * 10 + (s[idx] - '0');
      ++idx;
    }
  }
  const double m = std::strtod(("0." + mantissa).c_str(), nullptr);
  out = sign * m * std::pow(10.0, expSign * expVal);
  return std::isfinite(out);
}

bool parseFixedDouble(const std::string& s, double& out) {
  const std::string t = trimCopy(s);
  if (t.empty()) return false;
  char* endPtr = nullptr;
  double v = std::strtod(t.c_str(), &endPtr);
  if (endPtr == t.c_str() || *endPtr != '\0' || !std::isfinite(v)) return false;
  out = v;
  return true;
}

bool parseFixedInt(const std::string& s, int& out) {
  const std::string t = trimCopy(s);
  if (t.empty()) return false;
  char* endPtr = nullptr;
  long v = std::strtol(t.c_str(), &endPtr, 10);
  if (endPtr == t.c_str() || *endPtr != '\0') return false;
  out = static_cast<int>(v);
  return true;
}

bool isLeapYear(int year) {
  return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

std::string formatIsoUtc(int year, int month, int day, int hour, int minute, double second) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%06.3fZ", year, month, day, hour, minute, second);
  return std::string(buf);
}

std::string decodeChunkedBody(const std::string& raw) {
  std::string out;
  size_t pos = 0;
  while (pos < raw.size()) {
    size_t lineEnd = raw.find("\r\n", pos);
    if (lineEnd == std::string::npos) break;
    std::string sizeHex = raw.substr(pos, lineEnd - pos);
    size_t semi = sizeHex.find(';');
    if (semi != std::string::npos) sizeHex = sizeHex.substr(0, semi);
    size_t chunkLen = std::strtoul(sizeHex.c_str(), nullptr, 16);
    pos = lineEnd + 2;
    if (chunkLen == 0) break;
    if (pos + chunkLen > raw.size()) break;
    if (out.size() + chunkLen > kMaxPayloadBytes) break;
    out.append(raw, pos, chunkLen);
    pos += chunkLen;
    if (pos + 2 <= raw.size() && raw[pos] == '\r' && raw[pos + 1] == '\n') {
      pos += 2;
    }
  }
  return out;
}

std::vector<SatelliteTargetSpec> defaultTargetSpecs() {
  return {
      SatelliteTargetSpec{
          kNoradIss,
          "ISS",
          "ISS — Estação Espacial Internacional",
          "ISS",
          "1998-067A",
          "Estação Espacial (LEO)",
          "#22d3ee",
      },
      SatelliteTargetSpec{
          kNoradTiangong,
          "TIANGONG",
          "Tiangong — Estação Espacial Chinesa",
          "Tiangong",
          "2021-035A",
          "Estação Espacial (LEO)",
          "#fbbf24",
      },
  };
}

} // namespace

SatelliteCatalog::SatelliteCatalog(std::filesystem::path cachePath)
    : cachePath_(std::move(cachePath)),
      fetcher_([](const std::string& url) { return defaultHttpsGet(url); }) {
  std::lock_guard lock(mutex_);
  initDefaultSpecsLocked();
}

void SatelliteCatalog::initDefaultSpecsLocked() {
  entries_.clear();
  for (const auto& spec : defaultTargetSpecs()) {
    CatalogEntry entry;
    entry.spec = spec;
    entries_.push_back(std::move(entry));
  }
}

void SatelliteCatalog::setTargetSpecs(std::vector<SatelliteTargetSpec> specs) {
  std::lock_guard lock(mutex_);
  entries_.clear();
  for (auto& spec : specs) {
    CatalogEntry entry;
    entry.spec = std::move(spec);
    entries_.push_back(std::move(entry));
  }
}

void SatelliteCatalog::setHttpFetcher(HttpFetchFn fetcher) {
  std::lock_guard lock(mutex_);
  fetcher_ = fetcher ? std::move(fetcher) : [](const std::string& url) { return defaultHttpsGet(url); };
}

void SatelliteCatalog::setPrimaryEndpoints(std::string stationsOmmUrl,
                                           std::string catnrJsonTemplateUrl,
                                           std::string catnrTleTemplateUrl) {
  std::lock_guard lock(mutex_);
  if (!stationsOmmUrl.empty()) stationsOmmUrl_ = std::move(stationsOmmUrl);
  if (!catnrJsonTemplateUrl.empty()) catnrJsonUrlTpl_ = std::move(catnrJsonTemplateUrl);
  if (!catnrTleTemplateUrl.empty()) catnrTleUrlTpl_ = std::move(catnrTleTemplateUrl);
}

int SatelliteCatalog::computeTleChecksum(const std::string& line) {
  if (line.size() < 68) return -1;
  int sum = 0;
  for (size_t i = 0; i < 68; ++i) {
    char c = line[i];
    if (c >= '0' && c <= '9') {
      sum += (c - '0');
    } else if (c == '-') {
      sum += 1;
    }
  }
  return sum % 10;
}

bool SatelliteCatalog::parseIsoUtc(const std::string& iso,
                                   double& outJd,
                                   double& outJdFrac,
                                   uint64_t& outUnixMs) {
  const std::string s = trimCopy(iso);
  if (s.size() < 19) return false;
  if (s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') ||
      s[13] != ':' || s[16] != ':') {
    return false;
  }
  int year = 0, month = 0, day = 0, hour = 0, minute = 0;
  double sec = 0.0;
  if (!parseFixedInt(s.substr(0, 4), year) ||
      !parseFixedInt(s.substr(5, 2), month) ||
      !parseFixedInt(s.substr(8, 2), day) ||
      !parseFixedInt(s.substr(11, 2), hour) ||
      !parseFixedInt(s.substr(14, 2), minute)) {
    return false;
  }
  std::string secPart = s.substr(17);
  while (!secPart.empty() && (secPart.back() == 'Z' || secPart.back() == 'z')) {
    secPart.pop_back();
  }
  if (!parseFixedDouble(secPart, sec)) return false;
  return OrbitalPropagator::calendarUtcToJulianDate(year, month, day, hour, minute, sec, outJd, outJdFrac, outUnixMs);
}

bool SatelliteCatalog::parseTleEpoch(const std::string& epochStr,
                                     double& outJd,
                                     double& outJdFrac,
                                     uint64_t& outUnixMs,
                                     std::string& outIso) {
  const std::string s = trimCopy(epochStr);
  if (s.size() < 5) return false;
  int yy = 0;
  if (!parseFixedInt(s.substr(0, 2), yy)) return false;
  double doy = 0.0;
  if (!parseFixedDouble(s.substr(2), doy) || doy < 1.0 || doy >= 367.0) return false;

  const int year = (yy < 57) ? (2000 + yy) : (1900 + yy);
  const int intDay = static_cast<int>(std::floor(doy));
  const double fracDay = doy - static_cast<double>(intDay);

  static constexpr int kDaysInMonthNorm[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int rem = intDay;
  int month = 1;
  for (int m = 0; m < 12; ++m) {
    int dm = kDaysInMonthNorm[m];
    if (m == 1 && isLeapYear(year)) dm = 29;
    if (rem <= dm) {
      month = m + 1;
      break;
    }
    rem -= dm;
  }
  const int day = rem;
  const double totalSec = fracDay * 86400.0;
  int hour = static_cast<int>(totalSec / 3600.0);
  int minute = static_cast<int>((totalSec - hour * 3600.0) / 60.0);
  double sec = totalSec - hour * 3600.0 - minute * 60.0;
  if (hour >= 24) {
    hour = 23;
    minute = 59;
    sec = 59.999;
  }

  outIso = formatIsoUtc(year, month, day, hour, minute, sec);
  return OrbitalPropagator::calendarUtcToJulianDate(year, month, day, hour, minute, sec, outJd, outJdFrac, outUnixMs);
}

bool SatelliteCatalog::validateOrbitalElements(const OrbitalElements& el, std::string& outError) {
  if (el.noradId <= 0) {
    outError = "norad_id_invalid";
    return false;
  }
  if (!std::isfinite(el.meanMotionRevDay) || el.meanMotionRevDay <= 0.0 || el.meanMotionRevDay > 25.0) {
    outError = "mean_motion_out_of_range";
    return false;
  }
  if (!std::isfinite(el.eccentricity) || el.eccentricity < 0.0 || el.eccentricity >= 1.0) {
    outError = "eccentricity_out_of_range";
    return false;
  }
  if (!std::isfinite(el.inclinationDeg) || el.inclinationDeg < 0.0 || el.inclinationDeg > 180.0) {
    outError = "inclination_out_of_range";
    return false;
  }
  if (!std::isfinite(el.raanDeg) || !std::isfinite(el.argPerigeeDeg) ||
      !std::isfinite(el.meanAnomalyDeg) || !std::isfinite(el.bstar)) {
    outError = "orbital_angles_not_finite";
    return false;
  }
  if (!std::isfinite(el.epochJd) || el.epochJd < 2400000.0 || el.epochMs == 0) {
    outError = "epoch_invalid";
    return false;
  }
  return true;
}

bool SatelliteCatalog::parseOmmJson(const std::string& jsonBody,
                                    std::vector<OrbitalElements>& out,
                                    std::string& outError) {
  out.clear();
  if (jsonBody.empty() || jsonBody.size() > kMaxPayloadBytes) {
    outError = "omm_payload_empty_or_too_large";
    return false;
  }

  JsonValue root;
  if (!JsonValue::parse(jsonBody, root, outError, kMaxPayloadBytes)) {
    return false;
  }

  std::vector<const JsonValue*> objs;
  if (root.isArray()) {
    for (const auto& elem : root.asArray()) {
      if (elem.isObject()) objs.push_back(&elem);
    }
  } else if (root.isObject()) {
    if (const JsonValue* entries = root.get("entries"); entries && entries->isArray()) {
      for (const auto& elem : entries->asArray()) {
        if (elem.isObject()) objs.push_back(&elem);
      }
    } else {
      objs.push_back(&root);
    }
  } else {
    outError = "omm_root_must_be_array_or_object";
    return false;
  }

  if (objs.empty()) {
    outError = "omm_empty_records";
    return false;
  }

  for (const JsonValue* obj : objs) {
    OrbitalElements el;
    if (!extractJsonIntField(*obj, "NORAD_CAT_ID", el.noradId)) continue;

    el.objectName = trimCopy(obj->getString("OBJECT_NAME"));
    el.intlDesignator = trimCopy(obj->getString("OBJECT_ID"));
    el.epochIso = trimCopy(obj->getString("EPOCH"));
    if (!parseIsoUtc(el.epochIso, el.epochJd, el.epochJdFrac, el.epochMs)) {
      continue;
    }

    if (!extractJsonNumberField(*obj, "MEAN_MOTION", el.meanMotionRevDay)) continue;
    if (!extractJsonNumberField(*obj, "ECCENTRICITY", el.eccentricity)) continue;
    if (!extractJsonNumberField(*obj, "INCLINATION", el.inclinationDeg)) continue;
    if (!extractJsonNumberField(*obj, "RA_OF_ASC_NODE", el.raanDeg)) continue;
    if (!extractJsonNumberField(*obj, "ARG_OF_PERICENTER", el.argPerigeeDeg)) continue;
    if (!extractJsonNumberField(*obj, "MEAN_ANOMALY", el.meanAnomalyDeg)) continue;

    extractJsonNumberField(*obj, "BSTAR", el.bstar);
    extractJsonNumberField(*obj, "MEAN_MOTION_DOT", el.ndot);
    extractJsonNumberField(*obj, "MEAN_MOTION_DDOT", el.nddot);
    extractJsonIntField(*obj, "EPHEMERIS_TYPE", el.ephemerisType);
    extractJsonIntField(*obj, "ELEMENT_SET_NO", el.elementSetNo);
    extractJsonIntField(*obj, "REV_AT_EPOCH", el.revAtEpoch);

    const std::string cls = trimCopy(obj->getString("CLASSIFICATION_TYPE", "U"));
    el.classification = cls.empty() ? 'U' : cls[0];
    el.format = obj->getString("FORMAT", "OMM_JSON");
    el.source = obj->getString("SOURCE", "CelesTrak");
    el.fetchedAtMs = static_cast<uint64_t>(obj->getInt("FETCHED_AT_MS", 0));

    std::string verr;
    if (!validateOrbitalElements(el, verr)) {
      continue;
    }
    el.valid = true;
    out.push_back(std::move(el));
  }

  if (out.empty()) {
    outError = "omm_no_valid_records";
    return false;
  }
  return true;
}

bool SatelliteCatalog::parseTleText(const std::string& tleText,
                                    std::vector<OrbitalElements>& out,
                                    std::string& outError) {
  out.clear();
  if (tleText.empty() || tleText.size() > kMaxPayloadBytes) {
    outError = "tle_payload_empty_or_too_large";
    return false;
  }

  std::vector<std::string> lines;
  std::istringstream ss(tleText);
  std::string raw;
  while (std::getline(ss, raw)) {
    while (!raw.empty() && (raw.back() == '\r' || raw.back() == '\n')) raw.pop_back();
    if (!trimCopy(raw).empty()) lines.push_back(raw);
  }

  size_t i = 0;
  while (i < lines.size()) {
    std::string name;
    std::string l1;
    std::string l2;

    if (lines[i].size() >= 68 && lines[i][0] == '1' && lines[i][1] == ' ') {
      if (i + 1 >= lines.size()) break;
      l1 = lines[i];
      l2 = lines[i + 1];
      i += 2;
    } else if (i + 2 < lines.size() && lines[i + 1].size() >= 68 && lines[i + 1][0] == '1' &&
               lines[i + 2].size() >= 68 && lines[i + 2][0] == '2') {
      name = trimCopy(lines[i]);
      l1 = lines[i + 1];
      l2 = lines[i + 2];
      i += 3;
    } else {
      ++i;
      continue;
    }

    if (l1.size() < 69 || l2.size() < 69 || l1[0] != '1' || l2[0] != '2') {
      continue;
    }
    if (!std::isdigit(static_cast<unsigned char>(l1[68])) ||
        !std::isdigit(static_cast<unsigned char>(l2[68]))) {
      continue;
    }
    const int cksum1 = computeTleChecksum(l1);
    const int cksum2 = computeTleChecksum(l2);
    if (cksum1 != (l1[68] - '0') || cksum2 != (l2[68] - '0')) {
      outError = "tle_checksum_mismatch";
      continue;
    }

    int norad1 = 0, norad2 = 0;
    if (!parseFixedInt(l1.substr(2, 5), norad1) || !parseFixedInt(l2.substr(2, 5), norad2) ||
        norad1 <= 0 || norad1 != norad2) {
      outError = "tle_norad_mismatch";
      continue;
    }

    OrbitalElements el;
    el.noradId = norad1;
    el.objectName = name.empty() ? ("NORAD " + std::to_string(norad1)) : name;
    el.classification = l1[7];
    el.intlDesignator = trimCopy(l1.substr(9, 8));
    if (!parseTleEpoch(l1.substr(18, 14), el.epochJd, el.epochJdFrac, el.epochMs, el.epochIso)) {
      continue;
    }
    if (!parseFixedDouble(l1.substr(33, 10), el.ndot)) {
      el.ndot = 0.0;
    }
    if (!parseTleImpliedDecimal(l1.substr(44, 8), el.nddot)) continue;
    if (!parseTleImpliedDecimal(l1.substr(53, 8), el.bstar)) continue;
    parseFixedInt(l1.substr(62, 1), el.ephemerisType);
    parseFixedInt(l1.substr(64, 4), el.elementSetNo);

    if (!parseFixedDouble(l2.substr(8, 8), el.inclinationDeg)) continue;
    if (!parseFixedDouble(l2.substr(17, 8), el.raanDeg)) continue;
    if (!parseFixedDouble("0." + trimCopy(l2.substr(26, 7)), el.eccentricity)) continue;
    if (!parseFixedDouble(l2.substr(34, 8), el.argPerigeeDeg)) continue;
    if (!parseFixedDouble(l2.substr(43, 8), el.meanAnomalyDeg)) continue;
    if (!parseFixedDouble(l2.substr(52, 11), el.meanMotionRevDay)) continue;
    parseFixedInt(l2.substr(63, 5), el.revAtEpoch);

    el.format = "TLE";
    el.source = "CelesTrak";
    el.tleLine1 = l1;
    el.tleLine2 = l2;

    std::string verr;
    if (!validateOrbitalElements(el, verr)) {
      outError = verr;
      continue;
    }
    el.valid = true;
    out.push_back(std::move(el));
  }

  if (out.empty()) {
    if (outError.empty()) outError = "tle_no_valid_records";
    return false;
  }
  return true;
}

HttpFetchResult SatelliteCatalog::defaultHttpsGet(const std::string& url) {
  HttpFetchResult res;
  const std::string lower = toLowerCopy(url);
  const bool isHttps = (lower.rfind("https://", 0) == 0);
  const bool isHttp = (lower.rfind("http://", 0) == 0);
  if (!isHttps && !isHttp) {
    res.error = "unsupported_url_scheme";
    return res;
  }

  const size_t authStart = isHttps ? 8 : 7;
  const size_t pathPos = url.find('/', authStart);
  const std::string hostPort = (pathPos == std::string::npos) ? url.substr(authStart)
                                                              : url.substr(authStart, pathPos - authStart);
  std::string host = hostPort;
  const size_t colon = hostPort.rfind(':');
  if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
    host = hostPort.substr(0, colon);
  }
  if (isHttp && !isLoopbackHost(host)) {
    res.error = "external_requests_require_https";
    return res;
  }

#ifdef _WIN32
  std::wstring wUrl(url.begin(), url.end());
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof(uc);
  wchar_t hostBuf[256] = {};
  wchar_t pathBuf[2048] = {};
  uc.lpszHostName = hostBuf;
  uc.dwHostNameLength = static_cast<DWORD>(std::size(hostBuf));
  uc.lpszUrlPath = pathBuf;
  uc.dwUrlPathLength = static_cast<DWORD>(std::size(pathBuf));
  if (!WinHttpCrackUrl(wUrl.c_str(), static_cast<DWORD>(wUrl.size()), 0, &uc)) {
    res.error = "winhttp_crack_url_failed";
    return res;
  }

  const bool isLoop = isLoopbackHost(host);
  HINTERNET hSession = WinHttpOpen(L"NetPulse-Satellite/1.0",
                                   isLoop ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    res.error = "winhttp_open_failed";
    return res;
  }
  WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 8000);

  HINTERNET hConnect = WinHttpConnect(hSession, hostBuf, uc.nPort, 0);
  if (!hConnect) {
    WinHttpCloseHandle(hSession);
    res.error = "winhttp_connect_failed";
    return res;
  }

  const DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
  const wchar_t* pathPtr = pathBuf[0] ? pathBuf : L"/";
  HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pathPtr, nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!hRequest) {
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    res.error = "winhttp_open_request_failed";
    return res;
  }

  const wchar_t* hdrs = L"Accept: application/json, text/plain\r\n";
  BOOL sent = WinHttpSendRequest(hRequest, hdrs, static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
    const DWORD gle = GetLastError();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    res.error = "winhttp_transport_error_" + std::to_string(gle);
    return res;
  }

  DWORD statusCode = 0;
  DWORD sz = sizeof(statusCode);
  if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX)) {
    res.statusCode = static_cast<int>(statusCode);
  }

  DWORD avail = 0;
  while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
    if (res.body.size() + avail > kMaxPayloadBytes) {
      res.error = "payload_exceeds_limit";
      WinHttpCloseHandle(hRequest);
      WinHttpCloseHandle(hConnect);
      WinHttpCloseHandle(hSession);
      return res;
    }
    std::string chunk(avail, '\0');
    DWORD readBytes = 0;
    if (WinHttpReadData(hRequest, chunk.data(), avail, &readBytes) && readBytes > 0) {
      res.body.append(chunk.data(), readBytes);
    } else {
      break;
    }
  }

  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  res.ok = (res.statusCode >= 200 && res.statusCode < 300);
  if (!res.ok) res.error = "http_status_" + std::to_string(res.statusCode);
  return res;
#else
  std::string reqPath = (pathPos == std::string::npos) ? "/" : url.substr(pathPos);
  std::string portStr = isHttps ? "443" : "80";
  if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
    portStr = hostPort.substr(colon + 1);
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* resList = nullptr;
  if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &resList) != 0 || !resList) {
    res.error = "dns_resolution_failed";
    return res;
  }

  int fd = -1;
  for (addrinfo* p = resList; p != nullptr; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{8, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(resList);
  if (fd < 0) {
    res.error = "tcp_connect_failed";
    return res;
  }

  const std::string req = "GET " + reqPath + " HTTP/1.1\r\n"
                          "Host: " + hostPort + "\r\n"
                          "User-Agent: NetPulse-Satellite/1.0\r\n"
                          "Accept: application/json, text/plain\r\n"
                          "Accept-Encoding: identity\r\n"
                          "Connection: close\r\n\r\n";

  std::string raw;
  if (isHttps) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
      close(fd);
      res.error = "ssl_ctx_new_failed";
      return res;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());
    SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
    if (SSL_connect(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(fd);
      res.error = "tls_handshake_failed";
      return res;
    }
    SSL_write(ssl, req.data(), static_cast<int>(req.size()));
    char buf[4096];
    while (raw.size() < kMaxPayloadBytes + 8192) {
      int n = SSL_read(ssl, buf, sizeof(buf));
      if (n <= 0) break;
      raw.append(buf, static_cast<size_t>(n));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  } else {
    size_t sent = 0;
    while (sent < req.size()) {
      ssize_t n = send(fd, req.data() + sent, req.size() - sent, MSG_NOSIGNAL);
      if (n <= 0) break;
      sent += static_cast<size_t>(n);
    }
    char buf[4096];
    while (raw.size() < kMaxPayloadBytes + 8192) {
      ssize_t n = recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) break;
      raw.append(buf, static_cast<size_t>(n));
    }
  }
  close(fd);

  const size_t hdrEnd = raw.find("\r\n\r\n");
  if (hdrEnd == std::string::npos) {
    res.error = "invalid_http_response";
    return res;
  }
  const std::string hdrs = raw.substr(0, hdrEnd);
  std::string body = raw.substr(hdrEnd + 4);
  const size_t sp = hdrs.find(' ');
  if (sp != std::string::npos && sp + 4 <= hdrs.size()) {
    res.statusCode = std::atoi(hdrs.substr(sp + 1, 3).c_str());
  }
  const std::string lowerHdrs = toLowerCopy(hdrs);
  if (lowerHdrs.find("transfer-encoding: chunked") != std::string::npos) {
    body = decodeChunkedBody(body);
  }
  if (body.size() > kMaxPayloadBytes) {
    res.error = "payload_exceeds_limit";
    return res;
  }
  res.body = std::move(body);
  res.ok = (res.statusCode >= 200 && res.statusCode < 300);
  if (!res.ok) res.error = "http_status_" + std::to_string(res.statusCode);
  return res;
#endif
}

bool SatelliteCatalog::loadCache() {
  std::lock_guard lock(mutex_);
  std::error_code ec;
  if (!std::filesystem::exists(cachePath_, ec)) {
    return false;
  }
  std::ifstream in(cachePath_, std::ios::binary);
  if (!in.is_open()) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string content = ss.str();

  std::vector<OrbitalElements> parsed;
  std::string err;
  if (!parseOmmJson(content, parsed, err)) {
    return false;
  }

  std::vector<int> updatedIds;
  return applyParsedElementsLocked(parsed, CatalogDataState::Cached, 0, updatedIds);
}

void SatelliteCatalog::saveCacheLocked() const {
  std::error_code ec;
  if (!cachePath_.parent_path().empty()) {
    std::filesystem::create_directories(cachePath_.parent_path(), ec);
  }

  char buf[64];
  std::string out = "{\"version\":1,\"entries\":[";
  bool first = true;
  for (const auto& entry : entries_) {
    if (!entry.elements.valid) continue;
    const auto& el = entry.elements;
    if (!first) out.push_back(',');
    first = false;

    out += "{\"NORAD_CAT_ID\":" + std::to_string(el.noradId);
    out += ",\"OBJECT_NAME\":"; appendJsonEscaped(out, el.objectName);
    out += ",\"OBJECT_ID\":"; appendJsonEscaped(out, el.intlDesignator);
    out += ",\"EPOCH\":"; appendJsonEscaped(out, el.epochIso);
    std::snprintf(buf, sizeof(buf), "%.10f", el.meanMotionRevDay);
    out += ",\"MEAN_MOTION\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.10f", el.eccentricity);
    out += ",\"ECCENTRICITY\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.6f", el.inclinationDeg);
    out += ",\"INCLINATION\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.6f", el.raanDeg);
    out += ",\"RA_OF_ASC_NODE\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.6f", el.argPerigeeDeg);
    out += ",\"ARG_OF_PERICENTER\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.6f", el.meanAnomalyDeg);
    out += ",\"MEAN_ANOMALY\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.10e", el.bstar);
    out += ",\"BSTAR\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.10e", el.ndot);
    out += ",\"MEAN_MOTION_DOT\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.10e", el.nddot);
    out += ",\"MEAN_MOTION_DDOT\":"; out += buf;
    out += ",\"EPHEMERIS_TYPE\":" + std::to_string(el.ephemerisType);
    out += ",\"ELEMENT_SET_NO\":" + std::to_string(el.elementSetNo);
    out += ",\"REV_AT_EPOCH\":" + std::to_string(el.revAtEpoch);
    out += ",\"CLASSIFICATION_TYPE\":"; appendJsonEscaped(out, std::string(1, el.classification));
    out += ",\"FORMAT\":"; appendJsonEscaped(out, el.format);
    out += ",\"SOURCE\":"; appendJsonEscaped(out, el.source);
    out += ",\"FETCHED_AT_MS\":" + std::to_string(el.fetchedAtMs);
    out.push_back('}');
  }
  out += "]}";

  const auto tmpPath = std::filesystem::path(cachePath_.string() + ".tmp");
  std::ofstream file(tmpPath, std::ios::binary | std::ios::trunc);
  if (!file.is_open()) return;
  file << out;
  file.close();
  std::filesystem::rename(tmpPath, cachePath_, ec);
  if (ec) {
    std::filesystem::remove(cachePath_, ec);
    std::filesystem::rename(tmpPath, cachePath_, ec);
  }
}

bool SatelliteCatalog::applyParsedElementsLocked(const std::vector<OrbitalElements>& parsed,
                                                 CatalogDataState newState,
                                                 uint64_t nowMs,
                                                 std::vector<int>& updatedIds) {
  bool anyUpdated = false;
  for (auto& entry : entries_) {
    for (const auto& el : parsed) {
      if (el.noradId == entry.spec.noradId) {
        OrbitalElements copy = el;
        if (copy.fetchedAtMs == 0 && nowMs > 0) {
          copy.fetchedAtMs = nowMs;
        }
        entry.elements = std::move(copy);
        entry.dataState = newState;
        entry.lastSuccessMs = (entry.elements.fetchedAtMs > 0) ? entry.elements.fetchedAtMs : nowMs;
        if (nowMs > 0) entry.lastAttemptMs = nowMs;
        entry.lastError.clear();
        updatedIds.push_back(entry.spec.noradId);
        anyUpdated = true;
        break;
      }
    }
  }
  return anyUpdated;
}

bool SatelliteCatalog::shouldAutoRefresh(uint64_t nowMs, int refreshIntervalSec) const {
  std::lock_guard lock(mutex_);
  const uint64_t ttlMs = static_cast<uint64_t>(std::max(900, refreshIntervalSec)) * 1000ULL;
  for (const auto& entry : entries_) {
    if (!entry.elements.valid) {
      // Missing data: respect short retry backoff of 60s
      if (entry.lastAttemptMs == 0 || (nowMs > entry.lastAttemptMs && (nowMs - entry.lastAttemptMs) >= 60000ULL)) {
        return true;
      }
      continue;
    }
    const uint64_t refTime = entry.elements.fetchedAtMs > 0 ? entry.elements.fetchedAtMs : entry.lastSuccessMs;
    if (refTime == 0 || (nowMs > refTime && (nowMs - refTime) >= ttlMs)) {
      if (entry.lastAttemptMs == 0 || (nowMs > entry.lastAttemptMs && (nowMs - entry.lastAttemptMs) >= 60000ULL)) {
        return true;
      }
    }
  }
  return false;
}

bool SatelliteCatalog::refreshFromSource(uint64_t nowMs, bool force, std::string& outSummaryError) {
  outSummaryError.clear();

  HttpFetchFn fetcher;
  std::string stationsUrl;
  std::string catnrJsonTpl;
  std::string catnrTleTpl;
  std::vector<int> targetIds;
  {
    std::lock_guard lock(mutex_);
    if (!force && lastManualFetchMs_ > 0 && nowMs >= lastManualFetchMs_ &&
        (nowMs - lastManualFetchMs_) < kManualCooldownMs) {
      outSummaryError = "cooldown_active";
      return false;
    }
    lastManualFetchMs_ = nowMs;
    fetcher = fetcher_;
    stationsUrl = stationsOmmUrl_;
    catnrJsonTpl = catnrJsonUrlTpl_;
    catnrTleTpl = catnrTleUrlTpl_;
    for (const auto& e : entries_) {
      targetIds.push_back(e.spec.noradId);
    }
  }

  auto fetchWithRetry = [&](const std::string& url) -> HttpFetchResult {
    HttpFetchResult r;
    for (int attempt = 0; attempt < 2; ++attempt) {
      r = fetcher(url);
      if (r.ok) return r;
      if (attempt == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kRetryWaitMs));
      }
    }
    return r;
  };

  std::vector<OrbitalElements> collected;
  std::string batchErr;

  // 1. Primary batch OMM JSON query (avoids repeated downloads for ISS + Tiangong)
  HttpFetchResult batchResp = fetchWithRetry(stationsUrl);
  if (batchResp.ok) {
    std::vector<OrbitalElements> parsed;
    if (parseOmmJson(batchResp.body, parsed, batchErr)) {
      for (auto& el : parsed) {
        if (el.fetchedAtMs == 0) el.fetchedAtMs = nowMs;
        collected.push_back(std::move(el));
      }
    }
  } else {
    batchErr = batchResp.error.empty() ? "http_error" : batchResp.error;
  }

  // 2. Fallback individual fetch (OMM JSON -> TLE) only for missing targets
  for (int id : targetIds) {
    const bool found = std::any_of(collected.begin(), collected.end(),
                                   [id](const OrbitalElements& el) { return el.noradId == id; });
    if (found) continue;

    bool gotOne = false;
    std::string errOne;
    HttpFetchResult jsonResp = fetchWithRetry(replaceCatnr(catnrJsonTpl, id));
    if (jsonResp.ok) {
      std::vector<OrbitalElements> parsed;
      if (parseOmmJson(jsonResp.body, parsed, errOne)) {
        for (auto& el : parsed) {
          if (el.noradId == id) {
            if (el.fetchedAtMs == 0) el.fetchedAtMs = nowMs;
            collected.push_back(std::move(el));
            gotOne = true;
          }
        }
      }
    } else {
      errOne = jsonResp.error;
    }

    if (!gotOne) {
      HttpFetchResult tleResp = fetchWithRetry(replaceCatnr(catnrTleTpl, id));
      if (tleResp.ok) {
        std::vector<OrbitalElements> parsed;
        std::string tleErr;
        if (parseTleText(tleResp.body, parsed, tleErr)) {
          for (auto& el : parsed) {
            if (el.noradId == id) {
              if (el.fetchedAtMs == 0) el.fetchedAtMs = nowMs;
              collected.push_back(std::move(el));
              gotOne = true;
            }
          }
        } else if (errOne.empty()) {
          errOne = tleErr;
        }
      } else if (errOne.empty()) {
        errOne = tleResp.error;
      }
    }

    if (!gotOne && !errOne.empty() && outSummaryError.empty()) {
      outSummaryError = errOne;
    }
  }

  if (outSummaryError.empty() && !batchErr.empty() && collected.empty()) {
    outSummaryError = batchErr;
  }

  std::lock_guard lock(mutex_);
  std::vector<int> updatedIds;
  const bool anyUpdated = applyParsedElementsLocked(collected, CatalogDataState::Live, nowMs, updatedIds);

  // Preserve valid cache on failure for any target not updated
  for (auto& entry : entries_) {
    const bool wasUpdated = std::find(updatedIds.begin(), updatedIds.end(), entry.spec.noradId) != updatedIds.end();
    if (!wasUpdated) {
      entry.lastAttemptMs = nowMs;
      entry.lastError = outSummaryError.empty() ? "orbital_elements_unavailable" : outSummaryError;
      if (entry.elements.valid) {
        entry.dataState = CatalogDataState::CachedFallback;
      } else {
        entry.dataState = CatalogDataState::Unavailable;
      }
    }
  }

  if (anyUpdated) {
    saveCacheLocked();
  }
  return anyUpdated;
}

bool SatelliteCatalog::upsertValidatedElements(const OrbitalElements& el,
                                               CatalogDataState state,
                                               uint64_t nowMs,
                                               std::string& outError) {
  if (!validateOrbitalElements(el, outError)) {
    return false;
  }
  OrbitalElements copy = el;
  copy.valid = true;
  if (copy.fetchedAtMs == 0) copy.fetchedAtMs = nowMs;

  std::lock_guard lock(mutex_);
  std::vector<int> updatedIds;
  const bool ok = applyParsedElementsLocked({copy}, state, nowMs, updatedIds);
  if (!ok) {
    outError = "norad_id_not_registered";
    return false;
  }
  saveCacheLocked();
  return true;
}

std::vector<CatalogEntry> SatelliteCatalog::getEntriesSnapshot() const {
  std::lock_guard lock(mutex_);
  return entries_;
}

std::optional<CatalogEntry> SatelliteCatalog::getEntry(int noradId) const {
  std::lock_guard lock(mutex_);
  for (const auto& entry : entries_) {
    if (entry.spec.noradId == noradId) return entry;
  }
  return std::nullopt;
}

std::string SatelliteCatalog::toCatalogJson() const {
  std::lock_guard lock(mutex_);
  char buf[64];
  std::string out = "{\"objects\":[";
  for (size_t i = 0; i < entries_.size(); ++i) {
    const auto& e = entries_[i];
    if (i > 0) out.push_back(',');
    out += "{\"noradId\":" + std::to_string(e.spec.noradId);
    out += ",\"code\":"; appendJsonEscaped(out, e.spec.code);
    out += ",\"displayName\":"; appendJsonEscaped(out, e.spec.displayName);
    out += ",\"intlId\":"; appendJsonEscaped(out, e.spec.intlId);
    out += ",\"category\":"; appendJsonEscaped(out, e.spec.category);
    out += ",\"dataState\":"; appendJsonEscaped(out, catalogDataStateToString(e.dataState));
    out += ",\"lastAttemptMs\":" + std::to_string(e.lastAttemptMs);
    out += ",\"lastSuccessMs\":" + std::to_string(e.lastSuccessMs);
    out += ",\"lastError\":"; appendJsonEscaped(out, e.lastError);
    out += ",\"hasElements\":"; out += (e.elements.valid ? "true" : "false");
    if (e.elements.valid) {
      out += ",\"objectName\":"; appendJsonEscaped(out, e.elements.objectName);
      out += ",\"epochIso\":"; appendJsonEscaped(out, e.elements.epochIso);
      out += ",\"epochMs\":" + std::to_string(e.elements.epochMs);
      out += ",\"fetchedAtMs\":" + std::to_string(e.elements.fetchedAtMs);
      out += ",\"format\":"; appendJsonEscaped(out, e.elements.format);
      out += ",\"source\":"; appendJsonEscaped(out, e.elements.source);
      std::snprintf(buf, sizeof(buf), "%.4f", e.elements.inclinationDeg);
      out += ",\"inclinationDeg\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.7f", e.elements.eccentricity);
      out += ",\"eccentricity\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.8f", e.elements.meanMotionRevDay);
      out += ",\"meanMotionRevDay\":"; out += buf;
    }
    out.push_back('}');
  }
  out += "]}";
  return out;
}

} // namespace netpulse::satellite
