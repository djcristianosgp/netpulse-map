#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include "models.hpp"
#include "updater.hpp"
#include "version.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>

namespace netpulse {

namespace {

struct WinHttpCloser {
  HINTERNET h = nullptr;
  ~WinHttpCloser() {
    if (h) WinHttpCloseHandle(h);
  }
};

std::wstring utf8ToWide(const std::string& s) {
  if (s.empty()) return {};
  int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
  return out;
}

std::string toLower(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

const char* updateStateToString(UpdateState st) {
  switch (st) {
    case UpdateState::Checking: return "checking";
    case UpdateState::UpToDate: return "up_to_date";
    case UpdateState::Available: return "available";
    case UpdateState::Downloading: return "downloading";
    case UpdateState::Verifying: return "verifying";
    case UpdateState::Installing: return "installing";
    case UpdateState::Error: return "error";
    default: return "idle";
  }
}

bool extractJsonStringField(const std::string& obj, const std::string& key, std::string& out) {
  size_t i = 0;
  const size_t n = obj.size();
  while (i < n) {
    if (obj[i] == '"') {
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
    } else {
      ++i;
    }
  }
  return false;
}

bool extractJsonUint64Field(const std::string& obj, const std::string& key, uint64_t& out) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = 0;
  while ((pos = obj.find(needle, pos)) != std::string::npos) {
    size_t i = pos + needle.size();
    while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t')) ++i;
    if (i < obj.size() && obj[i] == ':') {
      ++i;
      while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t')) ++i;
      if (i < obj.size() && obj[i] >= '0' && obj[i] <= '9') {
        char* endPtr = nullptr;
        uint64_t val = std::strtoull(obj.c_str() + i, &endPtr, 10);
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

std::vector<std::string> splitAssetObjects(const std::string& json) {
  std::vector<std::string> items;
  const size_t assetsKey = json.find("\"assets\"");
  if (assetsKey == std::string::npos) return items;
  const size_t arrStart = json.find('[', assetsKey);
  if (arrStart == std::string::npos) return items;

  bool inStr = false;
  int depth = 0;
  size_t objStart = std::string::npos;
  for (size_t i = arrStart + 1; i < json.size(); ++i) {
    char c = json[i];
    if (inStr) {
      if (c == '\\' && i + 1 < json.size()) ++i;
      else if (c == '"') inStr = false;
      continue;
    }
    if (c == '"') {
      inStr = true;
    } else if (c == '{') {
      if (depth == 0) objStart = i;
      ++depth;
    } else if (c == '}') {
      if (depth > 0) --depth;
      if (depth == 0 && objStart != std::string::npos) {
        items.push_back(json.substr(objStart, i - objStart + 1));
        objStart = std::string::npos;
      }
    } else if (c == ']' && depth == 0) {
      break;
    }
  }
  return items;
}

struct HttpsResponse {
  DWORD status = 0;
  std::string body;
  std::string error;
};

HttpsResponse httpsGetUrl(const std::string& url,
                          const std::filesystem::path* saveToPath = nullptr,
                          std::function<void(uint64_t downloaded, uint64_t total)> onProgress = nullptr) {
  HttpsResponse res;
  std::wstring wUrl = utf8ToWide(url);

  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof(uc);
  wchar_t hostBuf[256] = {};
  wchar_t pathBuf[2048] = {};
  uc.lpszHostName = hostBuf;
  uc.dwHostNameLength = static_cast<DWORD>(std::size(hostBuf));
  uc.lpszUrlPath = pathBuf;
  uc.dwUrlPathLength = static_cast<DWORD>(std::size(pathBuf));

  if (!WinHttpCrackUrl(wUrl.c_str(), static_cast<DWORD>(wUrl.size()), 0, &uc)) {
    res.error = "Invalid URL";
    return res;
  }

  WinHttpCloser session{WinHttpOpen(L"NetPulseMap-Updater/1.0",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS,
                                    0)};
  if (!session.h) {
    res.error = "WinHttpOpen failed";
    return res;
  }

  WinHttpSetTimeouts(session.h, 5000, 5000, 10000, 30000);
  DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
  WinHttpSetOption(session.h, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

  WinHttpCloser conn{WinHttpConnect(session.h, uc.lpszHostName, uc.nPort, 0)};
  if (!conn.h) {
    res.error = "WinHttpConnect failed";
    return res;
  }

  DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
  WinHttpCloser req{WinHttpOpenRequest(conn.h, L"GET", uc.lpszUrlPath, nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       flags)};
  if (!req.h) {
    res.error = "WinHttpOpenRequest failed";
    return res;
  }

  const wchar_t* hdrs = L"Accept: application/vnd.github+json\r\n";
  if (!WinHttpSendRequest(req.h, hdrs, static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
      !WinHttpReceiveResponse(req.h, nullptr)) {
    res.error = "Network request failed (error " + std::to_string(GetLastError()) + ")";
    return res;
  }

  DWORD statusSize = sizeof(res.status);
  WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &res.status, &statusSize, WINHTTP_NO_HEADER_INDEX);

  if (res.status < 200 || res.status >= 300) {
    res.error = "HTTP " + std::to_string(res.status);
    return res;
  }

  uint64_t totalBytes = 0;
  wchar_t lenBuf[32] = {};
  DWORD lenSize = sizeof(lenBuf);
  if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                          lenBuf, &lenSize, WINHTTP_NO_HEADER_INDEX)) {
    totalBytes = _wcstoui64(lenBuf, nullptr, 10);
  }

  std::ofstream outFile;
  if (saveToPath) {
    std::error_code ec;
    std::filesystem::create_directories(saveToPath->parent_path(), ec);
    outFile.open(*saveToPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
      res.error = "Failed to open destination file";
      return res;
    }
  }

  uint64_t downloaded = 0;
  DWORD avail = 0;
  std::vector<char> buf;
  while (WinHttpQueryDataAvailable(req.h, &avail) && avail > 0) {
    const size_t chunk = std::min<size_t>(avail, 65536);
    buf.resize(chunk);
    DWORD read = 0;
    if (!WinHttpReadData(req.h, buf.data(), static_cast<DWORD>(chunk), &read) || read == 0) {
      break;
    }
    if (saveToPath) {
      outFile.write(buf.data(), read);
    } else {
      res.body.append(buf.data(), read);
    }
    downloaded += read;
    if (onProgress) onProgress(downloaded, totalBytes);
  }
  return res;
}

bool spawnDetachedInstallerTrampoline(const std::filesystem::path& installerPath,
                                      const std::filesystem::path& currentExePath) {
  wchar_t tempDir[MAX_PATH] = {};
  if (GetTempPathW(MAX_PATH, tempDir) == 0) return false;

  const DWORD pid = GetCurrentProcessId();
  std::filesystem::path scriptPath = std::filesystem::path(tempDir) / "netpulse_self_update.ps1";
  {
    std::ofstream ps(scriptPath, std::ios::trunc);
    if (!ps.is_open()) return false;
    ps << "$ErrorActionPreference = 'SilentlyContinue'\n"
       << "Wait-Process -Id " << pid << " -Timeout 15\n"
       << "Start-Sleep -Milliseconds 400\n"
       << "$p = Start-Process -FilePath '" << installerPath.string() << "' -ArgumentList '/SILENT','/NORESTART' -Wait -PassThru\n"
       << "$installed = $null\n"
       << "foreach ($root in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8A4E9C21-6F3B-4B7A-9E12-3D5C7F8A1B40}_is1','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8A4E9C21-6F3B-4B7A-9E12-3D5C7F8A1B40}_is1')) {\n"
       << "  $prop = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue\n"
       << "  if ($prop -and $prop.InstallLocation) {\n"
       << "    $cand = Join-Path $prop.InstallLocation 'netpulse.exe'\n"
       << "    if (Test-Path $cand) { $installed = $cand; break }\n"
       << "  }\n"
       << "}\n"
       << "if (-not $installed) { $installed = '" << currentExePath.string() << "' }\n"
       << "if (Test-Path $installed) { Start-Process -FilePath $installed }\n";
  }

  std::wstring cmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" +
                     scriptPath.wstring() + L"\"";
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                           DETACHED_PROCESS | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
  if (ok) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
  }
  return false;
}

} // namespace

SemVer parseSemVer(const std::string& raw) {
  SemVer sv;
  std::string s = raw;
  if (!s.empty() && (s[0] == 'v' || s[0] == 'V')) s = s.substr(1);

  size_t dash = s.find('-');
  if (dash != std::string::npos) {
    sv.prerelease = s.substr(dash + 1);
    s = s.substr(0, dash);
  }
  size_t plus = s.find('+');
  if (plus != std::string::npos) s = s.substr(0, plus);

  std::stringstream ss(s);
  std::string part;
  std::vector<int> nums;
  while (std::getline(ss, part, '.')) {
    if (part.empty()) return sv;
    for (char c : part) {
      if (c < '0' || c > '9') return sv;
    }
    nums.push_back(std::atoi(part.c_str()));
  }
  if (nums.size() < 2) return sv;
  sv.major = nums[0];
  sv.minor = nums[1];
  sv.patch = (nums.size() >= 3) ? nums[2] : 0;
  sv.valid = true;
  return sv;
}

bool isNewerVersion(const std::string& current, const std::string& candidate) {
  const SemVer a = parseSemVer(current);
  const SemVer b = parseSemVer(candidate);
  if (!a.valid || !b.valid) return false;

  if (b.major != a.major) return b.major > a.major;
  if (b.minor != a.minor) return b.minor > a.minor;
  if (b.patch != a.patch) return b.patch > a.patch;

  // Release without prerelease is newer than same version with prerelease (e.g. 1.0.0 > 1.0.0-beta.1)
  if (a.prerelease.empty() != b.prerelease.empty()) {
    return b.prerelease.empty();
  }
  return b.prerelease > a.prerelease;
}

ReleaseInfo parseGitHubReleaseJson(const std::string& json) {
  ReleaseInfo info;
  if (!extractJsonStringField(json, "tag_name", info.tagName) || info.tagName.empty()) {
    return info;
  }
  info.version = (!info.tagName.empty() && (info.tagName[0] == 'v' || info.tagName[0] == 'V'))
                     ? info.tagName.substr(1)
                     : info.tagName;
  extractJsonStringField(json, "html_url", info.htmlUrl);
  extractJsonStringField(json, "published_at", info.publishedAt);

  for (const auto& assetObj : splitAssetObjects(json)) {
    std::string name;
    std::string dlUrl;
    uint64_t size = 0;
    extractJsonStringField(assetObj, "name", name);
    extractJsonStringField(assetObj, "browser_download_url", dlUrl);
    extractJsonUint64Field(assetObj, "size", size);

    if (name == "NetPulse2D-Setup-x64.exe") {
      info.installerUrl = dlUrl;
      info.installerSize = size;
    } else if (name == "checksums.txt") {
      info.checksumsUrl = dlUrl;
    }
  }
  info.valid = !info.version.empty();
  return info;
}

std::string parseSha256FromChecksums(const std::string& checksumsText, const std::string& fileName) {
  std::istringstream iss(checksumsText);
  std::string line;
  while (std::getline(iss, line)) {
    // Strip UTF-8 BOM if present
    if (line.size() >= 3 &&
        static_cast<unsigned char>(line[0]) == 0xEF &&
        static_cast<unsigned char>(line[1]) == 0xBB &&
        static_cast<unsigned char>(line[2]) == 0xBF) {
      line = line.substr(3);
    }
    if (line.find(fileName) == std::string::npos) continue;
    std::istringstream lss(line);
    std::string hash;
    lss >> hash;
    if (hash.size() == 64) {
      return toLower(hash);
    }
  }
  return {};
}

std::string computeFileSha256Hex(const std::filesystem::path& filePath) {
  std::ifstream in(filePath, std::ios::binary);
  if (!in.is_open()) return {};

  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;
  if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};

  std::string hexOut;
  if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
    char buf[65536];
    bool ok = true;
    while (in.good()) {
      in.read(buf, sizeof(buf));
      std::streamsize n = in.gcount();
      if (n > 0) {
        if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buf), static_cast<ULONG>(n), 0) != 0) {
          ok = false;
          break;
        }
      }
    }
    uint8_t digest[32] = {};
    if (ok && BCryptFinishHash(hHash, digest, sizeof(digest), 0) == 0) {
      static const char* kHex = "0123456789abcdef";
      hexOut.reserve(64);
      for (uint8_t b : digest) {
        hexOut.push_back(kHex[(b >> 4) & 0x0F]);
        hexOut.push_back(kHex[b & 0x0F]);
      }
    }
    BCryptDestroyHash(hHash);
  }
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return hexOut;
}

UpdateManager::UpdateManager(std::string currentVersion, ExitCallback onRequestExit)
    : currentVersion_(std::move(currentVersion)),
      onRequestExit_(std::move(onRequestExit)) {
  status_.currentVersion = currentVersion_;
}

UpdateManager::~UpdateManager() {
  stop();
}

void UpdateManager::startAutoCheck() {
  if (running_.exchange(true)) return;
  autoThread_ = std::jthread([this](std::stop_token st) {
    // Wait 2.5s after startup before checking so initial telemetry loads first.
    for (int i = 0; i < 25 && !st.stop_requested(); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    while (!st.stop_requested()) {
      runCheck();
      for (int i = 0; i < 6 * 3600 && !st.stop_requested(); ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
  });
}

void UpdateManager::stop() {
  if (!running_.exchange(false)) return;
  if (autoThread_.joinable()) {
    autoThread_.request_stop();
    autoThread_.join();
  }
  if (workerThread_.joinable()) {
    workerThread_.join();
  }
}

void UpdateManager::checkNowAsync() {
  if (busy_.exchange(true)) return;
  if (workerThread_.joinable()) workerThread_.join();
  workerThread_ = std::jthread([this](std::stop_token) {
    runCheck();
    busy_.store(false);
  });
}

bool UpdateManager::startInstallAsync() {
  {
    std::lock_guard lock(mutex_);
    if (!latestRelease_.valid || latestRelease_.installerUrl.empty()) return false;
    if (status_.state != UpdateState::Available && status_.state != UpdateState::Error) return false;
  }
  if (busy_.exchange(true)) return false;
  if (workerThread_.joinable()) workerThread_.join();
  workerThread_ = std::jthread([this](std::stop_token) {
    runDownloadAndInstall();
    busy_.store(false);
  });
  return true;
}

void UpdateManager::runCheck() {
  {
    std::lock_guard lock(mutex_);
    if (status_.state == UpdateState::Downloading ||
        status_.state == UpdateState::Verifying ||
        status_.state == UpdateState::Installing) {
      return;
    }
    status_.state = UpdateState::Checking;
    status_.error.clear();
  }

  const std::string apiUrl = std::string("https://api.github.com/repos/") +
                             kGitHubOwner + "/" + kGitHubRepo + "/releases/latest";
  auto resp = httpsGetUrl(apiUrl);
  if (!resp.error.empty() || resp.body.empty()) {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Error;
    status_.error = resp.error.empty() ? "Empty GitHub API response" : resp.error;
    return;
  }

  ReleaseInfo rel = parseGitHubReleaseJson(resp.body);
  if (!rel.valid) {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Error;
    status_.error = "Could not parse latest release metadata";
    return;
  }

  std::lock_guard lock(mutex_);
  latestRelease_ = rel;
  status_.latestVersion = rel.version;
  status_.releaseUrl = rel.htmlUrl;
  status_.installerUrl = rel.installerUrl;
  status_.installerSize = rel.installerSize;
  status_.state = (isNewerVersion(currentVersion_, rel.version) && !rel.installerUrl.empty())
                      ? UpdateState::Available
                      : UpdateState::UpToDate;
}

void UpdateManager::runDownloadAndInstall() {
  ReleaseInfo rel;
  {
    std::lock_guard lock(mutex_);
    rel = latestRelease_;
    status_.state = UpdateState::Downloading;
    status_.progressPct = 0;
    status_.error.clear();
  }

  std::string expectedHash;
  if (!rel.checksumsUrl.empty()) {
    auto csResp = httpsGetUrl(rel.checksumsUrl);
    if (!csResp.error.empty()) {
      std::lock_guard lock(mutex_);
      status_.state = UpdateState::Error;
      status_.error = "Falha ao baixar checksums.txt: " + csResp.error;
      return;
    }
    expectedHash = parseSha256FromChecksums(csResp.body, "NetPulse2D-Setup-x64.exe");
  }

  wchar_t tempDir[MAX_PATH] = {};
  GetTempPathW(MAX_PATH, tempDir);
  const std::filesystem::path setupPath =
      std::filesystem::path(tempDir) / ("NetPulse2D-Setup-" + rel.version + ".exe");

  auto dlResp = httpsGetUrl(rel.installerUrl, &setupPath, [this, &rel](uint64_t got, uint64_t total) {
    uint64_t denom = (total > 0) ? total : rel.installerSize;
    int pct = (denom > 0) ? static_cast<int>(std::min<uint64_t>(100, (got * 100) / denom)) : 0;
    std::lock_guard lock(mutex_);
    status_.progressPct = pct;
  });

  if (!dlResp.error.empty()) {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Error;
    status_.error = "Falha no download do instalador: " + dlResp.error;
    return;
  }

  {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Verifying;
    status_.progressPct = 100;
  }

  if (!expectedHash.empty()) {
    const std::string actualHash = computeFileSha256Hex(setupPath);
    if (actualHash.empty() || actualHash != expectedHash) {
      std::error_code ec;
      std::filesystem::remove(setupPath, ec);
      std::lock_guard lock(mutex_);
      status_.state = UpdateState::Error;
      status_.error = "Falha de integridade SHA-256 do instalador";
      return;
    }
  }

  wchar_t exeBuf[MAX_PATH * 2] = {};
  GetModuleFileNameW(nullptr, exeBuf, static_cast<DWORD>(std::size(exeBuf)));
  if (!spawnDetachedInstallerTrampoline(setupPath, std::filesystem::path(exeBuf))) {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Error;
    status_.error = "Nao foi possivel iniciar o instalador";
    return;
  }

  {
    std::lock_guard lock(mutex_);
    status_.state = UpdateState::Installing;
  }
  if (onRequestExit_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    onRequestExit_();
  }
}

UpdateStatus UpdateManager::getStatus() const {
  std::lock_guard lock(mutex_);
  return status_;
}

std::string UpdateManager::getStatusJson() const {
  UpdateStatus st = getStatus();
  std::string out = "{\"currentVersion\":";
  appendJsonEscaped(out, st.currentVersion);
  out += ",\"state\":\"";
  out += updateStateToString(st.state);
  out += "\",\"latestVersion\":";
  appendJsonEscaped(out, st.latestVersion);
  out += ",\"releaseUrl\":";
  appendJsonEscaped(out, st.releaseUrl);
  out += ",\"downloadUrl\":";
  appendJsonEscaped(out, st.installerUrl);
  out += ",\"assetSize\":";
  out += std::to_string(st.installerSize);
  out += ",\"progressPct\":";
  out += std::to_string(st.progressPct);
  out += ",\"error\":";
  appendJsonEscaped(out, st.error);
  out.push_back('}');
  return out;
}

} // namespace netpulse
