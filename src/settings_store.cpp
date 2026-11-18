#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#endif

#include "models.hpp"
#include "settings_store.hpp"

#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr wchar_t kRunSubkey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"NetPulse2D";

} // namespace

bool SettingsStore::parseLine(const std::string& line, std::string& key, std::string& val) {
  if (line.empty() || line[0] == '#') return false;
  size_t tab = line.find('\t');
  if (tab == std::string::npos) return false;
  key = line.substr(0, tab);
  val = line.substr(tab + 1);
  while (!val.empty() && (val.back() == '\r' || val.back() == '\n')) val.pop_back();
  return !key.empty();
}

bool SettingsStore::queryWindowsAutoStartRegistry() {
#ifdef _WIN32
  HKEY hKey = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunSubkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
    return false;
  }
  DWORD type = 0;
  DWORD size = 0;
  LONG rc = RegQueryValueExW(hKey, kRunValueName, nullptr, &type, nullptr, &size);
  RegCloseKey(hKey);
  return (rc == ERROR_SUCCESS && size > 2);
#else
  return false;
#endif
}

bool SettingsStore::syncWindowsAutoStartRegistry(bool enabled,
                                                 bool startMinimized,
                                                 std::string& outError) {
#ifdef _WIN32
  HKEY hKey = nullptr;
  LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, kRunSubkey, 0, nullptr, 0,
                            KEY_WRITE, nullptr, &hKey, nullptr);
  if (rc != ERROR_SUCCESS) {
    outError = "Falha ao abrir registro do Windows (" + std::to_string(rc) + ")";
    return false;
  }

  if (enabled) {
    wchar_t exeBuf[MAX_PATH * 2] = {};
    DWORD len = GetModuleFileNameW(nullptr, exeBuf, static_cast<DWORD>(std::size(exeBuf)));
    if (len == 0) {
      RegCloseKey(hKey);
      outError = "Nao foi possivel localizar executavel";
      return false;
    }
    std::wstring cmd = L"\"";
    cmd.append(exeBuf, len);
    cmd += L"\"";
    if (startMinimized) {
      cmd += L" --no-browser";
    }
    rc = RegSetValueExW(hKey, kRunValueName, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(cmd.c_str()),
                        static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
  } else {
    rc = RegDeleteValueW(hKey, kRunValueName);
    if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;
  }

  RegCloseKey(hKey);
  if (rc != ERROR_SUCCESS) {
    outError = "Falha ao gravar registro do Windows (" + std::to_string(rc) + ")";
    return false;
  }
  return true;
#else
  (void)enabled;
  (void)startMinimized;
  (void)outError;
  return true;
#endif
}

SettingsStore::SettingsStore(std::filesystem::path settingsPath)
    : path_(std::move(settingsPath)) {
  load();
}

void SettingsStore::load() {
  std::lock_guard lock(mutex_);
  std::error_code ec;
  if (std::filesystem::exists(path_, ec)) {
    std::ifstream in(path_);
    std::string line;
    while (std::getline(in, line)) {
      std::string k, v;
      if (!parseLine(line, k, v)) continue;
      if (k == "alertsEnabled") settings_.alertsEnabled = (v == "1" || v == "true");
      else if (k == "notifyServiceDown") settings_.notifyServiceDown = (v == "1" || v == "true");
      else if (k == "notifyServiceDegraded") settings_.notifyServiceDegraded = (v == "1" || v == "true");
      else if (k == "notifySensitivePort") settings_.notifySensitivePort = (v == "1" || v == "true");
      else if (k == "notifyNewCountry") settings_.notifyNewCountry = (v == "1" || v == "true");
      else if (k == "autoStart") settings_.autoStart = (v == "1" || v == "true");
      else if (k == "defaultView") settings_.defaultView = (v == "global") ? "global" : "local";
      else if (k == "minimizeToTray") settings_.minimizeToTray = (v == "1" || v == "true");
    }
  }
  // Authoritative check against HKCU Run key (in case installer checked startup task)
  settings_.autoStart = queryWindowsAutoStartRegistry();
}

void SettingsStore::save() {
  std::error_code ec;
  std::filesystem::create_directories(path_.parent_path(), ec);
  std::ofstream out(path_, std::ios::trunc);
  if (!out.is_open()) return;
  out << "alertsEnabled\t" << (settings_.alertsEnabled ? "1" : "0") << '\n'
      << "notifyServiceDown\t" << (settings_.notifyServiceDown ? "1" : "0") << '\n'
      << "notifyServiceDegraded\t" << (settings_.notifyServiceDegraded ? "1" : "0") << '\n'
      << "notifySensitivePort\t" << (settings_.notifySensitivePort ? "1" : "0") << '\n'
      << "notifyNewCountry\t" << (settings_.notifyNewCountry ? "1" : "0") << '\n'
      << "autoStart\t" << (settings_.autoStart ? "1" : "0") << '\n'
      << "defaultView\t" << settings_.defaultView << '\n'
      << "minimizeToTray\t" << (settings_.minimizeToTray ? "1" : "0") << '\n';
}

AppSettings SettingsStore::get() const {
  std::lock_guard lock(mutex_);
  AppSettings copy = settings_;
  copy.autoStart = queryWindowsAutoStartRegistry();
  return copy;
}

bool SettingsStore::update(const AppSettings& next, std::string& outError) {
  AppSettings clean = next;
  clean.defaultView = (clean.defaultView == "global") ? "global" : "local";

  if (!syncWindowsAutoStartRegistry(clean.autoStart, clean.minimizeToTray, outError)) {
    return false;
  }

  {
    std::lock_guard lock(mutex_);
    settings_ = clean;
    save();
  }
  return true;
}

std::string SettingsStore::toJson() const {
  AppSettings s = get();
  std::string out = "{\"alertsEnabled\":";
  out += (s.alertsEnabled ? "true" : "false");
  out += ",\"notifyServiceDown\":";
  out += (s.notifyServiceDown ? "true" : "false");
  out += ",\"notifyServiceDegraded\":";
  out += (s.notifyServiceDegraded ? "true" : "false");
  out += ",\"notifySensitivePort\":";
  out += (s.notifySensitivePort ? "true" : "false");
  out += ",\"notifyNewCountry\":";
  out += (s.notifyNewCountry ? "true" : "false");
  out += ",\"autoStart\":";
  out += (s.autoStart ? "true" : "false");
  out += ",\"defaultView\":";
  appendJsonEscaped(out, s.defaultView);
  out += ",\"minimizeToTray\":";
  out += (s.minimizeToTray ? "true" : "false");
  out.push_back('}');
  return out;
}

} // namespace netpulse
