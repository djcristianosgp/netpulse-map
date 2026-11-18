#pragma once

#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>

namespace netpulse {

struct AppSettings {
  bool alertsEnabled = true;
  bool notifyServiceDown = true;
  bool notifyServiceDegraded = true;
  bool notifySensitivePort = true;
  bool notifyNewCountry = true;
  bool autoStart = false;
  std::string defaultView = "local"; // "local" | "global"
  bool minimizeToTray = true;
  int retentionDays = 30;            // 1, 7, 30, 90, or custom 1..365
  int maxDbSizeMb = 256;             // 32..2048 MB
};

class SettingsStore {
public:
  explicit SettingsStore(std::filesystem::path settingsPath);

  AppSettings get() const;
  bool update(const AppSettings& next, std::string& outError);
  std::string toJson() const;

  // Exposed for testing TSV parsing/serialization
  static bool parseLine(const std::string& line, std::string& key, std::string& val);
  static bool syncWindowsAutoStartRegistry(bool enabled, bool startMinimized, std::string& outError);
  static bool queryWindowsAutoStartRegistry();

private:
  void load();
  void save();

  std::filesystem::path path_;
  mutable std::mutex mutex_;
  AppSettings settings_;
};

} // namespace netpulse
