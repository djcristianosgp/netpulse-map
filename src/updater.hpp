#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace netpulse {

struct SemVer {
  int major = 0;
  int minor = 0;
  int patch = 0;
  std::string prerelease;
  bool valid = false;
};

struct ReleaseInfo {
  bool valid = false;
  std::string tagName;
  std::string version;
  std::string htmlUrl;
  std::string installerUrl;
  uint64_t installerSize = 0;
  std::string checksumsUrl;
  std::string publishedAt;
};

enum class UpdateState : uint8_t {
  Idle = 0,
  Checking,
  UpToDate,
  Available,
  Downloading,
  Verifying,
  Installing,
  Error,
};

struct UpdateStatus {
  UpdateState state = UpdateState::Idle;
  std::string currentVersion;
  std::string latestVersion;
  std::string releaseUrl;
  std::string installerUrl;
  uint64_t installerSize = 0;
  int progressPct = 0;
  std::string error;
};

// Pure helpers (exposed for unit tests)
SemVer parseSemVer(const std::string& raw);
bool isNewerVersion(const std::string& current, const std::string& candidate);
ReleaseInfo parseGitHubReleaseJson(const std::string& json);
std::string parseSha256FromChecksums(const std::string& checksumsText, const std::string& fileName);
std::string computeFileSha256Hex(const std::filesystem::path& filePath);

class UpdateManager {
public:
  using ExitCallback = std::function<void()>;

  explicit UpdateManager(std::string currentVersion, ExitCallback onRequestExit);
  ~UpdateManager();

  UpdateManager(const UpdateManager&) = delete;
  UpdateManager& operator=(const UpdateManager&) = delete;

  void startAutoCheck();
  void stop();

  void checkNowAsync();
  bool startInstallAsync();

  UpdateStatus getStatus() const;
  std::string getStatusJson() const;

private:
  void runCheck();
  void runDownloadAndInstall();

  std::string currentVersion_;
  ExitCallback onRequestExit_;

  mutable std::mutex mutex_;
  UpdateStatus status_;
  ReleaseInfo latestRelease_;

  std::atomic<bool> running_{false};
  std::atomic<bool> busy_{false};
  std::jthread autoThread_;
  std::jthread workerThread_;
};

} // namespace netpulse
