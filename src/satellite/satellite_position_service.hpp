#pragma once

#include "satellite_manager.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace netpulse::satellite {

class SatellitePositionService {
public:
  using BroadcastCallback = std::function<void(const std::string& jsonPayload)>;

  explicit SatellitePositionService(SatelliteManager& manager);
  ~SatellitePositionService();

  SatellitePositionService(const SatellitePositionService&) = delete;
  SatellitePositionService& operator=(const SatellitePositionService&) = delete;

  void start();
  void stop();

  void setBroadcastCallback(BroadcastCallback cb);

  // Wakes worker immediately after config changes (enable/disable, selection, cadence, track horizon).
  void notifyConfigChanged();

  // Triggers an asynchronous catalog refresh (non-blocking).
  void requestCatalogRefreshAsync(bool force = false);

  // Synchronous recompute + cache update (used by API mutations & unit tests).
  void recomputeNow(bool includeTracks = true);

  std::string getSnapshotJson() const;
  bool isSuspended() const { return suspended_.load(); }
  uint64_t computationCount() const { return computationCount_.load(); }

private:
  void workerLoop(std::stop_token st);
  void catalogLoop(std::stop_token st);

  SatelliteManager& manager_;
  BroadcastCallback onBroadcast_;

  mutable std::mutex stateMutex_;
  std::string latestJson_;
  std::unordered_map<int, SatelliteTrack> cachedTracks_;
  uint64_t lastTrackComputeMs_ = 0;

  std::mutex wakeMutex_;
  std::condition_variable_any wakeCv_;
  std::mutex catWakeMutex_;
  std::condition_variable_any catWakeCv_;

  std::atomic<bool> running_{false};
  std::atomic<bool> suspended_{true};
  std::atomic<bool> trackDirty_{true};
  std::atomic<bool> catalogRefreshPending_{false};
  std::atomic<bool> catalogForcePending_{false};
  std::atomic<uint64_t> computationCount_{0};

  std::jthread workerThread_;
  std::jthread catalogThread_;
};

} // namespace netpulse::satellite
