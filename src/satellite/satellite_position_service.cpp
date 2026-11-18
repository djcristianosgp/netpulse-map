#include "satellite_position_service.hpp"

#include <chrono>

namespace netpulse::satellite {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

} // namespace

SatellitePositionService::SatellitePositionService(SatelliteManager& manager)
    : manager_(manager) {
  recomputeNow(true);
}

SatellitePositionService::~SatellitePositionService() {
  stop();
}

void SatellitePositionService::setBroadcastCallback(BroadcastCallback cb) {
  std::lock_guard lock(stateMutex_);
  onBroadcast_ = std::move(cb);
}

void SatellitePositionService::start() {
  if (running_.exchange(true)) return;
  manager_.catalog().loadCache();
  recomputeNow(true);

  catalogThread_ = std::jthread([this](std::stop_token st) { catalogLoop(st); });
  workerThread_ = std::jthread([this](std::stop_token st) { workerLoop(st); });
}

void SatellitePositionService::stop() {
  if (!running_.exchange(false)) return;
  workerThread_.request_stop();
  catalogThread_.request_stop();
  wakeCv_.notify_all();
  catWakeCv_.notify_all();
  if (workerThread_.joinable()) workerThread_.join();
  if (catalogThread_.joinable()) catalogThread_.join();
}

void SatellitePositionService::notifyConfigChanged() {
  trackDirty_.store(true);
  recomputeNow(true);
  wakeCv_.notify_all();
  catWakeCv_.notify_all();
}

void SatellitePositionService::requestCatalogRefreshAsync(bool force) {
  if (force) catalogForcePending_.store(true);
  catalogRefreshPending_.store(true);
  catWakeCv_.notify_all();
}

void SatellitePositionService::recomputeNow(bool includeTracks) {
  const uint64_t now = nowEpochMs();
  const auto cfg = manager_.config().get();
  const bool active = manager_.hasActiveTargets();
  suspended_.store(!active);

  const bool shouldBuildTracks = includeTracks || trackDirty_.load();
  auto objs = manager_.computeSnapshot(now, shouldBuildTracks);

  {
    std::lock_guard lock(stateMutex_);
    if (shouldBuildTracks) {
      for (const auto& o : objs) {
        if (cfg.enabled && o.enabled && cfg.showTrajectory) {
          cachedTracks_[o.spec.noradId] = o.track;
        } else {
          cachedTracks_.erase(o.spec.noradId);
        }
      }
      lastTrackComputeMs_ = now;
      trackDirty_.store(false);
    } else {
      for (auto& o : objs) {
        if (cfg.enabled && o.enabled && cfg.showTrajectory) {
          auto it = cachedTracks_.find(o.spec.noradId);
          if (it != cachedTracks_.end()) {
            o.track = it->second;
          }
        }
      }
    }
    latestJson_ = SatelliteManager::serializeSnapshotJson(cfg, objs, now);
  }
  if (active) {
    computationCount_.fetch_add(1);
  }
}

std::string SatellitePositionService::getSnapshotJson() const {
  std::lock_guard lock(stateMutex_);
  return latestJson_;
}

void SatellitePositionService::catalogLoop(std::stop_token st) {
  while (running_.load() && !st.stop_requested()) {
    const auto cfg = manager_.config().get();
    const uint64_t now = nowEpochMs();
    const bool manual = catalogRefreshPending_.exchange(false);
    const bool force = catalogForcePending_.exchange(false);

    if (manual || (cfg.enabled && manager_.catalog().shouldAutoRefresh(now, cfg.catalogRefreshSec))) {
      std::string err;
      manager_.catalog().refreshFromSource(now, force, err);
      trackDirty_.store(true);
      recomputeNow(true);

      BroadcastCallback cb;
      std::string payload;
      {
        std::lock_guard lock(stateMutex_);
        cb = onBroadcast_;
        payload = latestJson_;
      }
      if (cb && !payload.empty()) {
        cb(payload);
      }
    }

    std::unique_lock lk(catWakeMutex_);
    catWakeCv_.wait_for(lk, st, std::chrono::seconds(30), [this, &st]() {
      return !running_.load() || st.stop_requested() || catalogRefreshPending_.load();
    });
  }
}

void SatellitePositionService::workerLoop(std::stop_token st) {
  while (running_.load() && !st.stop_requested()) {
    const auto cfg = manager_.config().get();
    if (!manager_.hasActiveTargets()) {
      suspended_.store(true);
      std::unique_lock lk(wakeMutex_);
      wakeCv_.wait(lk, st, [this, &st]() {
        return !running_.load() || st.stop_requested() || manager_.hasActiveTargets();
      });
      continue;
    }

    suspended_.store(false);
    const uint64_t now = nowEpochMs();
    const bool needTrackRecompute = trackDirty_.load() || (now - lastTrackComputeMs_ >= 15000ULL);
    recomputeNow(needTrackRecompute);

    BroadcastCallback cb;
    std::string payload;
    {
      std::lock_guard lock(stateMutex_);
      cb = onBroadcast_;
      payload = latestJson_;
    }
    if (cb && !payload.empty()) {
      cb(payload);
    }

    const int intervalMs = std::max(500, cfg.positionIntervalMs);
    std::unique_lock lk(wakeMutex_);
    wakeCv_.wait_for(lk, st, std::chrono::milliseconds(intervalMs), [this, &st]() {
      return !running_.load() || st.stop_requested() || trackDirty_.load();
    });
  }
}

} // namespace netpulse::satellite
