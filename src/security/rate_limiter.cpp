#include "rate_limiter.hpp"

#include <algorithm>
#include <chrono>

namespace netpulse {

RateLimiter::RateLimiter(uint32_t maxRequests, uint64_t windowMs, uint64_t blockDurationMs)
    : maxRequests_(std::max<uint32_t>(1, maxRequests)),
      windowMs_(std::max<uint64_t>(100, windowMs)),
      blockDurationMs_(blockDurationMs) {}

uint64_t RateLimiter::currentMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void RateLimiter::pruneLocked(uint64_t nowMs) {
  if (buckets_.size() < 1024) return;
  for (auto it = buckets_.begin(); it != buckets_.end();) {
    if (nowMs > it->second.lastSeenMs &&
        (nowMs - it->second.lastSeenMs) > std::max(windowMs_ * 4, blockDurationMs_ * 2)) {
      it = buckets_.erase(it);
    } else {
      ++it;
    }
  }
}

RateLimiter::Decision RateLimiter::check(const std::string& key, uint64_t nowMs) {
  if (nowMs == 0) nowMs = currentMs();
  std::lock_guard lock(mutex_);
  pruneLocked(nowMs);

  auto& b = buckets_[key];
  b.lastSeenMs = nowMs;

  if (b.blockedUntilMs > nowMs) {
    uint64_t remMs = b.blockedUntilMs - nowMs;
    return {false, static_cast<uint32_t>((remMs + 999) / 1000)};
  }

  if (b.windowStartMs == 0 || (nowMs - b.windowStartMs) >= windowMs_) {
    b.windowStartMs = nowMs;
    b.count = 0;
  }

  if (b.count >= maxRequests_) {
    if (blockDurationMs_ > 0) {
      b.blockedUntilMs = nowMs + blockDurationMs_;
      return {false, static_cast<uint32_t>((blockDurationMs_ + 999) / 1000)};
    }
    uint64_t remMs = windowMs_ - (nowMs - b.windowStartMs);
    return {false, static_cast<uint32_t>(std::max<uint64_t>(1, (remMs + 999) / 1000))};
  }

  ++b.count;
  return {true, 0};
}

void RateLimiter::recordFailure(const std::string& key, uint64_t nowMs) {
  (void)check(key, nowMs);
}

void RateLimiter::reset(const std::string& key) {
  std::lock_guard lock(mutex_);
  buckets_.erase(key);
}

} // namespace netpulse
