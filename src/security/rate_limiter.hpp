#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace netpulse {

class RateLimiter {
public:
  struct Decision {
    bool allowed = true;
    uint32_t retryAfterSec = 0;
  };

  RateLimiter(uint32_t maxRequests, uint64_t windowMs, uint64_t blockDurationMs = 0);

  Decision check(const std::string& key, uint64_t nowMs = 0);
  void recordFailure(const std::string& key, uint64_t nowMs = 0);
  void reset(const std::string& key);

private:
  struct Bucket {
    uint64_t windowStartMs = 0;
    uint32_t count = 0;
    uint64_t blockedUntilMs = 0;
    uint64_t lastSeenMs = 0;
  };

  static uint64_t currentMs();
  void pruneLocked(uint64_t nowMs);

  uint32_t maxRequests_;
  uint64_t windowMs_;
  uint64_t blockDurationMs_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, Bucket> buckets_;
};

} // namespace netpulse
