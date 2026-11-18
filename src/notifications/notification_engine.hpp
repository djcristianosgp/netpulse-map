#pragma once

#include "../history_store.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace netpulse {

struct NotificationEvent {
  uint64_t tsMs = 0;
  std::string kind;      // "service_down" | "route_changed" | "wan_failover" | "security_alert" | "test" | ...
  std::string severity;  // "info" | "low" | "warn" | "high" | "critical"
  std::string title;
  std::string detail;
  std::string source = "netpulse";
};

// Pure deterministic helpers exposed for unit testing
std::string hmacSha256Hex(const std::string& key, const std::string& message);
int notificationSeverityRank(const std::string& sev);
bool validateNotificationTargetUrl(const std::string& kind,
                                   const std::string& endpointUrl,
                                   const std::string& secretOrToken,
                                   const std::string& chatId,
                                   std::string& outEffectiveUrl,
                                   std::string& outError);
bool shouldDispatchToChannel(const NotificationChannelRecord& ch,
                             const NotificationEvent& ev,
                             uint64_t lastChannelSentMs,
                             uint64_t nowMs);
std::string buildNotificationPayloadJson(const NotificationChannelRecord& ch,
                                         const NotificationEvent& ev);

class NotificationEngine {
public:
  explicit NotificationEngine(HistoryStore& history);
  ~NotificationEngine();

  NotificationEngine(const NotificationEngine&) = delete;
  NotificationEngine& operator=(const NotificationEngine&) = delete;

  void start();
  void stop();

  void notify(const NotificationEvent& ev);
  bool sendTestNotification(const std::string& channelId, std::string& outError);

  bool upsertChannel(const NotificationChannelRecord& incoming,
                     NotificationChannelRecord& outSaved,
                     std::string& outError);
  bool deleteChannel(const std::string& id);

  std::string getChannelsJson() const;
  std::string getDeliveriesJson(size_t limit = 80) const;

  uint64_t sentOkCount() const { return sentOk_.load(); }
  uint64_t sentErrorCount() const { return sentErr_.load(); }

private:
  void workerLoop(std::stop_token st);
  bool deliverSingle(const NotificationChannelRecord& ch,
                     const NotificationEvent& ev,
                     int& outHttpStatus,
                     std::string& outError);

  HistoryStore& history_;
  mutable std::mutex mutex_;
  std::vector<NotificationChannelRecord> channels_;
  std::unordered_map<std::string, uint64_t> lastSentByChannel_;

  std::mutex queueMutex_;
  std::condition_variable_any queueCv_;
  std::deque<NotificationEvent> queue_;
  std::atomic<bool> running_{false};
  std::jthread worker_;

  std::atomic<uint64_t> sentOk_{0};
  std::atomic<uint64_t> sentErr_{0};
};

} // namespace netpulse
