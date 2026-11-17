#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netpulse {

// RFC 6455 helper utilities (exposed for unit testing).
std::string computeWebSocketAcceptKey(const std::string& clientKey);
std::vector<uint8_t> encodeWebSocketFrame(uint8_t opcode, const std::string& payload);

class WsServer {
public:
  using CommandCallback = std::function<void(const std::string&)>;
  using HealthCallback = std::function<std::string()>;

  WsServer(uint16_t port,
           std::filesystem::path staticDir,
           std::filesystem::path assetsDir);
  ~WsServer();

  WsServer(const WsServer&) = delete;
  WsServer& operator=(const WsServer&) = delete;

  bool start();
  void stop();

  uint16_t port() const { return boundPort_; }
  size_t clientCount() const;

  void setLatestSnapshotJson(std::string json);
  void broadcastText(const std::string& text);
  void setCommandCallback(CommandCallback cb);
  void setHealthCallback(HealthCallback cb);

private:
  struct ClientConn;

  void acceptLoop(std::stop_token stopToken);
  void handleHttpOrWs(uintptr_t rawSock);
  void handleWebSocketClient(std::shared_ptr<ClientConn> client);
  bool sendFileResponse(uintptr_t sock, const std::filesystem::path& filePath, const char* mimeType, const char* cacheControl);
  void sendSimpleResponse(uintptr_t sock, const char* status, const char* contentType, const std::string& body);

  uint16_t requestedPort_ = 8740;
  uint16_t boundPort_ = 0;
  std::filesystem::path staticDir_;
  std::filesystem::path assetsDir_;

  uintptr_t listenSock_ = ~static_cast<uintptr_t>(0);
  std::atomic<bool> running_{false};
  std::jthread acceptThread_;

  mutable std::mutex clientsMutex_;
  std::vector<std::shared_ptr<ClientConn>> clients_;
  std::atomic<int> activeHandlers_{0};
  std::mutex shutdownMutex_;
  std::condition_variable shutdownCv_;

  mutable std::mutex snapshotMutex_;
  std::string latestSnapshotJson_;

  CommandCallback onCommand_;
  HealthCallback onHealth_;
};

} // namespace netpulse
