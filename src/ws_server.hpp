#pragma once

#include "security/auth_manager.hpp"
#include "security/tls_context.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace netpulse {

// RFC 6455 helper utilities (exposed for unit testing).
std::string computeWebSocketAcceptKey(const std::string& clientKey);
std::vector<uint8_t> encodeWebSocketFrame(uint8_t opcode, const std::string& payload);
bool isSafeRelativeSubpath(const std::string& rel);
std::string urlDecode(const std::string& in);

struct HttpRequest {
  std::string method;
  std::string path;
  std::string query;
  std::string body;
  std::string remoteIp;
  bool isTls = false;
  std::unordered_map<std::string, std::string> headers; // lowercase keys

  std::string header(const std::string& lowerName) const;
  std::string queryParam(const std::string& key) const;
};

struct HttpResponse {
  int statusCode = 200;
  std::string contentType = "application/json; charset=utf-8";
  std::string body;
  std::vector<std::pair<std::string, std::string>> extraHeaders;
};

struct WsAuthDecision {
  bool allowed = false;
  int httpStatus = 401;
  std::string errorBody = "{\"error\":\"unauthorized\"}";
  AuthContext auth;
};

class WsServer {
public:
  using CommandCallback = std::function<void(const std::string& cmd, const AuthContext& auth, const std::string& remoteIp)>;
  using HealthCallback = std::function<std::string()>;
  using ApiCallback = std::function<HttpResponse(const HttpRequest& req)>;
  using WsAuthCallback = std::function<WsAuthDecision(const HttpRequest& req)>;
  using RateLimitCallback = std::function<std::pair<bool, uint32_t>(const std::string& remoteIp)>;

  WsServer(uint16_t port,
           std::filesystem::path staticDir,
           std::filesystem::path assetsDir,
           std::string bindHost = "127.0.0.1");
  ~WsServer();

  WsServer(const WsServer&) = delete;
  WsServer& operator=(const WsServer&) = delete;

  void setTlsContext(const TlsContext* tls) { tlsCtx_ = tls; }
  void setTrustProxyTls(bool trust) { trustProxyTls_ = trust; }
  void setAllowedHosts(std::vector<std::string> hosts);
  void setMaxConnections(size_t maxConns) { maxConnections_ = maxConns; }
  void setMaxWsClients(size_t maxWs) { maxWsClients_ = maxWs; }

  bool start();
  void stop();

  uint16_t port() const { return boundPort_; }
  const std::string& bindHost() const { return bindHost_; }
  bool isTlsEnabled() const { return tlsCtx_ != nullptr && tlsCtx_->isReady(); }
  size_t clientCount() const;

  void setLatestSnapshotJson(std::string json);
  void broadcastText(const std::string& text);
  void disconnectAllWebSockets();
  void setCommandCallback(CommandCallback cb);
  void setHealthCallback(HealthCallback cb);
  void setApiCallback(ApiCallback cb);
  void setWsAuthCallback(WsAuthCallback cb);
  void setRateLimitCallback(RateLimitCallback cb);

  bool isHostAllowed(const std::string& hostHeader) const;
  bool isOriginAllowed(const std::string& originHeader, const std::string& hostHeader, bool reqTls) const;

private:
  struct ClientConn;
  struct Transport;

  void acceptLoop(std::stop_token stopToken);
  void handleHttpOrWs(uintptr_t rawSock, std::string remoteIp);
  void handleWebSocketClient(std::shared_ptr<ClientConn> client);
  bool sendFileResponse(Transport& io,
                        const std::filesystem::path& filePath,
                        const std::filesystem::path& allowedRoot,
                        const char* mimeType,
                        const char* cacheControl,
                        bool isHtml);
  void sendResponse(Transport& io, const HttpResponse& resp);
  void sendSimpleResponse(Transport& io,
                          int statusCode,
                          const char* contentType,
                          const std::string& body);

  uint16_t requestedPort_ = 8740;
  uint16_t boundPort_ = 0;
  std::string bindHost_ = "127.0.0.1";
  std::filesystem::path staticDir_;
  std::filesystem::path assetsDir_;
  std::filesystem::path canonicalStaticDir_;
  std::filesystem::path canonicalAssetsDir_;

  const TlsContext* tlsCtx_ = nullptr;
  bool trustProxyTls_ = false;
  std::vector<std::string> allowedHosts_;
  size_t maxConnections_ = 64;
  size_t maxWsClients_ = 16;

  uintptr_t listenSock_ = ~static_cast<uintptr_t>(0);
  std::atomic<bool> running_{false};
  std::jthread acceptThread_;

  mutable std::mutex clientsMutex_;
  std::vector<std::shared_ptr<ClientConn>> clients_;
  std::atomic<size_t> activeHandlers_{0};
  std::mutex shutdownMutex_;
  std::condition_variable shutdownCv_;

  mutable std::mutex snapshotMutex_;
  std::string latestSnapshotJson_;

  CommandCallback onCommand_;
  HealthCallback onHealth_;
  ApiCallback onApi_;
  WsAuthCallback onWsAuth_;
  RateLimitCallback onRateLimit_;
};

} // namespace netpulse
