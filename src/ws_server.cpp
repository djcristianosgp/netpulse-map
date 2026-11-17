#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include "ws_server.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr const char* kWsMagicGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

std::string toLowerAscii(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string trimAscii(const std::string& s) {
  size_t b = 0;
  while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
  size_t e = s.size();
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
  return s.substr(b, e - b);
}

bool sendAll(SOCKET s, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    int chunk = static_cast<int>(std::min<size_t>(len - sent, 65536));
    int n = send(s, data + sent, chunk, 0);
    if (n <= 0) return false;
    sent += static_cast<size_t>(n);
  }
  return true;
}

bool recvExact(SOCKET s, uint8_t* buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    int n = recv(s, reinterpret_cast<char*>(buf + got), static_cast<int>(len - got), 0);
    if (n <= 0) return false;
    got += static_cast<size_t>(n);
  }
  return true;
}

const char* mimeFromExtension(const std::filesystem::path& p) {
  std::string ext = toLowerAscii(p.extension().string());
  if (ext == ".html") return "text/html; charset=utf-8";
  if (ext == ".css") return "text/css; charset=utf-8";
  if (ext == ".js") return "application/javascript; charset=utf-8";
  if (ext == ".json") return "application/json; charset=utf-8";
  if (ext == ".svg") return "image/svg+xml";
  if (ext == ".png") return "image/png";
  return "application/octet-stream";
}

bool isSafeRelativeSubpath(const std::string& rel) {
  if (rel.empty()) return false;
  if (rel.find("..") != std::string::npos) return false;
  if (rel.find('\\') != std::string::npos) return false;
  if (rel.find(':') != std::string::npos) return false;
  return true;
}

} // namespace

struct WsServer::ClientConn {
  SOCKET sock = INVALID_SOCKET;
  std::mutex sendMutex;
  std::atomic<bool> alive{true};

  bool sendFrame(uint8_t opcode, const std::string& payload) {
    if (!alive.load()) return false;
    auto frame = encodeWebSocketFrame(opcode, payload);
    std::lock_guard lock(sendMutex);
    if (!alive.load()) return false;
    bool ok = sendAll(sock, reinterpret_cast<const char*>(frame.data()), frame.size());
    if (!ok) alive.store(false);
    return ok;
  }

  void close() {
    if (alive.exchange(false)) {
      shutdown(sock, SD_BOTH);
      closesocket(sock);
    }
  }
};

std::string computeWebSocketAcceptKey(const std::string& clientKey) {
  const std::string combined = trimAscii(clientKey) + kWsMagicGuid;

  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;
  uint8_t sha1Digest[20] = {};

  if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0) {
    return {};
  }
  bool ok = false;
  if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
    if (BCryptHashData(hHash,
                       reinterpret_cast<PUCHAR>(const_cast<char*>(combined.data())),
                       static_cast<ULONG>(combined.size()),
                       0) == 0) {
      ok = (BCryptFinishHash(hHash, sha1Digest, sizeof(sha1Digest), 0) == 0);
    }
    BCryptDestroyHash(hHash);
  }
  BCryptCloseAlgorithmProvider(hAlg, 0);
  if (!ok) return {};

  DWORD b64Len = 0;
  if (!CryptBinaryToStringA(sha1Digest, sizeof(sha1Digest),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            nullptr, &b64Len)) {
    return {};
  }
  std::string out(b64Len, '\0');
  if (!CryptBinaryToStringA(sha1Digest, sizeof(sha1Digest),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            out.data(), &b64Len)) {
    return {};
  }
  if (!out.empty() && out.back() == '\0') out.pop_back();
  return out;
}

std::vector<uint8_t> encodeWebSocketFrame(uint8_t opcode, const std::string& payload) {
  std::vector<uint8_t> frame;
  const uint64_t len = payload.size();
  frame.reserve(10 + len);

  frame.push_back(static_cast<uint8_t>(0x80 | (opcode & 0x0F)));
  if (len <= 125) {
    frame.push_back(static_cast<uint8_t>(len));
  } else if (len <= 65535) {
    frame.push_back(126);
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
  } else {
    frame.push_back(127);
    for (int shift = 56; shift >= 0; shift -= 8) {
      frame.push_back(static_cast<uint8_t>((len >> shift) & 0xFF));
    }
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

WsServer::WsServer(uint16_t port,
                   std::filesystem::path staticDir,
                   std::filesystem::path assetsDir)
    : requestedPort_(port),
      staticDir_(std::move(staticDir)),
      assetsDir_(std::move(assetsDir)) {}

WsServer::~WsServer() {
  stop();
}

bool WsServer::start() {
  if (running_.exchange(true)) return true;

  SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ls == INVALID_SOCKET) {
    running_.store(false);
    return false;
  }

  BOOL opt = TRUE;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(requestedPort_);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

  if (bind(ls, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
    closesocket(ls);
    running_.store(false);
    return false;
  }

  sockaddr_in boundAddr{};
  int boundLen = sizeof(boundAddr);
  if (getsockname(ls, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen) == 0) {
    boundPort_ = ntohs(boundAddr.sin_port);
  } else {
    boundPort_ = requestedPort_;
  }

  if (listen(ls, SOMAXCONN) == SOCKET_ERROR) {
    closesocket(ls);
    running_.store(false);
    return false;
  }

  listenSock_ = static_cast<uintptr_t>(ls);
  acceptThread_ = std::jthread([this](std::stop_token st) { acceptLoop(st); });
  return true;
}

void WsServer::stop() {
  if (!running_.exchange(false)) return;

  SOCKET ls = static_cast<SOCKET>(listenSock_);
  if (ls != INVALID_SOCKET) {
    listenSock_ = static_cast<uintptr_t>(INVALID_SOCKET);
    closesocket(ls);
  }

  if (acceptThread_.joinable()) {
    acceptThread_.request_stop();
    acceptThread_.join();
  }

  std::vector<std::shared_ptr<ClientConn>> copyClients;
  {
    std::lock_guard lock(clientsMutex_);
    copyClients = clients_;
    clients_.clear();
  }
  for (auto& c : copyClients) {
    c->close();
  }

  std::unique_lock sLock(shutdownMutex_);
  shutdownCv_.wait_for(sLock, std::chrono::seconds(2), [this]() {
    return activeHandlers_.load() == 0;
  });
}

size_t WsServer::clientCount() const {
  std::lock_guard lock(clientsMutex_);
  return clients_.size();
}

void WsServer::setLatestSnapshotJson(std::string json) {
  std::lock_guard lock(snapshotMutex_);
  latestSnapshotJson_ = std::move(json);
}

void WsServer::setCommandCallback(CommandCallback cb) {
  onCommand_ = std::move(cb);
}

void WsServer::setHealthCallback(HealthCallback cb) {
  onHealth_ = std::move(cb);
}

void WsServer::broadcastText(const std::string& text) {
  std::vector<std::shared_ptr<ClientConn>> snapshot;
  {
    std::lock_guard lock(clientsMutex_);
    if (clients_.empty()) return;
    snapshot = clients_;
  }

  bool anyDead = false;
  for (auto& c : snapshot) {
    if (!c->sendFrame(0x1, text)) {
      anyDead = true;
    }
  }

  if (anyDead) {
    std::lock_guard lock(clientsMutex_);
    clients_.erase(
        std::remove_if(clients_.begin(), clients_.end(),
                       [](const std::shared_ptr<ClientConn>& c) { return !c->alive.load(); }),
        clients_.end());
  }
}

void WsServer::acceptLoop(std::stop_token stopToken) {
  SOCKET ls = static_cast<SOCKET>(listenSock_);
  while (!stopToken.stop_requested() && running_.load()) {
    SOCKET cs = accept(ls, nullptr, nullptr);
    if (cs == INVALID_SOCKET) break;

    BOOL nodelay = TRUE;
    setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    activeHandlers_.fetch_add(1);
    std::thread([this, sock = static_cast<uintptr_t>(cs)]() {
      handleHttpOrWs(sock);
      if (activeHandlers_.fetch_sub(1) == 1) {
        std::lock_guard lk(shutdownMutex_);
        shutdownCv_.notify_all();
      }
    }).detach();
  }
}

void WsServer::sendSimpleResponse(uintptr_t rawSock,
                                  const char* status,
                                  const char* contentType,
                                  const std::string& body) {
  SOCKET s = static_cast<SOCKET>(rawSock);
  std::ostringstream oss;
  oss << "HTTP/1.1 " << status << "\r\n"
      << "Content-Type: " << contentType << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n"
      << "Access-Control-Allow-Origin: *\r\n\r\n"
      << body;
  std::string msg = oss.str();
  sendAll(s, msg.data(), msg.size());
  closesocket(s);
}

bool WsServer::sendFileResponse(uintptr_t rawSock,
                                const std::filesystem::path& filePath,
                                const char* mimeType,
                                const char* cacheControl) {
  SOCKET s = static_cast<SOCKET>(rawSock);
  std::ifstream in(filePath, std::ios::binary | std::ios::ate);
  if (!in.is_open()) return false;

  const auto size = in.tellg();
  in.seekg(0, std::ios::beg);
  std::string body(static_cast<size_t>(size), '\0');
  if (size > 0) {
    in.read(body.data(), size);
  }

  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n"
      << "Content-Type: " << mimeType << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Cache-Control: " << cacheControl << "\r\n"
      << "Connection: close\r\n\r\n";
  std::string hdr = oss.str();
  sendAll(s, hdr.data(), hdr.size());
  if (!body.empty()) {
    sendAll(s, body.data(), body.size());
  }
  closesocket(s);
  return true;
}

void WsServer::handleHttpOrWs(uintptr_t rawSock) {
  SOCKET s = static_cast<SOCKET>(rawSock);

  DWORD timeoutMs = 5000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

  std::string req;
  req.reserve(2048);
  char buf[2048];
  size_t hdrEnd = std::string::npos;

  while (req.size() < 16384) {
    int n = recv(s, buf, sizeof(buf), 0);
    if (n <= 0) {
      closesocket(s);
      return;
    }
    req.append(buf, static_cast<size_t>(n));
    hdrEnd = req.find("\r\n\r\n");
    if (hdrEnd != std::string::npos) break;
  }

  if (hdrEnd == std::string::npos) {
    sendSimpleResponse(rawSock, "400 Bad Request", "text/plain", "Bad Request");
    return;
  }

  std::istringstream iss(req.substr(0, hdrEnd));
  std::string method, target, version;
  iss >> method >> target >> version;

  // Strip query string if present.
  size_t qPos = target.find('?');
  std::string path = (qPos == std::string::npos) ? target : target.substr(0, qPos);

  std::string upgradeHeader;
  std::string wsKey;
  std::string line;
  std::getline(iss, line); // consume remainder of request line
  while (std::getline(iss, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string k = toLowerAscii(trimAscii(line.substr(0, colon)));
    std::string v = trimAscii(line.substr(colon + 1));
    if (k == "upgrade") upgradeHeader = toLowerAscii(v);
    if (k == "sec-websocket-key") wsKey = v;
  }

  if (upgradeHeader == "websocket" && !wsKey.empty()) {
    std::string acceptKey = computeWebSocketAcceptKey(wsKey);
    std::ostringstream oss;
    oss << "HTTP/1.1 101 Switching Protocols\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";
    std::string resp = oss.str();
    if (!sendAll(s, resp.data(), resp.size())) {
      closesocket(s);
      return;
    }

    // Clear receive timeout for long-lived WebSocket connection.
    DWORD noTimeout = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&noTimeout), sizeof(noTimeout));

    auto client = std::make_shared<ClientConn>();
    client->sock = s;
    {
      std::lock_guard lock(clientsMutex_);
      clients_.push_back(client);
    }

    // Push latest snapshot immediately so UI renders without delay.
    std::string initial;
    {
      std::lock_guard lock(snapshotMutex_);
      initial = latestSnapshotJson_;
    }
    if (!initial.empty()) {
      client->sendFrame(0x1, initial);
    }

    handleWebSocketClient(std::move(client));
    return;
  }

  if (method != "GET") {
    sendSimpleResponse(rawSock, "405 Method Not Allowed", "text/plain", "Method Not Allowed");
    return;
  }

  if (path == "/api/health") {
    std::string body = onHealth_ ? onHealth_() : "{\"status\":\"ok\"}";
    sendSimpleResponse(rawSock, "200 OK", "application/json; charset=utf-8", body);
    return;
  }

  if (path == "/api/snapshot") {
    std::string snap;
    {
      std::lock_guard lock(snapshotMutex_);
      snap = latestSnapshotJson_;
    }
    if (snap.empty()) snap = "{\"connections\":[]}";
    sendSimpleResponse(rawSock, "200 OK", "application/json; charset=utf-8", snap);
    return;
  }

  if (path == "/") path = "/index.html";

  if (path.rfind("/assets/", 0) == 0) {
    std::string rel = path.substr(8);
    if (!isSafeRelativeSubpath(rel)) {
      sendSimpleResponse(rawSock, "403 Forbidden", "text/plain", "Forbidden");
      return;
    }
    std::filesystem::path full = assetsDir_ / rel;
    if (!sendFileResponse(rawSock, full, mimeFromExtension(full), "public, max-age=86400")) {
      sendSimpleResponse(rawSock, "404 Not Found", "text/plain", "Not Found");
    }
    return;
  }

  std::string rel = (path.front() == '/') ? path.substr(1) : path;
  if (!isSafeRelativeSubpath(rel)) {
    sendSimpleResponse(rawSock, "403 Forbidden", "text/plain", "Forbidden");
    return;
  }
  std::filesystem::path full = staticDir_ / rel;
  if (!sendFileResponse(rawSock, full, mimeFromExtension(full), "no-cache")) {
    sendSimpleResponse(rawSock, "404 Not Found", "text/plain", "Not Found");
  }
}

void WsServer::handleWebSocketClient(std::shared_ptr<ClientConn> client) {
  while (running_.load() && client->alive.load()) {
    uint8_t hdr[2];
    if (!recvExact(client->sock, hdr, 2)) break;

    uint8_t opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t payloadLen = hdr[1] & 0x7F;

    if (payloadLen == 126) {
      uint8_t ext[2];
      if (!recvExact(client->sock, ext, 2)) break;
      payloadLen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
    } else if (payloadLen == 127) {
      uint8_t ext[8];
      if (!recvExact(client->sock, ext, 8)) break;
      payloadLen = 0;
      for (int i = 0; i < 8; ++i) {
        payloadLen = (payloadLen << 8) | ext[i];
      }
    }

    if (payloadLen > 1024 * 1024) break; // guard against malformed oversized frames

    uint8_t maskKey[4] = {};
    if (masked && !recvExact(client->sock, maskKey, 4)) break;

    std::string payload(static_cast<size_t>(payloadLen), '\0');
    if (payloadLen > 0) {
      if (!recvExact(client->sock, reinterpret_cast<uint8_t*>(payload.data()), static_cast<size_t>(payloadLen))) {
        break;
      }
      if (masked) {
        for (size_t i = 0; i < payload.size(); ++i) {
          payload[i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ maskKey[i % 4]);
        }
      }
    }

    if (opcode == 0x8) {
      client->sendFrame(0x8, "");
      break;
    } else if (opcode == 0x9) {
      client->sendFrame(0xA, payload);
    } else if (opcode == 0x1) {
      if (onCommand_) onCommand_(payload);
    }
  }

  client->close();
  std::lock_guard lock(clientsMutex_);
  clients_.erase(
      std::remove_if(clients_.begin(), clients_.end(),
                     [&](const std::shared_ptr<ClientConn>& c) { return c.get() == client.get() || !c->alive.load(); }),
      clients_.end());
}

} // namespace netpulse
