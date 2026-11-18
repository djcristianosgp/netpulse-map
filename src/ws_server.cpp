#ifdef _WIN32
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
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(int s) { return ::close(s); }
#ifndef SD_BOTH
#define SD_BOTH SHUT_RDWR
#endif
#endif

#include "ws_server.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr const char* kWsMagicGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr size_t kMaxHttpHeaderBytes = 16384;
constexpr size_t kMaxHttpBodyBytes = 65536;

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

const char* httpStatusText(int code) {
  switch (code) {
    case 200: return "200 OK";
    case 201: return "201 Created";
    case 202: return "202 Accepted";
    case 204: return "204 No Content";
    case 400: return "400 Bad Request";
    case 401: return "401 Unauthorized";
    case 403: return "403 Forbidden";
    case 404: return "404 Not Found";
    case 405: return "405 Method Not Allowed";
    case 409: return "409 Conflict";
    case 413: return "413 Payload Too Large";
    case 429: return "429 Too Many Requests";
    case 503: return "503 Service Unavailable";
    default: return "500 Internal Server Error";
  }
}

void setRecvTimeoutMs(SOCKET s, uint32_t ms) {
#ifdef _WIN32
  DWORD timeoutMs = ms;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
#else
  timeval tv{};
  tv.tv_sec = static_cast<time_t>(ms / 1000);
  tv.tv_usec = static_cast<suseconds_t>((ms % 1000) * 1000);
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

const char* mimeFromExtension(const std::filesystem::path& p) {
  std::string ext = toLowerAscii(p.extension().string());
  if (ext == ".html") return "text/html; charset=utf-8";
  if (ext == ".css") return "text/css; charset=utf-8";
  if (ext == ".js") return "application/javascript; charset=utf-8";
  if (ext == ".json") return "application/json; charset=utf-8";
  if (ext == ".svg") return "image/svg+xml";
  if (ext == ".png") return "image/png";
  if (ext == ".ico") return "image/x-icon";
  return "application/octet-stream";
}

std::string stripPortFromAuthority(const std::string& auth) {
  std::string low = toLowerAscii(trimAscii(auth));
  if (low.empty()) return {};
  if (low.front() == '[') {
    size_t rb = low.find(']');
    if (rb == std::string::npos) return {};
    return low.substr(0, rb + 1);
  }
  size_t colon = low.rfind(':');
  if (colon != std::string::npos) {
    return low.substr(0, colon);
  }
  return low;
}

bool isLoopbackHostName(const std::string& hostOnly) {
  return hostOnly == "localhost" || hostOnly == "127.0.0.1" || hostOnly == "[::1]" || hostOnly == "::1";
}

std::string extractRemoteIp(const sockaddr_storage& ss) {
  char buf[INET6_ADDRSTRLEN] = {};
  if (ss.ss_family == AF_INET) {
    const auto* s4 = reinterpret_cast<const sockaddr_in*>(&ss);
    if (inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf))) return std::string(buf);
  } else if (ss.ss_family == AF_INET6) {
    const auto* s6 = reinterpret_cast<const sockaddr_in6*>(&ss);
    if (inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf))) return std::string(buf);
  }
  return "unknown";
}

} // namespace

std::string urlDecode(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%' && i + 2 < in.size()) {
      auto hexVal = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
      };
      int hi = hexVal(in[i + 1]);
      int lo = hexVal(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(in[i]);
  }
  return out;
}

bool isSafeRelativeSubpath(const std::string& rel) {
  if (rel.empty()) return false;
  std::string decoded = urlDecode(rel);
  if (decoded.empty()) return false;
  for (unsigned char c : decoded) {
    if (c == '\0' || c < 0x20) return false;
  }
  if (decoded.find("..") != std::string::npos) return false;
  if (decoded.find('\\') != std::string::npos) return false;
  if (decoded.find(':') != std::string::npos) return false;
  if (decoded.front() == '/') return false;
  return true;
}

std::string HttpRequest::header(const std::string& lowerName) const {
  auto it = headers.find(lowerName);
  return (it != headers.end()) ? it->second : std::string{};
}

std::string HttpRequest::queryParam(const std::string& key) const {
  if (query.empty()) return {};
  std::istringstream ss(query);
  std::string part;
  while (std::getline(ss, part, '&')) {
    size_t eq = part.find('=');
    std::string k = (eq == std::string::npos) ? part : part.substr(0, eq);
    if (urlDecode(k) == key) {
      return (eq == std::string::npos) ? std::string{} : urlDecode(part.substr(eq + 1));
    }
  }
  return {};
}

struct WsServer::Transport {
  SOCKET sock = INVALID_SOCKET;
  std::unique_ptr<TlsConnection> tls;
  bool closed = false;

  int recvSome(char* buf, size_t len) {
    if (closed) return -1;
    if (tls) return tls->recvBytes(buf, len);
    return recv(sock, buf, static_cast<int>(len), 0);
  }

  bool sendAll(const char* data, size_t len) {
    if (closed) return false;
    if (tls) {
      return tls->sendBytes(data, len) == static_cast<int>(len);
    }
    size_t sent = 0;
    while (sent < len) {
      int chunk = static_cast<int>(std::min<size_t>(len - sent, 65536));
#ifdef _WIN32
      int n = send(sock, data + sent, chunk, 0);
#else
      ssize_t n = send(sock, data + sent, static_cast<size_t>(chunk), MSG_NOSIGNAL);
#endif
      if (n <= 0) return false;
      sent += static_cast<size_t>(n);
    }
    return true;
  }

  bool recvExact(uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
      int n = recvSome(reinterpret_cast<char*>(buf + got), len - got);
      if (n <= 0) return false;
      got += static_cast<size_t>(n);
    }
    return true;
  }

  void close() {
    if (closed) return;
    closed = true;
    if (tls) {
      tls->shutdownTls();
      tls.reset();
    }
    if (sock != INVALID_SOCKET) {
      shutdown(sock, SD_BOTH);
      closesocket(sock);
      sock = INVALID_SOCKET;
    }
  }
};

struct WsServer::ClientConn {
  std::shared_ptr<Transport> io;
  std::mutex sendMutex;
  std::atomic<bool> alive{true};
  AuthContext auth;
  std::string remoteIp;

  bool sendFrame(uint8_t opcode, const std::string& payload) {
    if (!alive.load()) return false;
    auto frame = encodeWebSocketFrame(opcode, payload);
    std::lock_guard lock(sendMutex);
    if (!alive.load() || !io) return false;
    bool ok = io->sendAll(reinterpret_cast<const char*>(frame.data()), frame.size());
    if (!ok) alive.store(false);
    return ok;
  }

  void close() {
    if (alive.exchange(false)) {
      if (io && io->sock != INVALID_SOCKET) {
        shutdown(io->sock, SD_BOTH);
      }
    }
  }
};

std::string computeWebSocketAcceptKey(const std::string& clientKey) {
  const std::string combined = trimAscii(clientKey) + kWsMagicGuid;
  uint8_t sha1Digest[20] = {};

#ifdef _WIN32
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;

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
#else
  SHA1(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), sha1Digest);
  unsigned char b64[64] = {};
  int len = EVP_EncodeBlock(b64, sha1Digest, sizeof(sha1Digest));
  if (len <= 0) return {};
  return std::string(reinterpret_cast<char*>(b64), static_cast<size_t>(len));
#endif
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
                   std::filesystem::path assetsDir,
                   std::string bindHost)
    : requestedPort_(port),
      bindHost_(std::move(bindHost)),
      staticDir_(std::move(staticDir)),
      assetsDir_(std::move(assetsDir)) {
  std::error_code ec;
  canonicalStaticDir_ = std::filesystem::weakly_canonical(staticDir_, ec);
  if (ec) canonicalStaticDir_ = staticDir_;
  canonicalAssetsDir_ = std::filesystem::weakly_canonical(assetsDir_, ec);
  if (ec) canonicalAssetsDir_ = assetsDir_;
}

WsServer::~WsServer() {
  stop();
}

void WsServer::setAllowedHosts(std::vector<std::string> hosts) {
  allowedHosts_.clear();
  for (auto& h : hosts) {
    std::string low = toLowerAscii(trimAscii(h));
    if (!low.empty()) allowedHosts_.push_back(std::move(low));
  }
}

bool WsServer::isHostAllowed(const std::string& hostHeader) const {
  if (hostHeader.empty()) return false;
  std::string hostOnly = stripPortFromAuthority(hostHeader);
  if (hostOnly.empty()) return false;
  if (isLoopbackHostName(hostOnly)) return true;

  if (bindHost_ == "0.0.0.0") {
    if (allowedHosts_.empty()) return true;
  } else if (toLowerAscii(bindHost_) == hostOnly) {
    return true;
  }

  for (const auto& ah : allowedHosts_) {
    if (ah == hostOnly || ah == toLowerAscii(trimAscii(hostHeader))) return true;
  }
  return false;
}

bool WsServer::isOriginAllowed(const std::string& originHeader,
                               const std::string& hostHeader,
                               bool reqTls) const {
  if (originHeader.empty()) return true;
  std::string lowOrigin = toLowerAscii(trimAscii(originHeader));
  if (lowOrigin == "null") return false;

  size_t schemePos = lowOrigin.find("://");
  if (schemePos == std::string::npos) return false;
  std::string scheme = lowOrigin.substr(0, schemePos);
  std::string originAuthority = lowOrigin.substr(schemePos + 3);
  size_t slash = originAuthority.find('/');
  if (slash != std::string::npos) originAuthority = originAuthority.substr(0, slash);

  if (scheme != "http" && scheme != "https") return false;
  if (reqTls && scheme != "https" && !trustProxyTls_) return false;

  std::string cleanHost = toLowerAscii(trimAscii(hostHeader));
  if (originAuthority == cleanHost) return true;

  std::string originHostOnly = stripPortFromAuthority(originAuthority);
  std::string reqHostOnly = stripPortFromAuthority(cleanHost);
  if (!isHostAllowed(originAuthority)) return false;
  return originHostOnly == reqHostOnly;
}

bool WsServer::start() {
  if (running_.exchange(true)) return true;

  SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ls == INVALID_SOCKET) {
    running_.store(false);
    return false;
  }

  int opt = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(requestedPort_);
  if (bindHost_.empty() || bindHost_ == "0.0.0.0") {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  } else if (inet_pton(AF_INET, bindHost_.c_str(), &addr.sin_addr) != 1) {
    closesocket(ls);
    running_.store(false);
    return false;
  }

  if (bind(ls, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
    closesocket(ls);
    running_.store(false);
    return false;
  }

  sockaddr_in boundAddr{};
#ifdef _WIN32
  int boundLen = sizeof(boundAddr);
#else
  socklen_t boundLen = sizeof(boundAddr);
#endif
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
    shutdown(ls, SD_BOTH);
    closesocket(ls);
  }

  if (acceptThread_.joinable()) {
    acceptThread_.request_stop();
    acceptThread_.join();
  }

  disconnectAllWebSockets();

  std::unique_lock sLock(shutdownMutex_);
  shutdownCv_.wait_for(sLock, std::chrono::seconds(5), [this]() {
    return activeHandlers_.load() == 0;
  });
}

void WsServer::disconnectAllWebSockets() {
  std::vector<std::shared_ptr<ClientConn>> copyClients;
  {
    std::lock_guard lock(clientsMutex_);
    copyClients = clients_;
    clients_.clear();
  }
  for (auto& c : copyClients) {
    c->close();
  }
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

void WsServer::setApiCallback(ApiCallback cb) {
  onApi_ = std::move(cb);
}

void WsServer::setWsAuthCallback(WsAuthCallback cb) {
  onWsAuth_ = std::move(cb);
}

void WsServer::setRateLimitCallback(RateLimitCallback cb) {
  onRateLimit_ = std::move(cb);
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
    sockaddr_storage peerAddr{};
#ifdef _WIN32
    int peerLen = sizeof(peerAddr);
#else
    socklen_t peerLen = sizeof(peerAddr);
#endif
    SOCKET cs = accept(ls, reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
    if (cs == INVALID_SOCKET) break;

    if (activeHandlers_.load() >= maxConnections_) {
      closesocket(cs);
      continue;
    }

    int nodelay = 1;
    setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    std::string remoteIp = extractRemoteIp(peerAddr);
    activeHandlers_.fetch_add(1);
    std::thread([this, sock = static_cast<uintptr_t>(cs), remoteIp = std::move(remoteIp)]() mutable {
      handleHttpOrWs(sock, std::move(remoteIp));
      if (activeHandlers_.fetch_sub(1) == 1) {
        std::lock_guard lk(shutdownMutex_);
        shutdownCv_.notify_all();
      }
    }).detach();
  }
}

void WsServer::sendResponse(Transport& io, const HttpResponse& resp) {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << httpStatusText(resp.statusCode) << "\r\n"
      << "Content-Type: " << resp.contentType << "\r\n"
      << "Content-Length: " << resp.body.size() << "\r\n"
      << "Connection: close\r\n"
      << "X-Content-Type-Options: nosniff\r\n"
      << "X-Frame-Options: DENY\r\n"
      << "Referrer-Policy: no-referrer\r\n"
      << "Cache-Control: no-store\r\n";
  for (const auto& [k, v] : resp.extraHeaders) {
    oss << k << ": " << v << "\r\n";
  }
  oss << "\r\n" << resp.body;
  std::string msg = oss.str();
  io.sendAll(msg.data(), msg.size());
  io.close();
}

void WsServer::sendSimpleResponse(Transport& io,
                                  int statusCode,
                                  const char* contentType,
                                  const std::string& body) {
  HttpResponse resp;
  resp.statusCode = statusCode;
  resp.contentType = contentType;
  resp.body = body;
  sendResponse(io, resp);
}

bool WsServer::sendFileResponse(Transport& io,
                                const std::filesystem::path& filePath,
                                const std::filesystem::path& allowedRoot,
                                const char* mimeType,
                                const char* cacheControl,
                                bool isHtml) {
  std::error_code ec;
  std::filesystem::path canonTarget = std::filesystem::weakly_canonical(filePath, ec);
  if (ec) return false;

  std::string targetStr = canonTarget.generic_string();
  std::string rootStr = allowedRoot.generic_string();
  if (!rootStr.empty() && rootStr.back() != '/') rootStr.push_back('/');
  if (targetStr.rfind(rootStr, 0) != 0) {
    return false;
  }

  std::ifstream in(canonTarget, std::ios::binary | std::ios::ate);
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
      << "X-Content-Type-Options: nosniff\r\n"
      << "X-Frame-Options: DENY\r\n"
      << "Referrer-Policy: no-referrer\r\n";
  if (isHtml) {
    oss << "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:;\r\n";
  }
  oss << "Connection: close\r\n\r\n";
  std::string hdr = oss.str();
  io.sendAll(hdr.data(), hdr.size());
  if (!body.empty()) {
    io.sendAll(body.data(), body.size());
  }
  io.close();
  return true;
}

void WsServer::handleHttpOrWs(uintptr_t rawSock, std::string remoteIp) {
  auto io = std::make_shared<Transport>();
  io->sock = static_cast<SOCKET>(rawSock);
  setRecvTimeoutMs(io->sock, 5000);

  bool reqIsTls = false;
  if (tlsCtx_ && tlsCtx_->isReady()) {
    io->tls = tlsCtx_->wrapAcceptedSocket(rawSock);
    if (!io->tls || !io->tls->handshake()) {
      io->close();
      return;
    }
    reqIsTls = true;
  }

  if (onRateLimit_) {
    auto [allowed, retryAfter] = onRateLimit_(remoteIp);
    if (!allowed) {
      HttpResponse resp;
      resp.statusCode = 429;
      resp.body = "{\"error\":\"rate_limited\"}";
      resp.extraHeaders.emplace_back("Retry-After", std::to_string(retryAfter));
      sendResponse(*io, resp);
      return;
    }
  }

  std::string reqStr;
  reqStr.reserve(2048);
  char buf[2048];
  size_t hdrEnd = std::string::npos;

  while (reqStr.size() < kMaxHttpHeaderBytes) {
    int n = io->recvSome(buf, sizeof(buf));
    if (n <= 0) {
      io->close();
      return;
    }
    reqStr.append(buf, static_cast<size_t>(n));
    hdrEnd = reqStr.find("\r\n\r\n");
    if (hdrEnd != std::string::npos) break;
  }

  if (hdrEnd == std::string::npos) {
    sendSimpleResponse(*io, 400, "application/json; charset=utf-8", "{\"error\":\"bad_request\"}");
    return;
  }

  std::istringstream iss(reqStr.substr(0, hdrEnd));
  HttpRequest req;
  req.remoteIp = std::move(remoteIp);
  req.isTls = reqIsTls;

  std::string target, version;
  iss >> req.method >> target >> version;
  if (req.method.empty() || target.empty() || version.rfind("HTTP/", 0) != 0) {
    sendSimpleResponse(*io, 400, "application/json; charset=utf-8", "{\"error\":\"malformed_request_line\"}");
    return;
  }

  size_t qPos = target.find('?');
  req.path = (qPos == std::string::npos) ? target : target.substr(0, qPos);
  req.query = (qPos == std::string::npos) ? std::string{} : target.substr(qPos + 1);

  size_t contentLength = 0;
  std::string line;
  std::getline(iss, line);
  while (std::getline(iss, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string k = toLowerAscii(trimAscii(line.substr(0, colon)));
    std::string v = trimAscii(line.substr(colon + 1));
    if (!k.empty()) req.headers[k] = v;
    if (k == "content-length") {
      for (char ch : v) {
        if (ch < '0' || ch > '9') {
          sendSimpleResponse(*io, 400, "application/json; charset=utf-8", "{\"error\":\"invalid_content_length\"}");
          return;
        }
      }
      long long cl = std::atoll(v.c_str());
      if (cl < 0) {
        sendSimpleResponse(*io, 400, "application/json; charset=utf-8", "{\"error\":\"invalid_content_length\"}");
        return;
      }
      if (static_cast<size_t>(cl) > kMaxHttpBodyBytes) {
        sendSimpleResponse(*io, 413, "application/json; charset=utf-8", "{\"error\":\"payload_too_large\"}");
        return;
      }
      contentLength = static_cast<size_t>(cl);
    }
  }

  if (trustProxyTls_ && toLowerAscii(req.header("x-forwarded-proto")) == "https") {
    req.isTls = true;
  }

  const std::string hostHdr = req.header("host");
  if (!isHostAllowed(hostHdr)) {
    sendSimpleResponse(*io, 403, "application/json; charset=utf-8", "{\"error\":\"invalid_host\"}");
    return;
  }

  const std::string originHdr = req.header("origin");
  if (!isOriginAllowed(originHdr, hostHdr, req.isTls)) {
    sendSimpleResponse(*io, 403, "application/json; charset=utf-8", "{\"error\":\"origin_forbidden\"}");
    return;
  }

  if (req.method == "OPTIONS") {
    HttpResponse resp;
    resp.statusCode = 204;
    resp.contentType = "text/plain";
    sendResponse(*io, resp);
    return;
  }

  const std::string upgradeHeader = toLowerAscii(req.header("upgrade"));
  const std::string wsKey = req.header("sec-websocket-key");
  if (upgradeHeader == "websocket" && !wsKey.empty()) {
    if (clientCount() >= maxWsClients_) {
      sendSimpleResponse(*io, 503, "application/json; charset=utf-8", "{\"error\":\"ws_client_limit\"}");
      return;
    }

    AuthContext wsAuth;
    if (onWsAuth_) {
      WsAuthDecision dec = onWsAuth_(req);
      if (!dec.allowed) {
        sendSimpleResponse(*io, dec.httpStatus, "application/json; charset=utf-8", dec.errorBody);
        return;
      }
      wsAuth = std::move(dec.auth);
    }

    std::string acceptKey = computeWebSocketAcceptKey(wsKey);
    std::ostringstream oss;
    oss << "HTTP/1.1 101 Switching Protocols\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";
    std::string resp = oss.str();
    if (!io->sendAll(resp.data(), resp.size())) {
      io->close();
      return;
    }

    setRecvTimeoutMs(io->sock, 0);

    auto client = std::make_shared<ClientConn>();
    client->io = io;
    client->auth = std::move(wsAuth);
    client->remoteIp = req.remoteIp;
    {
      std::lock_guard lock(clientsMutex_);
      clients_.push_back(client);
    }

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

  if (req.path.rfind("/api/", 0) == 0 && req.path != "/api/health") {
    req.body = reqStr.substr(hdrEnd + 4);
    while (req.body.size() < contentLength) {
      int n = io->recvSome(buf, sizeof(buf));
      if (n <= 0) break;
      req.body.append(buf, static_cast<size_t>(n));
    }
    if (req.body.size() > contentLength) req.body.resize(contentLength);
    if (req.body.size() < contentLength) {
      sendSimpleResponse(*io, 400, "application/json; charset=utf-8", "{\"error\":\"incomplete_body\"}");
      return;
    }

    if (onApi_) {
      HttpResponse resp = onApi_(req);
      sendResponse(*io, resp);
      return;
    }
    sendSimpleResponse(*io, 404, "application/json; charset=utf-8", "{\"error\":\"not_found\"}");
    return;
  }

  if (req.method != "GET") {
    sendSimpleResponse(*io, 405, "application/json; charset=utf-8", "{\"error\":\"method_not_allowed\"}");
    return;
  }

  if (req.path == "/api/health") {
    std::string body = onHealth_ ? onHealth_() : "{\"status\":\"ok\"}";
    sendSimpleResponse(*io, 200, "application/json; charset=utf-8", body);
    return;
  }

  std::string path = req.path;
  if (path == "/") path = "/index.html";

  if (path.rfind("/assets/", 0) == 0) {
    std::string rel = path.substr(8);
    if (!isSafeRelativeSubpath(rel)) {
      sendSimpleResponse(*io, 403, "text/plain", "Forbidden");
      return;
    }
    std::filesystem::path full = assetsDir_ / urlDecode(rel);
    if (!sendFileResponse(*io, full, canonicalAssetsDir_, mimeFromExtension(full), "public, max-age=86400", false)) {
      sendSimpleResponse(*io, 404, "text/plain", "Not Found");
    }
    return;
  }

  std::string rel = (path.front() == '/') ? path.substr(1) : path;
  if (!isSafeRelativeSubpath(rel)) {
    sendSimpleResponse(*io, 403, "text/plain", "Forbidden");
    return;
  }
  std::filesystem::path full = staticDir_ / urlDecode(rel);
  bool isHtml = (toLowerAscii(full.extension().string()) == ".html");
  if (!sendFileResponse(*io, full, canonicalStaticDir_, mimeFromExtension(full), "no-cache", isHtml)) {
    sendSimpleResponse(*io, 404, "text/plain", "Not Found");
  }
}

void WsServer::handleWebSocketClient(std::shared_ptr<ClientConn> client) {
  while (running_.load() && client->alive.load()) {
    uint8_t hdr[2];
    if (!client->io->recvExact(hdr, 2)) break;

    uint8_t opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t payloadLen = hdr[1] & 0x7F;

    if (payloadLen == 126) {
      uint8_t ext[2];
      if (!client->io->recvExact(ext, 2)) break;
      payloadLen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
    } else if (payloadLen == 127) {
      uint8_t ext[8];
      if (!client->io->recvExact(ext, 8)) break;
      payloadLen = 0;
      for (int i = 0; i < 8; ++i) {
        payloadLen = (payloadLen << 8) | ext[i];
      }
    }

    if (payloadLen > 65536) break;

    uint8_t maskKey[4] = {};
    if (masked && !client->io->recvExact(maskKey, 4)) break;

    std::string payload(static_cast<size_t>(payloadLen), '\0');
    if (payloadLen > 0) {
      if (!client->io->recvExact(reinterpret_cast<uint8_t*>(payload.data()), static_cast<size_t>(payloadLen))) {
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
      if (onCommand_) onCommand_(payload, client->auth, client->remoteIp);
    }
  }

  {
    std::lock_guard lock(client->sendMutex);
    client->alive.store(false);
    if (client->io) client->io->close();
  }
  std::lock_guard lock(clientsMutex_);
  clients_.erase(
      std::remove_if(clients_.begin(), clients_.end(),
                     [&](const std::shared_ptr<ClientConn>& c) { return c.get() == client.get() || !c->alive.load(); }),
      clients_.end());
}

} // namespace netpulse
