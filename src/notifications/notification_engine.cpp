#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "notification_engine.hpp"
#include "../models.hpp"
#include "../security/auth_manager.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace netpulse {
namespace {

uint64_t currentMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string toLowerCopy(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string trimCopy(const std::string& s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

std::string makeId(const std::string& prefix, uint64_t now) {
  static uint64_t seq = 0;
  ++seq;
  return prefix + "-" + std::to_string(now) + "-" + std::to_string(seq);
}

bool hexToRawBytes(const std::string& hex, std::string& outBytes) {
  if (hex.size() % 2 != 0) return false;
  outBytes.clear();
  outBytes.reserve(hex.size() / 2);
  auto hexVal = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = hexVal(hex[i]);
    int lo = hexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    outBytes.push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

std::string extractHostLower(const std::string& url) {
  const size_t schemePos = url.find("://");
  if (schemePos == std::string::npos) return {};
  const size_t start = schemePos + 3;
  size_t end = url.find_first_of("/?#", start);
  if (end == std::string::npos) end = url.size();
  std::string auth = url.substr(start, end - start);
  const size_t at = auth.rfind('@');
  if (at != std::string::npos) auth = auth.substr(at + 1);
  if (!auth.empty() && auth.front() == '[') {
    const size_t closeBr = auth.find(']');
    if (closeBr != std::string::npos) {
      return toLowerCopy(auth.substr(0, closeBr + 1));
    }
  }
  const size_t colon = auth.rfind(':');
  if (colon != std::string::npos) {
    auth = auth.substr(0, colon);
  }
  return toLowerCopy(auth);
}

bool isLoopbackHostUrl(const std::string& host) {
  return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
}

std::string maskSecret(const std::string& secret) {
  if (secret.empty()) return "";
  if (secret.size() <= 4) return "****";
  return "***" + secret.substr(secret.size() - 4);
}

bool httpPostJson(const std::string& url,
                  const std::string& jsonBody,
                  const std::string& hmacSignatureHex,
                  int& outHttpStatus,
                  std::string& outError) {
  outHttpStatus = 0;
  outError.clear();

#ifdef _WIN32
  std::wstring wUrl(url.begin(), url.end());
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof(uc);
  wchar_t hostBuf[256] = {};
  wchar_t pathBuf[2048] = {};
  uc.lpszHostName = hostBuf;
  uc.dwHostNameLength = static_cast<DWORD>(std::size(hostBuf));
  uc.lpszUrlPath = pathBuf;
  uc.dwUrlPathLength = static_cast<DWORD>(std::size(pathBuf));
  if (!WinHttpCrackUrl(wUrl.c_str(), static_cast<DWORD>(wUrl.size()), 0, &uc)) {
    outError = "WinHttpCrackUrl failed";
    return false;
  }

  const bool isLoop = (wcscmp(hostBuf, L"127.0.0.1") == 0 || _wcsicmp(hostBuf, L"localhost") == 0 ||
                       wcscmp(hostBuf, L"::1") == 0 || wcscmp(hostBuf, L"[::1]") == 0);
  HINTERNET hSession = WinHttpOpen(L"NetPulse-Notifier/1.0",
                                   isLoop ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    outError = "WinHttpOpen failed";
    return false;
  }
  WinHttpSetTimeouts(hSession, 4000, 4000, 5000, 5000);

  HINTERNET hConnect = WinHttpConnect(hSession, hostBuf, uc.nPort, 0);
  if (!hConnect) {
    WinHttpCloseHandle(hSession);
    outError = "WinHttpConnect failed";
    return false;
  }

  const DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
  const wchar_t* pathPtr = pathBuf[0] ? pathBuf : L"/";
  HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", pathPtr, nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!hRequest) {
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    outError = "WinHttpOpenRequest failed";
    return false;
  }

  std::wstring headers = L"Content-Type: application/json; charset=utf-8\r\n";
  if (!hmacSignatureHex.empty()) {
    std::string sigHdr = "X-NetPulse-Signature: sha256=" + hmacSignatureHex + "\r\n";
    headers.append(sigHdr.begin(), sigHdr.end());
  }

  BOOL sent = WinHttpSendRequest(
      hRequest,
      headers.c_str(),
      static_cast<DWORD>(headers.size()),
      const_cast<char*>(jsonBody.data()),
      static_cast<DWORD>(jsonBody.size()),
      static_cast<DWORD>(jsonBody.size()),
      0);
  if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
    const DWORD gle = GetLastError();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    outError = "HTTP transport error (" + std::to_string(gle) + ")";
    return false;
  }

  DWORD statusCode = 0;
  DWORD sz = sizeof(statusCode);
  if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX)) {
    outHttpStatus = static_cast<int>(statusCode);
  }

  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);

  if (outHttpStatus < 200 || outHttpStatus >= 300) {
    outError = "HTTP status " + std::to_string(outHttpStatus);
    return false;
  }
  return true;
#else
  const bool isHttps = url.rfind("https://", 0) == 0;
  const bool isHttp = url.rfind("http://", 0) == 0;
  if (!isHttps && !isHttp) {
    outError = "Unsupported URL scheme";
    return false;
  }
  const size_t authStart = isHttps ? 8 : 7;
  size_t pathPos = url.find('/', authStart);
  std::string hostPort = (pathPos == std::string::npos) ? url.substr(authStart) : url.substr(authStart, pathPos - authStart);
  std::string reqPath = (pathPos == std::string::npos) ? "/" : url.substr(pathPos);
  std::string host = hostPort;
  std::string portStr = isHttps ? "443" : "80";
  const size_t colon = hostPort.rfind(':');
  if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
    host = hostPort.substr(0, colon);
    portStr = hostPort.substr(colon + 1);
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
    outError = "DNS resolution failed";
    return false;
  }

  int fd = -1;
  for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    outError = "TCP connect failed";
    return false;
  }

  std::string req = "POST " + reqPath + " HTTP/1.1\r\n"
                    "Host: " + hostPort + "\r\n"
                    "User-Agent: NetPulse-Notifier/1.0\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    "Content-Length: " + std::to_string(jsonBody.size()) + "\r\n"
                    "Connection: close\r\n";
  if (!hmacSignatureHex.empty()) {
    req += "X-NetPulse-Signature: sha256=" + hmacSignatureHex + "\r\n";
  }
  req += "\r\n" + jsonBody;

  std::string resp;
  if (isHttps) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
      close(fd);
      outError = "SSL_CTX_new failed";
      return false;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
    if (SSL_connect(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(fd);
      outError = "TLS handshake failed";
      return false;
    }
    SSL_write(ssl, req.data(), static_cast<int>(req.size()));
    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) resp.assign(buf, static_cast<size_t>(n));
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  } else {
    send(fd, req.data(), req.size(), 0);
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) resp.assign(buf, static_cast<size_t>(n));
  }
  close(fd);

  const size_t sp = resp.find(' ');
  if (sp != std::string::npos && sp + 4 <= resp.size()) {
    outHttpStatus = std::atoi(resp.substr(sp + 1, 3).c_str());
  }
  if (outHttpStatus < 200 || outHttpStatus >= 300) {
    outError = "HTTP status " + std::to_string(outHttpStatus);
    return false;
  }
  return true;
#endif
}

} // namespace

std::string hmacSha256Hex(const std::string& key, const std::string& message) {
  constexpr size_t kBlockSize = 64;
  std::string kPrime = key;
  if (kPrime.size() > kBlockSize) {
    std::string raw;
    if (!hexToRawBytes(AuthManager::sha256Hex(kPrime), raw)) return {};
    kPrime = std::move(raw);
  }
  kPrime.resize(kBlockSize, '\0');

  std::string iPad(kBlockSize, '\0');
  std::string oPad(kBlockSize, '\0');
  for (size_t i = 0; i < kBlockSize; ++i) {
    iPad[i] = static_cast<char>(static_cast<uint8_t>(kPrime[i]) ^ 0x36);
    oPad[i] = static_cast<char>(static_cast<uint8_t>(kPrime[i]) ^ 0x5c);
  }

  std::string innerBytes;
  if (!hexToRawBytes(AuthManager::sha256Hex(iPad + message), innerBytes)) {
    return {};
  }
  return AuthManager::sha256Hex(oPad + innerBytes);
}

int notificationSeverityRank(const std::string& sev) {
  const std::string s = toLowerCopy(sev);
  if (s == "critical") return 4;
  if (s == "high" || s == "error") return 3;
  if (s == "warn" || s == "warning" || s == "moderate") return 2;
  if (s == "low") return 1;
  return 0;
}

bool validateNotificationTargetUrl(const std::string& kind,
                                   const std::string& endpointUrl,
                                   const std::string& secretOrToken,
                                   const std::string& chatId,
                                   std::string& outEffectiveUrl,
                                   std::string& outError) {
  if (kind != "webhook" && kind != "discord" && kind != "telegram") {
    outError = "kind deve ser webhook, discord ou telegram";
    return false;
  }

  std::string url = trimCopy(endpointUrl);
  if (kind == "telegram") {
    if (trimCopy(chatId).empty()) {
      outError = "chatId obrigatorio para canal Telegram";
      return false;
    }
    if (url.empty()) {
      const std::string tok = trimCopy(secretOrToken);
      if (tok.empty()) {
        outError = "Bot Token ou URL explicita obrigatoria para Telegram";
        return false;
      }
      url = "https://api.telegram.org/bot" + tok + "/sendMessage";
    }
  }

  if (url.empty() || url.size() > 512) {
    outError = "URL do endpoint invalida ou ausente";
    return false;
  }
  for (unsigned char ch : url) {
    if (ch < 0x20 || ch == 0x7f) {
      outError = "URL contem caracteres de controle";
      return false;
    }
  }

  const std::string lower = toLowerCopy(url);
  const bool isHttps = lower.rfind("https://", 0) == 0;
  const bool isHttp = lower.rfind("http://", 0) == 0;
  if (!isHttps && !isHttp) {
    outError = "Esquema invalido: somente https:// (ou http:// em loopback) permitido";
    return false;
  }
  const std::string host = extractHostLower(url);
  if (host.empty()) {
    outError = "Hostname invalido na URL";
    return false;
  }
  if (isHttp && !isLoopbackHostUrl(host)) {
    outError = "Enderecos externos exigem HTTPS (HTTP permitido somente em loopback localhost/127.0.0.1)";
    return false;
  }

  outEffectiveUrl = url;
  return true;
}

bool shouldDispatchToChannel(const NotificationChannelRecord& ch,
                             const NotificationEvent& ev,
                             uint64_t lastChannelSentMs,
                             uint64_t nowMs) {
  if (!ch.enabled) return false;
  if (ev.kind != "test") {
    if (notificationSeverityRank(ev.severity) < notificationSeverityRank(ch.minSeverity)) {
      return false;
    }
    if (!ch.categoriesCsv.empty()) {
      bool matched = false;
      std::stringstream ss(ch.categoriesCsv);
      std::string token;
      while (std::getline(ss, token, ',')) {
        if (toLowerCopy(trimCopy(token)) == toLowerCopy(ev.kind)) {
          matched = true;
          break;
        }
      }
      if (!matched) return false;
    }
    const uint64_t cdMs = static_cast<uint64_t>(std::max(0, ch.cooldownSec)) * 1000ULL;
    if (lastChannelSentMs > 0 && nowMs >= lastChannelSentMs && (nowMs - lastChannelSentMs) < cdMs) {
      return false;
    }
  }
  return true;
}

std::string buildNotificationPayloadJson(const NotificationChannelRecord& ch,
                                         const NotificationEvent& ev) {
  if (ch.kind == "discord") {
    const int color = (notificationSeverityRank(ev.severity) >= 3) ? 15158332
                      : (notificationSeverityRank(ev.severity) == 2) ? 15844367
                                                                     : 3447003;
    std::string out = "{\"username\":\"NetPulse\",\"embeds\":[{";
    out += "\"title\":"; appendJsonEscaped(out, "[" + toLowerCopy(ev.severity) + "] " + ev.title);
    out += ",\"description\":"; appendJsonEscaped(out, ev.detail);
    out += ",\"color\":" + std::to_string(color);
    out += ",\"fields\":[{\"name\":\"Categoria\",\"value\":"; appendJsonEscaped(out, ev.kind);
    out += ",\"inline\":true},{\"name\":\"Origem\",\"value\":"; appendJsonEscaped(out, ev.source);
    out += ",\"inline\":true}]}]}";
    return out;
  }

  if (ch.kind == "telegram") {
    const std::string text = "[NetPulse | " + toLowerCopy(ev.severity) + "] " + ev.title +
                             "\nCategoria: " + ev.kind + "\n" + ev.detail;
    std::string out = "{\"chat_id\":"; appendJsonEscaped(out, ch.chatId);
    out += ",\"text\":"; appendJsonEscaped(out, text);
    out += ",\"disable_web_page_preview\":true}";
    return out;
  }

  std::string out = "{\"event\":"; appendJsonEscaped(out, ev.kind);
  out += ",\"severity\":"; appendJsonEscaped(out, ev.severity);
  out += ",\"title\":"; appendJsonEscaped(out, ev.title);
  out += ",\"detail\":"; appendJsonEscaped(out, ev.detail);
  out += ",\"source\":"; appendJsonEscaped(out, ev.source);
  out += ",\"tsMs\":" + std::to_string(ev.tsMs > 0 ? ev.tsMs : currentMs()) + "}";
  return out;
}

NotificationEngine::NotificationEngine(HistoryStore& history) : history_(history) {
  std::lock_guard lock(mutex_);
  channels_ = history_.loadNotificationChannels();
}

NotificationEngine::~NotificationEngine() {
  stop();
}

void NotificationEngine::start() {
  if (running_.exchange(true)) return;
  worker_ = std::jthread([this](std::stop_token st) { workerLoop(st); });
}

void NotificationEngine::stop() {
  if (!running_.exchange(false)) return;
  if (worker_.joinable()) {
    worker_.request_stop();
    queueCv_.notify_all();
    worker_.join();
  }
}

void NotificationEngine::notify(const NotificationEvent& ev) {
  if (!running_.load()) return;
  NotificationEvent copy = ev;
  if (copy.tsMs == 0) copy.tsMs = currentMs();
  {
    std::lock_guard lock(queueMutex_);
    if (queue_.size() >= 256) {
      queue_.pop_front();
    }
    queue_.push_back(std::move(copy));
  }
  queueCv_.notify_one();
}

bool NotificationEngine::deliverSingle(const NotificationChannelRecord& ch,
                                       const NotificationEvent& ev,
                                       int& outHttpStatus,
                                       std::string& outError) {
  std::string targetUrl;
  std::string urlErr;
  if (!validateNotificationTargetUrl(ch.kind, ch.endpointUrl, ch.secretOrToken, ch.chatId, targetUrl, urlErr)) {
    outHttpStatus = 0;
    outError = urlErr;
    return false;
  }

  const std::string payload = buildNotificationPayloadJson(ch, ev);
  std::string sigHex;
  if (ch.kind == "webhook" && !ch.secretOrToken.empty()) {
    sigHex = hmacSha256Hex(ch.secretOrToken, payload);
  }

  const uint64_t now = currentMs();
  const bool ok = httpPostJson(targetUrl, payload, sigHex, outHttpStatus, outError);
  if (ok) {
    sentOk_.fetch_add(1);
  } else {
    sentErr_.fetch_add(1);
  }

  NotificationDeliveryRecord rec;
  rec.tsMs = now;
  rec.channelId = ch.id;
  rec.channelName = ch.name;
  rec.eventKind = ev.kind;
  rec.severity = ev.severity;
  rec.title = ev.title;
  rec.ok = ok;
  rec.httpStatus = outHttpStatus;
  rec.error = outError;
  history_.saveNotificationDelivery(rec);
  history_.updateNotificationChannelStatus(ch.id, now, ok ? "ok" : "error", outError);

  std::lock_guard lock(mutex_);
  lastSentByChannel_[ch.id] = now;
  for (auto& existing : channels_) {
    if (existing.id == ch.id) {
      existing.lastSentMs = now;
      existing.lastStatus = ok ? "ok" : "error";
      existing.lastError = outError;
    }
  }
  return ok;
}

void NotificationEngine::workerLoop(std::stop_token st) {
  while (!st.stop_requested() && running_.load()) {
    NotificationEvent ev;
    {
      std::unique_lock lock(queueMutex_);
      queueCv_.wait(lock, st, [&]() { return !queue_.empty() || st.stop_requested() || !running_.load(); });
      if (st.stop_requested() || !running_.load()) break;
      if (queue_.empty()) continue;
      ev = std::move(queue_.front());
      queue_.pop_front();
    }

    std::vector<NotificationChannelRecord> snapshot;
    std::unordered_map<std::string, uint64_t> lastSentCopy;
    {
      std::lock_guard lock(mutex_);
      snapshot = channels_;
      lastSentCopy = lastSentByChannel_;
    }

    const uint64_t now = currentMs();
    for (const auto& ch : snapshot) {
      const uint64_t prevMs = lastSentCopy.count(ch.id) ? lastSentCopy[ch.id] : ch.lastSentMs;
      if (shouldDispatchToChannel(ch, ev, prevMs, now)) {
        int httpCode = 0;
        std::string err;
        deliverSingle(ch, ev, httpCode, err);
      }
    }
  }
}

bool NotificationEngine::sendTestNotification(const std::string& channelId, std::string& outError) {
  NotificationChannelRecord target;
  bool found = false;
  {
    std::lock_guard lock(mutex_);
    for (const auto& ch : channels_) {
      if (ch.id == channelId) {
        target = ch;
        found = true;
        break;
      }
    }
  }
  if (!found) {
    outError = "Canal nao encontrado";
    return false;
  }

  NotificationEvent ev;
  ev.tsMs = currentMs();
  ev.kind = "test";
  ev.severity = "info";
  ev.title = "Teste de Notificacao NetPulse";
  ev.detail = "Envio manual validado para o canal '" + target.name + "' (" + target.kind + ").";
  ev.source = "netpulse";

  int code = 0;
  return deliverSingle(target, ev, code, outError);
}

bool NotificationEngine::upsertChannel(const NotificationChannelRecord& incoming,
                                       NotificationChannelRecord& outSaved,
                                       std::string& outError) {
  if (trimCopy(incoming.name).empty()) {
    outError = "Nome do canal obrigatorio";
    return false;
  }

  NotificationChannelRecord rec = incoming;
  rec.name = trimCopy(rec.name);
  rec.kind = toLowerCopy(trimCopy(rec.kind));
  rec.endpointUrl = trimCopy(rec.endpointUrl);
  rec.chatId = trimCopy(rec.chatId);
  rec.cooldownSec = std::clamp(rec.cooldownSec, 0, 86400);
  if (rec.minSeverity.empty()) rec.minSeverity = "warn";

  // Preserve stored secret if caller submits blank secret while updating existing channel
  {
    std::lock_guard lock(mutex_);
    for (const auto& ex : channels_) {
      if (!rec.id.empty() && ex.id == rec.id) {
        if (rec.secretOrToken.empty()) rec.secretOrToken = ex.secretOrToken;
        rec.createdAtMs = ex.createdAtMs;
        rec.lastSentMs = ex.lastSentMs;
        rec.lastStatus = ex.lastStatus;
        rec.lastError = ex.lastError;
        break;
      }
    }
  }

  std::string effectiveUrl;
  if (!validateNotificationTargetUrl(rec.kind, rec.endpointUrl, rec.secretOrToken, rec.chatId, effectiveUrl, outError)) {
    return false;
  }

  if (rec.id.empty()) {
    rec.createdAtMs = currentMs();
    rec.id = makeId("ch", rec.createdAtMs);
  } else if (rec.createdAtMs == 0) {
    rec.createdAtMs = currentMs();
  }

  if (!history_.upsertNotificationChannel(rec)) {
    outError = "Falha ao persistir canal no SQLite";
    return false;
  }

  {
    std::lock_guard lock(mutex_);
    bool replaced = false;
    for (auto& ex : channels_) {
      if (ex.id == rec.id) {
        ex = rec;
        replaced = true;
        break;
      }
    }
    if (!replaced) channels_.insert(channels_.begin(), rec);
  }

  outSaved = rec;
  outSaved.secretOrToken = maskSecret(rec.secretOrToken);
  return true;
}

bool NotificationEngine::deleteChannel(const std::string& id) {
  if (id.empty() || !history_.deleteNotificationChannel(id)) return false;
  std::lock_guard lock(mutex_);
  channels_.erase(std::remove_if(channels_.begin(), channels_.end(),
                                 [&](const NotificationChannelRecord& c) { return c.id == id; }),
                  channels_.end());
  return true;
}

std::string NotificationEngine::getChannelsJson() const {
  std::lock_guard lock(mutex_);
  std::string out = "{\"channels\":[";
  for (size_t i = 0; i < channels_.size(); ++i) {
    const auto& c = channels_[i];
    if (i > 0) out += ",";
    out += "{\"id\":"; appendJsonEscaped(out, c.id);
    out += ",\"name\":"; appendJsonEscaped(out, c.name);
    out += ",\"kind\":"; appendJsonEscaped(out, c.kind);
    out += ",\"enabled\":" + std::string(c.enabled ? "true" : "false");
    out += ",\"endpointUrl\":"; appendJsonEscaped(out, c.endpointUrl);
    out += ",\"hasSecret\":" + std::string(!c.secretOrToken.empty() ? "true" : "false");
    out += ",\"secretPreview\":"; appendJsonEscaped(out, maskSecret(c.secretOrToken));
    out += ",\"chatId\":"; appendJsonEscaped(out, c.chatId);
    out += ",\"minSeverity\":"; appendJsonEscaped(out, c.minSeverity);
    out += ",\"categoriesCsv\":"; appendJsonEscaped(out, c.categoriesCsv);
    out += ",\"cooldownSec\":" + std::to_string(c.cooldownSec);
    out += ",\"lastSentMs\":" + std::to_string(c.lastSentMs);
    out += ",\"lastStatus\":"; appendJsonEscaped(out, c.lastStatus);
    out += ",\"lastError\":"; appendJsonEscaped(out, c.lastError);
    out += ",\"createdAtMs\":" + std::to_string(c.createdAtMs) + "}";
  }
  out += "],\"stats\":{\"sentOk\":" + std::to_string(sentOk_.load()) +
         ",\"sentError\":" + std::to_string(sentErr_.load()) + "}}";
  return out;
}

std::string NotificationEngine::getDeliveriesJson(size_t limit) const {
  const auto items = history_.loadNotificationDeliveries(limit);
  std::string out = "{\"deliveries\":[";
  for (size_t i = 0; i < items.size(); ++i) {
    const auto& d = items[i];
    if (i > 0) out += ",";
    out += "{\"id\":" + std::to_string(d.id);
    out += ",\"tsMs\":" + std::to_string(d.tsMs);
    out += ",\"channelId\":"; appendJsonEscaped(out, d.channelId);
    out += ",\"channelName\":"; appendJsonEscaped(out, d.channelName);
    out += ",\"eventKind\":"; appendJsonEscaped(out, d.eventKind);
    out += ",\"severity\":"; appendJsonEscaped(out, d.severity);
    out += ",\"title\":"; appendJsonEscaped(out, d.title);
    out += ",\"ok\":" + std::string(d.ok ? "true" : "false");
    out += ",\"httpStatus\":" + std::to_string(d.httpStatus);
    out += ",\"error\":"; appendJsonEscaped(out, d.error); out += "}";
  }
  out += "]}";
  return out;
}

} // namespace netpulse
