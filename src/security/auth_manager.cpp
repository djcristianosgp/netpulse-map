#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#endif

#include "auth_manager.hpp"
#include "../models.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string toHex(const uint8_t* data, size_t len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0x0F]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

std::string sanitizeTsv(std::string s) {
  for (char& c : s) {
    if (c == '\t' || c == '\r' || c == '\n') c = ' ';
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

bool isLoopbackIp(const std::string& ip) {
  return ip == "127.0.0.1" || ip == "::1" || ip == "::ffff:127.0.0.1";
}

} // namespace

std::string AuthManager::generateRandomHex(size_t numBytes) {
  std::vector<uint8_t> buf(std::max<size_t>(1, numBytes));
#ifdef _WIN32
  if (BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    return {};
  }
#else
  if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
    return {};
  }
#endif
  return toHex(buf.data(), buf.size());
}

std::string AuthManager::sha256Hex(const std::string& input) {
  uint8_t digest[32] = {};
#ifdef _WIN32
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;
  if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
  bool ok = false;
  if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
    if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                       static_cast<ULONG>(input.size()), 0) == 0) {
      ok = (BCryptFinishHash(hHash, digest, sizeof(digest), 0) == 0);
    }
    BCryptDestroyHash(hHash);
  }
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return ok ? toHex(digest, sizeof(digest)) : std::string{};
#else
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return {};
  unsigned int dlen = 0;
  bool ok = (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) &&
            (EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) &&
            (EVP_DigestFinal_ex(ctx, digest, &dlen) == 1);
  EVP_MD_CTX_free(ctx);
  return ok ? toHex(digest, dlen) : std::string{};
#endif
}

bool AuthManager::constantTimeEquals(const std::string& a, const std::string& b) {
  if (a.size() != b.size() || a.empty()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

std::string AuthManager::hashWithSalt(const std::string& saltHex, const std::string& secret) {
  // Key stretching via iterative SHA-256 (10,000 rounds) for offline brute-force resistance
  std::string h = sha256Hex(saltHex + ":" + secret);
  for (int i = 0; i < 4096; ++i) {
    h = sha256Hex(h + ":" + saltHex);
  }
  return h;
}

AuthManager::AuthManager(std::filesystem::path dataDir, std::string envAdminToken)
    : tokensPath_(dataDir / "auth_tokens.tsv"),
      bootstrapHintPath_(dataDir / "initial_admin_token.txt") {
  std::lock_guard lock(mutex_);
  loadTokensLocked();
  ensureBootstrapAdminToken(envAdminToken);
}

void AuthManager::loadTokensLocked() {
  std::error_code ec;
  if (!std::filesystem::exists(tokensPath_, ec)) return;
  std::ifstream in(tokensPath_);
  if (!in.is_open()) return;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, '\t')) cols.push_back(item);
    if (cols.size() < 9) continue;

    ApiTokenRecord rec;
    rec.id = cols[0];
    rec.label = cols[1];
    rec.prefix = cols[2];
    if (!parseRole(cols[3], rec.role)) rec.role = Role::Viewer;
    rec.saltHex = cols[4];
    rec.hashHex = cols[5];
    rec.createdAtMs = std::strtoull(cols[6].c_str(), nullptr, 10);
    rec.expiresAtMs = std::strtoull(cols[7].c_str(), nullptr, 10);
    rec.revoked = (cols[8] == "1");
    if (cols.size() >= 10) {
      rec.lastUsedMs = std::strtoull(cols[9].c_str(), nullptr, 10);
    }
    if (rec.id.rfind("tok-", 0) == 0) {
      uint64_t n = std::strtoull(rec.id.c_str() + 4, nullptr, 10);
      if (n >= nextTokenSeq_) nextTokenSeq_ = n + 1;
    }
    tokens_.push_back(std::move(rec));
  }
}

void AuthManager::saveTokensLocked() {
  std::error_code ec;
  std::filesystem::create_directories(tokensPath_.parent_path(), ec);
  std::ofstream out(tokensPath_, std::ios::trunc);
  if (!out.is_open()) return;
  out << "# id\tlabel\tprefix\trole\tsalt\thash\tcreated_ms\texpires_ms\trevoked\tlast_used_ms\n";
  for (const auto& t : tokens_) {
    out << sanitizeTsv(t.id) << '\t'
        << sanitizeTsv(t.label) << '\t'
        << sanitizeTsv(t.prefix) << '\t'
        << roleToString(t.role) << '\t'
        << t.saltHex << '\t'
        << t.hashHex << '\t'
        << t.createdAtMs << '\t'
        << t.expiresAtMs << '\t'
        << (t.revoked ? "1" : "0") << '\t'
        << t.lastUsedMs << '\n';
  }
}

void AuthManager::ensureBootstrapAdminToken(const std::string& envAdminToken) {
  const uint64_t now = nowEpochMs();
  bool hasActiveAdmin = false;
  for (const auto& t : tokens_) {
    if (!t.revoked && t.role == Role::Administrator &&
        (t.expiresAtMs == 0 || t.expiresAtMs > now)) {
      hasActiveAdmin = true;
      break;
    }
  }

  if (!envAdminToken.empty()) {
    // Ensure env token is registered (upsert by label "env-admin")
    bool alreadyValid = false;
    for (const auto& t : tokens_) {
      if (!t.revoked && t.label == "env-admin" &&
          constantTimeEquals(hashWithSalt(t.saltHex, envAdminToken), t.hashHex)) {
        alreadyValid = true;
        break;
      }
    }
    if (!alreadyValid) {
      ApiTokenRecord rec;
      rec.id = "tok-" + std::to_string(nextTokenSeq_++);
      rec.label = "env-admin";
      rec.prefix = envAdminToken.substr(0, std::min<size_t>(10, envAdminToken.size()));
      rec.role = Role::Administrator;
      rec.saltHex = generateRandomHex(16);
      rec.hashHex = hashWithSalt(rec.saltHex, envAdminToken);
      rec.createdAtMs = now;
      rec.expiresAtMs = 0;
      tokens_.push_back(std::move(rec));
      saveTokensLocked();
    }
    return;
  }

  if (hasActiveAdmin) return;

  const std::string raw = "np_adm_" + generateRandomHex(24);
  ApiTokenRecord rec;
  rec.id = "tok-" + std::to_string(nextTokenSeq_++);
  rec.label = "bootstrap-admin";
  rec.prefix = raw.substr(0, 12);
  rec.role = Role::Administrator;
  rec.saltHex = generateRandomHex(16);
  rec.hashHex = hashWithSalt(rec.saltHex, raw);
  rec.createdAtMs = now;
  rec.expiresAtMs = 0;
  tokens_.push_back(std::move(rec));
  saveTokensLocked();

  std::error_code ec;
  std::filesystem::create_directories(bootstrapHintPath_.parent_path(), ec);
  std::ofstream hint(bootstrapHintPath_, std::ios::trunc);
  if (hint.is_open()) {
    hint << raw << '\n';
    hint.close();
#ifndef _WIN32
    chmod(bootstrapHintPath_.c_str(), 0600);
#endif
  }
}

std::optional<ApiTokenRecord> AuthManager::verifyRawTokenLocked(const std::string& rawToken) const {
  if (rawToken.size() < 8 || rawToken.size() > 256) return std::nullopt;
  const uint64_t now = nowEpochMs();
  for (const auto& t : tokens_) {
    if (t.revoked) continue;
    if (t.expiresAtMs > 0 && t.expiresAtMs <= now) continue;
    std::string candidate = hashWithSalt(t.saltHex, rawToken);
    if (constantTimeEquals(candidate, t.hashHex)) {
      return t;
    }
  }
  return std::nullopt;
}

SessionInfo AuthManager::createSessionLocked(const std::string& actorLabel,
                                             const std::string& tokenId,
                                             Role role,
                                             const std::string& sourceIp,
                                             uint64_t ttlMs) {
  const uint64_t now = nowEpochMs();
  // Prune expired sessions if map grows
  if (sessions_.size() > 64) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
      if (it->second.expiresAtMs <= now) it = sessions_.erase(it);
      else ++it;
    }
  }

  SessionInfo s;
  s.sessionId = generateRandomHex(32);
  s.csrfToken = generateRandomHex(24);
  s.actorLabel = actorLabel;
  s.tokenId = tokenId;
  s.sourceIp = sourceIp;
  s.role = role;
  s.createdAtMs = now;
  s.lastActivityMs = now;
  s.expiresAtMs = now + ttlMs;
  sessions_[s.sessionId] = s;
  return s;
}

std::string AuthManager::issueLocalLaunchNonce() {
  std::lock_guard lock(mutex_);
  const uint64_t now = nowEpochMs();
  for (auto it = launchNonces_.begin(); it != launchNonces_.end();) {
    if (it->second.expiresAtMs <= now) it = launchNonces_.erase(it);
    else ++it;
  }
  std::string nonce = generateRandomHex(24);
  launchNonces_[nonce] = PendingNonce{now + 90000}; // 90s single-use window
  return nonce;
}

std::optional<SessionInfo> AuthManager::exchangeLaunchNonce(const std::string& nonce,
                                                            const std::string& sourceIp) {
  if (nonce.empty() || !isLoopbackIp(sourceIp)) return std::nullopt;
  std::lock_guard lock(mutex_);
  auto it = launchNonces_.find(nonce);
  if (it == launchNonces_.end()) return std::nullopt;
  const uint64_t exp = it->second.expiresAtMs;
  launchNonces_.erase(it); // single-use
  if (exp <= nowEpochMs()) return std::nullopt;

  return createSessionLocked("local-desktop", "local-boot", Role::Administrator,
                             sourceIp, 12ULL * 3600ULL * 1000ULL);
}

std::optional<SessionInfo> AuthManager::loginWithToken(const std::string& rawToken,
                                                       const std::string& sourceIp,
                                                       uint64_t ttlMs) {
  std::lock_guard lock(mutex_);
  auto matched = verifyRawTokenLocked(trimAscii(rawToken));
  if (!matched.has_value()) return std::nullopt;

  const uint64_t now = nowEpochMs();
  for (auto& t : tokens_) {
    if (t.id == matched->id) {
      t.lastUsedMs = now;
      break;
    }
  }
  saveTokensLocked();
  return createSessionLocked(matched->label, matched->id, matched->role, sourceIp, ttlMs);
}

bool AuthManager::logoutSession(const std::string& sessionId) {
  if (sessionId.empty()) return false;
  std::lock_guard lock(mutex_);
  return sessions_.erase(sessionId) > 0;
}

void AuthManager::revokeAllSessions() {
  std::lock_guard lock(mutex_);
  sessions_.clear();
  wsTickets_.clear();
}

std::string AuthManager::extractBearerToken(const std::string& authHeader) {
  if (authHeader.size() < 8) return {};
  std::string prefix = authHeader.substr(0, 7);
  for (char& c : prefix) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  if (prefix == "bearer ") {
    return trimAscii(authHeader.substr(7));
  }
  return {};
}

std::string AuthManager::extractSessionCookie(const std::string& cookieHeader) {
  if (cookieHeader.empty()) return {};
  std::istringstream ss(cookieHeader);
  std::string part;
  while (std::getline(ss, part, ';')) {
    size_t eq = part.find('=');
    if (eq == std::string::npos) continue;
    std::string k = trimAscii(part.substr(0, eq));
    if (k == "np_session") {
      return trimAscii(part.substr(eq + 1));
    }
  }
  return {};
}

AuthContext AuthManager::authenticateHttp(const std::string& authHeader,
                                          const std::string& cookieHeader,
                                          const std::string& csrfHeader,
                                          bool isMutating) const {
  AuthContext ctx;
  const uint64_t now = nowEpochMs();

  std::string bearer = extractBearerToken(authHeader);
  if (!bearer.empty()) {
    std::lock_guard lock(mutex_);
    // Support either raw API token or active sessionId in Authorization: Bearer
    auto sIt = sessions_.find(bearer);
    if (sIt != sessions_.end() && sIt->second.expiresAtMs > now) {
      ctx.authenticated = true;
      ctx.viaCookie = false;
      ctx.csrfValid = true;
      ctx.role = sIt->second.role;
      ctx.actor = sIt->second.actorLabel;
      ctx.sessionId = sIt->second.sessionId;
      ctx.csrfToken = sIt->second.csrfToken;
      ctx.expiresAtMs = sIt->second.expiresAtMs;
      return ctx;
    }
    auto tok = verifyRawTokenLocked(bearer);
    if (tok.has_value()) {
      ctx.authenticated = true;
      ctx.viaCookie = false;
      ctx.csrfValid = true;
      ctx.role = tok->role;
      ctx.actor = tok->label;
      ctx.expiresAtMs = tok->expiresAtMs;
      return ctx;
    }
    return ctx;
  }

  std::string sid = extractSessionCookie(cookieHeader);
  if (!sid.empty()) {
    std::lock_guard lock(mutex_);
    auto sIt = sessions_.find(sid);
    if (sIt != sessions_.end() && sIt->second.expiresAtMs > now) {
      ctx.authenticated = true;
      ctx.viaCookie = true;
      ctx.role = sIt->second.role;
      ctx.actor = sIt->second.actorLabel;
      ctx.sessionId = sIt->second.sessionId;
      ctx.csrfToken = sIt->second.csrfToken;
      ctx.expiresAtMs = sIt->second.expiresAtMs;
      ctx.csrfValid = !isMutating || constantTimeEquals(trimAscii(csrfHeader), sIt->second.csrfToken);
      return ctx;
    }
  }

  return ctx;
}

std::string AuthManager::issueWsTicket(const AuthContext& ctx) {
  if (!ctx.authenticated) return {};
  std::lock_guard lock(mutex_);
  const uint64_t now = nowEpochMs();
  for (auto it = wsTickets_.begin(); it != wsTickets_.end();) {
    if (it->second.expiresAtMs <= now) it = wsTickets_.erase(it);
    else ++it;
  }
  std::string ticket = generateRandomHex(24);
  wsTickets_[ticket] = WsTicket{ctx, "", now + 30000};
  return ticket;
}

std::optional<AuthContext> AuthManager::authenticateWs(const std::string& authHeader,
                                                       const std::string& cookieHeader,
                                                       const std::string& queryTicket,
                                                       const std::string& sourceIp) {
  (void)sourceIp;
  if (!queryTicket.empty()) {
    std::lock_guard lock(mutex_);
    auto it = wsTickets_.find(queryTicket);
    if (it != wsTickets_.end()) {
      AuthContext ctx = it->second.ctx;
      uint64_t exp = it->second.expiresAtMs;
      wsTickets_.erase(it); // single-use
      if (exp > nowEpochMs()) {
        return ctx;
      }
    }
  }

  AuthContext ctx = authenticateHttp(authHeader, cookieHeader, "", false);
  if (ctx.authenticated) return ctx;
  return std::nullopt;
}

bool AuthManager::createApiToken(const std::string& label,
                                 Role role,
                                 uint64_t ttlMs,
                                 std::string& outRawToken,
                                 ApiTokenRecord& outRecord) {
  std::string cleanLabel = trimAscii(label);
  if (cleanLabel.empty() || cleanLabel.size() > 64) return false;

  const uint64_t now = nowEpochMs();
  const char* rolePrefix = (role == Role::Administrator) ? "np_adm_"
                         : (role == Role::Operator)      ? "np_opr_"
                                                         : "np_vwr_";
  outRawToken = std::string(rolePrefix) + generateRandomHex(24);

  ApiTokenRecord rec;
  std::lock_guard lock(mutex_);
  rec.id = "tok-" + std::to_string(nextTokenSeq_++);
  rec.label = cleanLabel;
  rec.prefix = outRawToken.substr(0, 12);
  rec.role = role;
  rec.saltHex = generateRandomHex(16);
  rec.hashHex = hashWithSalt(rec.saltHex, outRawToken);
  rec.createdAtMs = now;
  rec.expiresAtMs = (ttlMs > 0) ? (now + ttlMs) : 0;
  rec.revoked = false;

  tokens_.push_back(rec);
  saveTokensLocked();
  outRecord = rec;
  return true;
}

bool AuthManager::revokeApiToken(const std::string& tokenId) {
  std::lock_guard lock(mutex_);
  bool found = false;
  for (auto& t : tokens_) {
    if (t.id == tokenId && !t.revoked) {
      t.revoked = true;
      found = true;
      break;
    }
  }
  if (!found) return false;

  // Also kill active sessions created by this token
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    if (it->second.tokenId == tokenId) it = sessions_.erase(it);
    else ++it;
  }
  saveTokensLocked();
  return true;
}

std::string AuthManager::listTokensJson() const {
  std::lock_guard lock(mutex_);
  std::string out = "{\"tokens\":[";
  for (size_t i = 0; i < tokens_.size(); ++i) {
    const auto& t = tokens_[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    appendJsonEscaped(out, t.id);
    out += ",\"label\":";
    appendJsonEscaped(out, t.label);
    out += ",\"prefix\":";
    appendJsonEscaped(out, t.prefix);
    out += ",\"role\":\"";
    out += roleToString(t.role);
    out += "\",\"createdAt\":";
    out += std::to_string(t.createdAtMs);
    out += ",\"expiresAt\":";
    out += std::to_string(t.expiresAtMs);
    out += ",\"lastUsedAt\":";
    out += std::to_string(t.lastUsedMs);
    out += ",\"revoked\":";
    out += (t.revoked ? "true" : "false");
    out.push_back('}');
  }
  out += "]}";
  return out;
}

std::string AuthManager::initialBootstrapHintPath() const {
  return bootstrapHintPath_.string();
}

bool AuthManager::hasInitialBootstrapFile() const {
  std::error_code ec;
  return std::filesystem::exists(bootstrapHintPath_, ec);
}

} // namespace netpulse
