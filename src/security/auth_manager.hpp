#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace netpulse {

enum class Role : uint8_t {
  Viewer = 0,
  Operator = 1,
  Administrator = 2,
};

inline const char* roleToString(Role r) {
  switch (r) {
    case Role::Administrator: return "administrator";
    case Role::Operator: return "operator";
    default: return "viewer";
  }
}

inline bool parseRole(const std::string& s, Role& out) {
  if (s == "viewer") { out = Role::Viewer; return true; }
  if (s == "operator") { out = Role::Operator; return true; }
  if (s == "administrator" || s == "admin") { out = Role::Administrator; return true; }
  return false;
}

inline bool hasRole(Role actual, Role required) {
  return static_cast<uint8_t>(actual) >= static_cast<uint8_t>(required);
}

struct ApiTokenRecord {
  std::string id;
  std::string label;
  std::string prefix;
  Role role = Role::Viewer;
  std::string saltHex;
  std::string hashHex;
  uint64_t createdAtMs = 0;
  uint64_t expiresAtMs = 0; // 0 = never
  uint64_t lastUsedMs = 0;
  bool revoked = false;
};

struct SessionInfo {
  std::string sessionId;
  std::string csrfToken;
  std::string actorLabel;
  std::string tokenId;
  std::string sourceIp;
  Role role = Role::Viewer;
  uint64_t createdAtMs = 0;
  uint64_t expiresAtMs = 0;
  uint64_t lastActivityMs = 0;
};

struct AuthContext {
  bool authenticated = false;
  bool viaCookie = false;
  bool csrfValid = false;
  Role role = Role::Viewer;
  std::string actor;
  std::string sessionId;
  std::string csrfToken;
  uint64_t expiresAtMs = 0;
};

class AuthManager {
public:
  explicit AuthManager(std::filesystem::path dataDir, std::string envAdminToken = {});

  static std::string generateRandomHex(size_t numBytes);
  static std::string sha256Hex(const std::string& input);
  static bool constantTimeEquals(const std::string& a, const std::string& b);

  // Generates a single-use launch nonce for local desktop --app browser handoff.
  std::string issueLocalLaunchNonce();
  std::optional<SessionInfo> exchangeLaunchNonce(const std::string& nonce, const std::string& sourceIp);

  std::optional<SessionInfo> loginWithToken(const std::string& rawToken,
                                            const std::string& sourceIp,
                                            uint64_t ttlMs = 12ULL * 3600ULL * 1000ULL);
  bool logoutSession(const std::string& sessionId);
  void revokeAllSessions();

  AuthContext authenticateHttp(const std::string& authHeader,
                               const std::string& cookieHeader,
                               const std::string& csrfHeader,
                               bool isMutating) const;

  std::string issueWsTicket(const AuthContext& ctx);
  std::optional<AuthContext> authenticateWs(const std::string& authHeader,
                                            const std::string& cookieHeader,
                                            const std::string& queryTicket,
                                            const std::string& sourceIp);

  bool createApiToken(const std::string& label,
                      Role role,
                      uint64_t ttlMs,
                      std::string& outRawToken,
                      ApiTokenRecord& outRecord);
  bool revokeApiToken(const std::string& tokenId);
  std::string listTokensJson() const;
  std::string initialBootstrapHintPath() const;
  bool hasInitialBootstrapFile() const;

private:
  void ensureBootstrapAdminToken(const std::string& envAdminToken);
  void loadTokensLocked();
  void saveTokensLocked();
  std::optional<ApiTokenRecord> verifyRawTokenLocked(const std::string& rawToken) const;
  SessionInfo createSessionLocked(const std::string& actorLabel,
                                  const std::string& tokenId,
                                  Role role,
                                  const std::string& sourceIp,
                                  uint64_t ttlMs);
  static std::string extractSessionCookie(const std::string& cookieHeader);
  static std::string extractBearerToken(const std::string& authHeader);
  static std::string hashWithSalt(const std::string& saltHex, const std::string& secret);

  std::filesystem::path tokensPath_;
  std::filesystem::path bootstrapHintPath_;
  mutable std::mutex mutex_;
  std::vector<ApiTokenRecord> tokens_;
  std::unordered_map<std::string, SessionInfo> sessions_;
  struct PendingNonce {
    uint64_t expiresAtMs = 0;
  };
  std::unordered_map<std::string, PendingNonce> launchNonces_;
  struct WsTicket {
    AuthContext ctx;
    std::string sourceIp;
    uint64_t expiresAtMs = 0;
  };
  std::unordered_map<std::string, WsTicket> wsTickets_;
  uint64_t nextTokenSeq_ = 1;
};

} // namespace netpulse
