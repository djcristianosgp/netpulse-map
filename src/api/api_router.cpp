#include "api_router.hpp"
#include "prometheus_openapi.hpp"
#include "../actions.hpp"
#include "../models.hpp"
#include "../net_monitor.hpp"
#include "../tray_host.hpp"
#include "../version.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string sanitizeTsv(std::string s) {
  for (char& c : s) {
    if (c == '\t' || c == '\r' || c == '\n') c = ' ';
  }
  return s;
}

std::string buildSessionCookie(const std::string& sessionId, bool isTls, uint64_t maxAgeSec) {
  std::string c = "np_session=" + sessionId + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" +
                  std::to_string(maxAgeSec);
  if (isTls) c += "; Secure";
  return c;
}

std::string buildClearCookie(bool isTls) {
  std::string c = "np_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
  if (isTls) c += "; Secure";
  return c;
}

} // namespace

ApiRouter::ApiRouter(ApiDependencies deps)
    : deps_(std::move(deps)),
      blocksPath_(deps_.dataDir / "blocked_ips.tsv") {
  loadBlockedIps();
}

void ApiRouter::loadBlockedIps() {
  std::lock_guard lock(blocksMutex_);
  std::error_code ec;
  if (!std::filesystem::exists(blocksPath_, ec)) return;
  std::ifstream in(blocksPath_);
  if (!in.is_open()) return;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, '\t')) cols.push_back(item);
    if (cols.size() < 4) continue;
    BlockedIpEntry b;
    b.ip = cols[0];
    b.blockedAtMs = std::strtoull(cols[1].c_str(), nullptr, 10);
    b.actor = cols[2];
    b.auditId = std::strtoull(cols[3].c_str(), nullptr, 10);
    if (isValidIpAddress(b.ip)) blockedIps_.push_back(std::move(b));
  }
}

void ApiRouter::saveBlockedIps() {
  std::error_code ec;
  std::filesystem::create_directories(blocksPath_.parent_path(), ec);
  std::ofstream out(blocksPath_, std::ios::trunc);
  if (!out.is_open()) return;
  for (const auto& b : blockedIps_) {
    out << sanitizeTsv(b.ip) << '\t'
        << b.blockedAtMs << '\t'
        << sanitizeTsv(b.actor) << '\t'
        << b.auditId << '\n';
  }
}

std::string ApiRouter::listBlockedIpsJson() const {
  std::lock_guard lock(blocksMutex_);
  std::string out = "{\"blocks\":[";
  for (size_t i = 0; i < blockedIps_.size(); ++i) {
    const auto& b = blockedIps_[i];
    if (i > 0) out.push_back(',');
    out += "{\"ip\":";
    appendJsonEscaped(out, b.ip);
    out += ",\"blockedAt\":";
    out += std::to_string(b.blockedAtMs);
    out += ",\"actor\":";
    appendJsonEscaped(out, b.actor);
    out += ",\"auditId\":";
    out += std::to_string(b.auditId);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

HttpResponse ApiRouter::jsonError(int status, const std::string& code, const std::string& message) {
  HttpResponse r;
  r.statusCode = status;
  r.body = "{\"ok\":false,\"error\":";
  appendJsonEscaped(r.body, code);
  if (!message.empty()) {
    r.body += ",\"message\":";
    appendJsonEscaped(r.body, message);
  }
  r.body.push_back('}');
  return r;
}

std::string ApiRouter::normalizeApiPath(const std::string& rawPath) const {
  if (rawPath.rfind("/api/v1/", 0) == 0) {
    return "/api/" + rawPath.substr(8);
  }
  return rawPath;
}

HttpResponse ApiRouter::requireAuth(const HttpRequest& req,
                                    Role requiredRole,
                                    AuthContext& outAuth,
                                    const std::string& auditAction) {
  const bool isMutating = (req.method != "GET" && req.method != "HEAD");
  outAuth = deps_.auth.authenticateHttp(
      req.header("authorization"),
      req.header("cookie"),
      req.header("x-csrf-token"),
      isMutating);

  if (!outAuth.authenticated) {
    if (!auditAction.empty()) {
      deps_.audit.record("anonymous", "none", req.remoteIp, auditAction, req.path,
                         "denied", "Autenticacao ausente ou expirada");
    }
    return jsonError(401, "unauthorized", "Autenticacao obrigatoria");
  }

  if (!outAuth.csrfValid) {
    deps_.audit.record(outAuth.actor, roleToString(outAuth.role), req.remoteIp,
                       auditAction.empty() ? "security.csrf" : auditAction, req.path,
                       "denied", "Token CSRF ausente ou invalido");
    return jsonError(403, "csrf_invalid", "Cabecalho X-CSRF-Token ausente ou invalido");
  }

  if (!hasRole(outAuth.role, requiredRole)) {
    deps_.audit.record(outAuth.actor, roleToString(outAuth.role), req.remoteIp,
                       auditAction.empty() ? "security.rbac" : auditAction, req.path,
                       "denied", std::string("Requer nivel ") + roleToString(requiredRole));
    return jsonError(403, "forbidden", "Permissao insuficiente para esta operacao");
  }

  return HttpResponse{200, "application/json; charset=utf-8", "", {}};
}

WsAuthDecision ApiRouter::handleWsAuth(const HttpRequest& req) {
  WsAuthDecision dec;
  auto authOpt = deps_.auth.authenticateWs(
      req.header("authorization"),
      req.header("cookie"),
      req.queryParam("ticket"),
      req.remoteIp);
  if (!authOpt.has_value() || !authOpt->authenticated) {
    deps_.audit.record("anonymous", "none", req.remoteIp, "ws.connect", "/ws",
                       "denied", "WebSocket sem sessao ou ticket valido");
    dec.allowed = false;
    dec.httpStatus = 401;
    dec.errorBody = "{\"error\":\"unauthorized\"}";
    return dec;
  }
  dec.allowed = true;
  dec.httpStatus = 200;
  dec.auth = *authOpt;
  return dec;
}

HttpResponse ApiRouter::handleHttp(const HttpRequest& req) {
  const std::string path = normalizeApiPath(req.path);
  const std::string& method = req.method;

  // --- Public Auth Endpoints ---
  if (path == "/api/auth/session" && method == "GET") {
    AuthContext ctx = deps_.auth.authenticateHttp(
        req.header("authorization"), req.header("cookie"), "", false);
    HttpResponse resp;
    resp.statusCode = 200;
    resp.body = "{\"authenticated\":";
    resp.body += (ctx.authenticated ? "true" : "false");
    resp.body += ",\"role\":";
    appendJsonEscaped(resp.body, ctx.authenticated ? roleToString(ctx.role) : "none");
    resp.body += ",\"actor\":";
    appendJsonEscaped(resp.body, ctx.actor);
    resp.body += ",\"csrfToken\":";
    appendJsonEscaped(resp.body, ctx.csrfToken);
    resp.body += ",\"expiresAt\":";
    resp.body += std::to_string(ctx.expiresAtMs);
    resp.body += ",\"remoteAccess\":";
    resp.body += (deps_.remoteAccess ? "true" : "false");
    resp.body += ",\"tlsEnabled\":";
    resp.body += (deps_.tlsEnabled ? "true" : "false");
    resp.body += ",\"bootstrapFileAvailable\":";
    resp.body += (deps_.auth.hasInitialBootstrapFile() ? "true" : "false");
    resp.body.push_back('}');
    return resp;
  }

  if (path == "/api/auth/login" && method == "POST") {
    auto rl = deps_.authRateLimiter.check("login:" + req.remoteIp);
    if (!rl.allowed) {
      deps_.audit.record("anonymous", "none", req.remoteIp, "auth.login_blocked", "/api/auth/login",
                         "denied", "Bloqueio temporario por excesso de tentativas");
      HttpResponse resp = jsonError(429, "rate_limited", "Muitas tentativas de login");
      resp.extraHeaders.emplace_back("Retry-After", std::to_string(rl.retryAfterSec));
      return resp;
    }

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }

    std::string token = body.getString("token");
    auto sess = deps_.auth.loginWithToken(token, req.remoteIp);
    if (!sess.has_value()) {
      deps_.audit.record("anonymous", "none", req.remoteIp, "auth.login_failed", "/api/auth/login",
                         "denied", "Token invalido ou revogado");
      return jsonError(401, "invalid_credentials", "Token invalido ou expirado");
    }

    deps_.authRateLimiter.reset("login:" + req.remoteIp);
    deps_.audit.record(sess->actorLabel, roleToString(sess->role), req.remoteIp,
                       "auth.login", "session", "allowed", "Sessao iniciada via token");

    HttpResponse resp;
    resp.statusCode = 200;
    resp.extraHeaders.emplace_back("Set-Cookie", buildSessionCookie(sess->sessionId, req.isTls, 12 * 3600));
    resp.body = "{\"ok\":true,\"role\":\"";
    resp.body += roleToString(sess->role);
    resp.body += "\",\"actor\":";
    appendJsonEscaped(resp.body, sess->actorLabel);
    resp.body += ",\"csrfToken\":";
    appendJsonEscaped(resp.body, sess->csrfToken);
    resp.body += ",\"expiresAt\":";
    resp.body += std::to_string(sess->expiresAtMs);
    resp.body.push_back('}');
    return resp;
  }

  if (path == "/api/auth/exchange" && method == "POST") {
    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    std::string nonce = body.getString("nonce");
    auto sess = deps_.auth.exchangeLaunchNonce(nonce, req.remoteIp);
    if (!sess.has_value()) {
      deps_.audit.record("anonymous", "none", req.remoteIp, "auth.exchange_failed", "/api/auth/exchange",
                         "denied", "Nonce de inicializacao invalido ou expirado");
      return jsonError(401, "invalid_nonce", "Codigo de sessao local expirado ou invalido");
    }

    deps_.audit.record(sess->actorLabel, roleToString(sess->role), req.remoteIp,
                       "auth.login", "local-boot", "allowed", "Sessao local inicializada");

    HttpResponse resp;
    resp.statusCode = 200;
    resp.extraHeaders.emplace_back("Set-Cookie", buildSessionCookie(sess->sessionId, req.isTls, 12 * 3600));
    resp.body = "{\"ok\":true,\"role\":\"";
    resp.body += roleToString(sess->role);
    resp.body += "\",\"actor\":";
    appendJsonEscaped(resp.body, sess->actorLabel);
    resp.body += ",\"csrfToken\":";
    appendJsonEscaped(resp.body, sess->csrfToken);
    resp.body += ",\"expiresAt\":";
    resp.body += std::to_string(sess->expiresAtMs);
    resp.body.push_back('}');
    return resp;
  }

  // --- Authenticated Endpoints ---
  if (path == "/api/auth/logout" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth, "auth.logout");
    if (err.statusCode != 200) return err;

    deps_.auth.logoutSession(auth.sessionId);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "auth.logout", "session", "allowed", "Sessao encerrada");
    HttpResponse resp;
    resp.statusCode = 200;
    resp.extraHeaders.emplace_back("Set-Cookie", buildClearCookie(req.isTls));
    resp.body = "{\"ok\":true}";
    return resp;
  }

  if (path == "/api/auth/ws-ticket" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;

    std::string ticket = deps_.auth.issueWsTicket(auth);
    HttpResponse resp;
    resp.statusCode = 200;
    resp.body = "{\"ticket\":";
    appendJsonEscaped(resp.body, ticket);
    resp.body.push_back('}');
    return resp;
  }

  if (path == "/api/snapshot" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string snap = deps_.getLatestSnapshotJson ? deps_.getLatestSnapshotJson() : "{\"connections\":[]}";
    if (snap.empty()) snap = "{\"connections\":[]}";
    return HttpResponse{200, "application/json; charset=utf-8", std::move(snap), {}};
  }

  if (path == "/api/update/status" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.updater.getStatusJson(), {}};
  }

  if (path == "/api/update/check" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "update.check");
    if (err.statusCode != 200) return err;
    deps_.updater.checkNowAsync();
    return HttpResponse{202, "application/json; charset=utf-8", deps_.updater.getStatusJson(), {}};
  }

  if (path == "/api/update/apply" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "update.apply");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }

    bool started = deps_.updater.startInstallAsync();
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "update.apply", "installer", started ? "allowed" : "failed",
                       started ? "Instalacao iniciada" : "Nenhuma atualizacao pronta");
    return HttpResponse{started ? 202 : 409, "application/json; charset=utf-8", deps_.updater.getStatusJson(), {}};
  }

  if (path == "/api/services" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.services.getServicesJson(), {}};
  }

  if (path == "/api/services/probe" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth);
    if (err.statusCode != 200) return err;
    deps_.services.probeNowAsync();
    return HttpResponse{202, "application/json; charset=utf-8", deps_.services.getServicesJson(), {}};
  }

  if (path == "/api/services/add" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "service.added");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }

    std::string name = body.getString("name");
    std::string host = body.getString("host");
    int64_t portNum = body.getInt("port", 443);
    if (portNum <= 0 || portNum > 65535) {
      return jsonError(400, "invalid_port", "Porta deve estar entre 1 e 65535");
    }
    std::string cont = body.getString("continent", "GLOBAL");
    double lat = body.getDouble("lat", 0.0);
    double lon = body.getDouble("lon", 0.0);
    if (name.size() > 80 || host.size() > 160) {
      return jsonError(400, "invalid_service", "Nome ou host excede o tamanho permitido");
    }

    if (!deps_.services.addCustomService(name, host, static_cast<uint16_t>(portNum), cont, lat, lon)) {
      return jsonError(400, "invalid_service", "Dados de servico invalidos");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "service.added", host + ":" + std::to_string(portNum), "allowed", name);
    return HttpResponse{201, "application/json; charset=utf-8", deps_.services.getServicesJson(), {}};
  }

  if (path == "/api/services/remove" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "service.removed");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    std::string id = body.getString("id");
    if (id.empty()) return jsonError(400, "invalid_id");
    if (!deps_.services.removeCustomService(id)) {
      return jsonError(404, "not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "service.removed", id, "allowed", "Servico customizado removido");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.services.getServicesJson(), {}};
  }

  if (path == "/api/trace/start" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "trace.started");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    std::string ip = body.getString("ip");
    std::string label = body.getString("label");
    if (!isValidIpAddress(ip) || !deps_.tracer.startTrace(ip, label)) {
      return jsonError(400, "invalid_ip");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "trace.started", ip, "allowed", "Traceroute ICMP iniciado");
    return HttpResponse{202, "application/json; charset=utf-8", deps_.tracer.getStatusJson(), {}};
  }

  if (path == "/api/trace/status" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.tracer.getStatusJson(), {}};
  }

  if (path == "/api/trace/history" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string targetIp = req.queryParam("targetIp");
    int lim = std::atoi(req.queryParam("limit").c_str());
    size_t limit = lim > 0 ? static_cast<size_t>(std::clamp(lim, 1, 100)) : 30;
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.tracer.getHistoryJson(targetIp, limit), {}};
  }

  if (path == "/api/trace/diff" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    int64_t runA = std::strtoll(req.queryParam("runA").c_str(), nullptr, 10);
    int64_t runB = std::strtoll(req.queryParam("runB").c_str(), nullptr, 10);
    std::string targetIp = req.queryParam("targetIp");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.tracer.getDiffJson(runA, runB, targetIp), {}};
  }

  if (path == "/api/trace/monitors" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.tracer.getMonitorsJson(), {}};
  }

  if (path == "/api/trace/monitors" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "trace.monitor_upserted");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string ip = body.getString("targetIp");
    const std::string label = body.getString("label");
    const int intervalSec = static_cast<int>(std::clamp<int64_t>(body.getInt("intervalSec", 300), 30, 3600));
    const bool enabled = body.getBool("enabled", true);
    if (!isValidIpAddress(ip) || !deps_.tracer.upsertMonitor(ip, label, intervalSec, enabled)) {
      return jsonError(400, "invalid_ip");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "trace.monitor_upserted", ip, "allowed",
                       std::string(enabled ? "enabled" : "paused") + ", interval=" + std::to_string(intervalSec) + "s");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.tracer.getMonitorsJson(), {}};
  }

  if ((path == "/api/trace/monitors/delete" && method == "POST") ||
      (path == "/api/trace/monitors" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "trace.monitor_removed");
    if (err.statusCode != 200) return err;

    std::string ip;
    bool confirmed = false;
    if (method == "DELETE") {
      ip = req.queryParam("targetIp");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      ip = body.getString("targetIp");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (!isValidIpAddress(ip) || !deps_.tracer.removeMonitor(ip)) {
      return jsonError(404, "monitor_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "trace.monitor_removed", ip, "allowed", "Monitoramento de rota removido");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.tracer.getMonitorsJson(), {}};
  }

  if (path == "/api/history/events" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    size_t limit = static_cast<size_t>(std::clamp(std::atoi(req.queryParam("limit").c_str()), 0, 500));
    if (limit == 0) limit = 150;
    size_t offset = static_cast<size_t>(std::max(0, std::atoi(req.queryParam("offset").c_str())));
    std::string sev = req.queryParam("severity");
    std::string kind = req.queryParam("kind");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.getEventsJson(limit, offset, sev, kind), {}};
  }

  if (path == "/api/history/connections" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;

    ConnectionQuery q;
    int lim = std::atoi(req.queryParam("limit").c_str());
    q.limit = (lim > 0) ? static_cast<size_t>(std::clamp(lim, 1, 250)) : 50;
    int off = std::atoi(req.queryParam("offset").c_str());
    q.offset = (off > 0) ? static_cast<size_t>(off) : 0;
    q.process = req.queryParam("process");
    q.remoteIp = req.queryParam("remoteIp");
    q.country = req.queryParam("country");
    q.protocol = req.queryParam("protocol");
    q.scope = req.queryParam("scope");
    q.search = req.queryParam("q");
    q.fromMs = std::strtoull(req.queryParam("fromMs").c_str(), nullptr, 10);
    q.toMs = std::strtoull(req.queryParam("toMs").c_str(), nullptr, 10);
    return HttpResponse{200, "application/json; charset=utf-8", deps_.history.queryConnectionsJson(q), {}};
  }

  if (path == "/api/history/processes" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string range = req.queryParam("range");
    if (range.empty()) range = "7d";
    int lim = std::atoi(req.queryParam("limit").c_str());
    size_t limit = (lim > 0) ? static_cast<size_t>(std::clamp(lim, 1, 200)) : 50;
    int off = std::atoi(req.queryParam("offset").c_str());
    size_t offset = (off > 0) ? static_cast<size_t>(off) : 0;
    std::string proc = req.queryParam("process");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.queryProcessesJson(range, limit, offset, proc), {}};
  }

  if (path == "/api/history/analytics" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string range = req.queryParam("range");
    if (range.empty()) range = "7d";
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.queryAnalyticsJson(range), {}};
  }

  if (path == "/api/history/storage" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.getStorageStatsJson(), {}};
  }

  if (path == "/api/history/prune" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "history.prune");
    if (err.statusCode != 200) return err;
    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    bool ok = deps_.history.pruneNow();
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "history.prune", "netpulse.db", ok ? "allowed" : "failed",
                       "Limpeza de retencao e vacuum executados");
    return HttpResponse{ok ? 200 : 500, "application/json; charset=utf-8",
                        deps_.history.getStorageStatsJson(), {}};
  }

  if (path == "/api/history/service" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    std::string id = body.getString("id");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.history.getServiceHistoryJson(id, 60), {}};
  }

  // ---- Fase 2: Network Quality Engine ----
  if (path == "/api/quality/status" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.quality->getStatusJson(), {}};
  }

  if (path == "/api/quality/history" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string targetId = req.queryParam("targetId");
    if (targetId.empty()) targetId = req.queryParam("id");
    std::string range = req.queryParam("range");
    if (range.empty()) range = "1h";
    if (targetId.empty()) return jsonError(400, "missing_target_id");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.queryQualityHistoryJson(targetId, range), {}};
  }

  if (path == "/api/quality/probe" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "quality.probe");
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");
    deps_.quality->probeNowAsync();
    return HttpResponse{202, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  if (path == "/api/quality/rediscover" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "quality.rediscover");
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");
    deps_.quality->rediscoverInfra();
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "quality.rediscover", "infra", "allowed", "Redescoberta de gateway e DNS");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.quality->getStatusJson(), {}};
  }

  if (path == "/api/quality/targets" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "quality.target_added");
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string name = body.getString("name");
    const std::string host = body.getString("host");
    const uint16_t port = static_cast<uint16_t>(std::clamp<int64_t>(body.getInt("port", 0), 0, 65535));
    const std::string category = body.getString("category", "custom");
    const std::string probeMode = body.getString("probeMode", "icmp");
    const int intervalSec = static_cast<int>(std::clamp<int64_t>(body.getInt("intervalSec", 10), 5, 300));

    std::string newId, addErr;
    if (!deps_.quality->addTarget(name, host, port, category, probeMode, intervalSec, newId, addErr)) {
      return jsonError(400, "invalid_target", addErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "quality.target_added", newId, "allowed", host + " (" + probeMode + ")");
    return HttpResponse{201, "application/json; charset=utf-8",
                        deps_.quality->getStatusJson(), {}};
  }

  if (path == "/api/quality/targets/update" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "quality.target_updated");
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string id = body.getString("id");
    const std::string name = body.getString("name");
    const uint16_t port = static_cast<uint16_t>(std::clamp<int64_t>(body.getInt("port", 0), 0, 65535));
    const std::string probeMode = body.getString("probeMode");
    const int intervalSec = static_cast<int>(std::clamp<int64_t>(body.getInt("intervalSec", 10), 5, 300));
    const bool enabled = body.getBool("enabled", true);

    std::string updErr;
    if (!deps_.quality->updateTarget(id, name, port, probeMode, intervalSec, enabled, updErr)) {
      return jsonError(404, "target_not_found", updErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "quality.target_updated", id, "allowed",
                       std::string(enabled ? "enabled" : "paused") + ", interval=" + std::to_string(intervalSec) + "s");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.quality->getStatusJson(), {}};
  }

  if ((path == "/api/quality/targets/delete" && method == "POST") ||
      (path == "/api/quality/targets" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "quality.target_removed");
    if (err.statusCode != 200) return err;
    if (!deps_.quality) return jsonError(503, "quality_unavailable");

    std::string id;
    bool confirmed = false;
    if (method == "DELETE") {
      id = req.queryParam("id");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      id = body.getString("id");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (id.empty() || !deps_.quality->removeTarget(id)) {
      return jsonError(404, "target_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "quality.target_removed", id, "allowed", "Alvo removido");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.quality->getStatusJson(), {}};
  }

  // ---- Fase 4: Multi-WAN & Network Interfaces ----
  if (path == "/api/interfaces" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.interfaces) return jsonError(503, "interfaces_unavailable");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.interfaces->getSnapshotJson(), {}};
  }

  if (path == "/api/interfaces/history" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    std::string id = req.queryParam("id");
    std::string range = req.queryParam("range");
    if (range.empty()) range = "1h";
    if (id.empty()) return jsonError(400, "missing_interface_id");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.history.queryInterfaceHistoryJson(id, range), {}};
  }

  if (path == "/api/interfaces/refresh" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "interfaces.refresh");
    if (err.statusCode != 200) return err;
    if (!deps_.interfaces) return jsonError(503, "interfaces_unavailable");
    deps_.interfaces->collect(nowEpochMs());
    return HttpResponse{200, "application/json; charset=utf-8", deps_.interfaces->getSnapshotJson(), {}};
  }

  // ---- Fase 5: Discovery Engine ----
  if (path == "/api/discovery/devices" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.discovery) return jsonError(503, "discovery_unavailable");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.discovery->getDevicesJson(), {}};
  }

  if (path == "/api/discovery/scan" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "discovery.scan");
    if (err.statusCode != 200) return err;
    if (!deps_.discovery) return jsonError(503, "discovery_unavailable");

    std::string subnet;
    if (!req.body.empty()) {
      JsonValue body;
      std::string parseErr;
      if (JsonValue::parse(req.body, body, parseErr) && body.isObject()) {
        subnet = body.getString("subnet");
      }
    }
    const bool started = deps_.discovery->triggerScanAsync(subnet);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "discovery.scan", subnet.empty() ? "auto" : subnet,
                       started ? "allowed" : "conflict",
                       started ? "Varredura LAN iniciada" : "Varredura ja em andamento");
    return HttpResponse{started ? 202 : 200, "application/json; charset=utf-8",
                        deps_.discovery->getDevicesJson(), {}};
  }

  if (path == "/api/discovery/label" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "discovery.label");
    if (err.statusCode != 200) return err;
    if (!deps_.discovery) return jsonError(503, "discovery_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string key = body.getString("deviceKey");
    const std::string label = body.getString("label");
    if (key.empty() || !deps_.discovery->setDeviceLabel(key, label)) {
      return jsonError(404, "device_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "discovery.label", key, "allowed", label);
    return HttpResponse{200, "application/json; charset=utf-8", deps_.discovery->getDevicesJson(), {}};
  }

  if ((path == "/api/discovery/devices/delete" && method == "POST") ||
      (path == "/api/discovery/devices" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "discovery.device_removed");
    if (err.statusCode != 200) return err;
    if (!deps_.discovery) return jsonError(503, "discovery_unavailable");

    std::string key;
    bool confirmed = false;
    if (method == "DELETE") {
      key = req.queryParam("key");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      key = body.getString("deviceKey");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (key.empty() || !deps_.discovery->removeDevice(key)) {
      return jsonError(404, "device_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "discovery.device_removed", key, "allowed", "Dispositivo removido do inventario");
    return HttpResponse{200, "application/json; charset=utf-8", deps_.discovery->getDevicesJson(), {}};
  }

  // ---- Fase 6: LAN Topology Map ----
  if (path == "/api/topology/lan" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (deps_.getLanTopologyJson) {
      return HttpResponse{200, "application/json; charset=utf-8", deps_.getLanTopologyJson(), {}};
    }
    if (!deps_.interfaces || !deps_.discovery) {
      return jsonError(503, "topology_unavailable");
    }
    std::vector<QualityTargetSnapshot> qSnaps;
    if (deps_.quality) qSnaps = deps_.quality->getTargetsSnapshot();
    auto topo = buildLanTopology(nowEpochMs(),
                                 "",
                                 deps_.interfaces->getSnapshot(),
                                 deps_.discovery->getDevicesSnapshot(),
                                 qSnaps,
                                 nullptr);
    return HttpResponse{200, "application/json; charset=utf-8", serializeLanTopologyJson(topo), {}};
  }

  // ---- Fase 7: Deterministic Intelligence & Security Engine ----
  if (path == "/api/intelligence/overview" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");
    size_t limit = 120;
    const std::string limitStr = req.queryParam("limit");
    if (!limitStr.empty()) {
      const long long v = std::strtoll(limitStr.c_str(), nullptr, 10);
      if (v > 0 && v <= 500) limit = static_cast<size_t>(v);
    }
    const std::string level = req.queryParam("level");
    const std::string unackParam = req.queryParam("unackOnly");
    const bool unackOnly = (unackParam == "true" || unackParam == "1");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(limit, level, unackOnly), {}};
  }

  if (path == "/api/intelligence/ack" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "intelligence.ack");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const int64_t alertId = body.getInt("alertId", 0);
    if (alertId <= 0 || !deps_.intelligence->acknowledgeAlert(alertId)) {
      return jsonError(404, "alert_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "intelligence.ack", std::to_string(alertId), "allowed", "Alerta reconhecido");
    return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  if (path == "/api/intelligence/rules" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "intelligence.rule_saved");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    SecurityRuleRecord rule;
    rule.id = body.getString("id");
    rule.name = body.getString("name");
    rule.kind = body.getString("kind");
    rule.enabled = body.getBool("enabled", true);
    rule.riskWeight = static_cast<int>(body.getInt("riskWeight", 30));
    rule.thresholdNum = body.getDouble("thresholdNum", 0.0);
    rule.matchCountry = body.getString("matchCountry");
    const int64_t portVal = body.getInt("matchPort", 0);
    if (portVal < 0 || portVal > 65535) {
      return jsonError(400, "invalid_port", "matchPort fora de 0..65535");
    }
    rule.matchPort = static_cast<uint16_t>(portVal);
    rule.matchProcess = body.getString("matchProcess");
    rule.description = body.getString("description");
    rule.isBuiltin = false;

    if (!deps_.intelligence->upsertRule(rule)) {
      return jsonError(400, "invalid_rule", "Campos name e kind obrigatorios");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "intelligence.rule_saved", rule.id, "allowed",
                       rule.name + " (" + rule.kind + ")");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  if ((path == "/api/intelligence/rules/delete" && method == "POST") ||
      (path == "/api/intelligence/rules" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "intelligence.rule_deleted");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    std::string id;
    bool confirmed = false;
    if (method == "DELETE") {
      id = req.queryParam("id");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      id = body.getString("id");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (id.empty() || !deps_.intelligence->deleteRule(id)) {
      return jsonError(400, "rule_delete_failed", "Regra inexistente ou builtin protegida");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "intelligence.rule_deleted", id, "allowed", "Regra personalizada removida");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  if (path == "/api/security/lists" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "security.list_added");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string listKind = body.getString("listKind");
    const std::string targetType = body.getString("targetType");
    const std::string targetValue = body.getString("targetValue");
    const std::string reason = body.getString("reason");

    SecurityListEntry created;
    std::string actErr;
    if (!deps_.intelligence->addListEntry(listKind, targetType, targetValue, reason, auth.actor, created, actErr)) {
      return jsonError(400, "invalid_list_entry", actErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "security.list_added", listKind + ":" + targetType + ":" + targetValue,
                       "allowed", reason, true);
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  if ((path == "/api/security/lists/delete" && method == "POST") ||
      (path == "/api/security/lists" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "security.list_removed");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    std::string id;
    bool confirmed = false;
    if (method == "DELETE") {
      id = req.queryParam("id");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      id = body.getString("id");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (id.empty() || !deps_.intelligence->removeListEntry(id)) {
      return jsonError(404, "list_entry_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "security.list_removed", id, "allowed", "Entrada removida da allowlist/blocklist");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  if (path == "/api/security/firewall" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "security.firewall_created");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    if (!body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    const std::string ruleName = body.getString("ruleName");
    const std::string direction = body.getString("direction", "out");
    const std::string action = body.getString("action", "block");
    const std::string protocol = body.getString("protocol", "ANY");
    const std::string remoteIp = body.getString("remoteIp");
    const int64_t portVal = body.getInt("remotePort", 0);
    if (portVal < 0 || portVal > 65535) {
      return jsonError(400, "invalid_port", "remotePort fora de 0..65535");
    }
    const uint16_t remotePort = static_cast<uint16_t>(portVal);
    const std::string programPath = body.getString("programPath");
    const bool applyToOs = body.getBool("applyToOs", false);

    FirewallRuleRecord created;
    std::string actErr;
    if (!deps_.intelligence->createFirewallRule(ruleName, direction, action, protocol, remoteIp, remotePort,
                                                programPath, applyToOs, netpulse::isProcessElevated(),
                                                auth.actor, created, actErr)) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "security.firewall_created", ruleName, "failed", actErr);
      return jsonError(400, "firewall_rule_failed", actErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "security.firewall_created", created.ruleName, "allowed",
                       action + " " + direction + " " + protocol + (applyToOs ? " [OS aplicado]" : " [politica salva]"),
                       true);
    deps_.history.recordManualAction("warn", "Regra Firewall criada", created.ruleName);
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  if ((path == "/api/security/firewall/delete" && method == "POST") ||
      (path == "/api/security/firewall" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "security.firewall_removed");
    if (err.statusCode != 200) return err;
    if (!deps_.intelligence) return jsonError(503, "intelligence_unavailable");

    std::string id;
    bool confirmed = false;
    if (method == "DELETE") {
      id = req.queryParam("id");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      id = body.getString("id");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    std::string actErr;
    if (id.empty() || !deps_.intelligence->removeFirewallRuleById(id, netpulse::isProcessElevated(), actErr)) {
      return jsonError(400, "firewall_remove_failed", actErr.empty() ? "Regra nao encontrada" : actErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "security.firewall_removed", id, "allowed", "Regra de firewall removida/revertida");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.intelligence->getOverviewJson(), {}};
  }

  // ---- Fase 8: Dashboard Analytics & Modo NOC (Somente Leitura) ----
  if (path == "/api/noc/overview" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;

    std::string range = req.queryParam("range");
    if (range != "24h" && range != "7d" && range != "30d") {
      range = "24h";
    }

    const std::string snapJson = deps_.getLatestSnapshotJson ? deps_.getLatestSnapshotJson() : "";
    const std::string qualJson = deps_.quality ? deps_.quality->getStatusJson() : "";
    const std::string ifaceJson = deps_.interfaces ? deps_.interfaces->getSnapshotJson() : "";
    const std::string discJson = deps_.discovery ? deps_.discovery->getDevicesJson() : "";
    const std::string intelJson = deps_.intelligence ? deps_.intelligence->getOverviewJson(12, "", false) : "";
    const std::string svcJson = deps_.services.getServicesJson();
    const std::string anaJson = deps_.history.queryAnalyticsJson(range);
    const std::string storJson = deps_.history.getStorageStatsJson();
    const std::string traceJson = deps_.history.queryTraceHistoryJson("", 6);

    std::string out = "{\"mode\":\"noc_readonly\",\"readOnly\":true,\"engineMode\":\"deterministic\",\"aiUsed\":false";
    out += ",\"version\":"; appendJsonEscaped(out, kAppVersion);
    out += ",\"tsMs\":" + std::to_string(nowEpochMs());
    out += ",\"range\":"; appendJsonEscaped(out, range);
    out += ",\"snapshot\":" + (snapJson.empty() ? "null" : snapJson);
    out += ",\"quality\":" + (qualJson.empty() ? "null" : qualJson);
    out += ",\"interfaces\":" + (ifaceJson.empty() ? "null" : ifaceJson);
    out += ",\"discovery\":" + (discJson.empty() ? "null" : discJson);
    out += ",\"intelligence\":" + (intelJson.empty() ? "null" : intelJson);
    out += ",\"services\":" + (svcJson.empty() ? "[]" : svcJson);
    out += ",\"analytics\":" + (anaJson.empty() ? "null" : anaJson);
    out += ",\"storage\":" + (storJson.empty() ? "null" : storJson);
    out += ",\"traceHistory\":" + (traceJson.empty() ? "null" : traceJson);
    out += "}";
    return HttpResponse{200, "application/json; charset=utf-8", std::move(out), {}};
  }

  // ---- Fase 9: Prometheus /metrics, OpenAPI v1 & Notifications ----
  if ((path == "/metrics" || path == "/api/metrics") && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "text/plain; version=0.0.4; charset=utf-8",
                        formatPrometheusMetrics(deps_), {}};
  }

  if (path == "/api/openapi.json" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8",
                        buildOpenApiV1SpecJson(kAppVersion), {}};
  }

  if (path == "/api/notifications/channels" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.notifications) return jsonError(503, "notifications_unavailable");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.notifications->getChannelsJson(), {}};
  }

  if ((path == "/api/notifications/channels" || path == "/api/notifications/channels/save") &&
      method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "notifications.channel_saved");
    if (err.statusCode != 200) return err;
    if (!deps_.notifications) return jsonError(503, "notifications_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }

    NotificationChannelRecord ch;
    ch.id = body.getString("id");
    ch.name = body.getString("name");
    ch.kind = body.getString("kind", "webhook");
    ch.enabled = body.getBool("enabled", true);
    ch.endpointUrl = body.getString("endpointUrl");
    ch.secretOrToken = body.getString("secretOrToken");
    ch.chatId = body.getString("chatId");
    ch.minSeverity = body.getString("minSeverity", "warn");
    ch.categoriesCsv = body.getString("categoriesCsv");
    ch.cooldownSec = static_cast<int>(body.getInt("cooldownSec", 60));

    NotificationChannelRecord saved;
    std::string actErr;
    if (!deps_.notifications->upsertChannel(ch, saved, actErr)) {
      return jsonError(400, "invalid_notification_channel", actErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "notifications.channel_saved", saved.id, "allowed",
                       saved.name + " (" + saved.kind + ")");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.notifications->getChannelsJson(), {}};
  }

  if ((path == "/api/notifications/channels/delete" && method == "POST") ||
      (path == "/api/notifications/channels" && method == "DELETE")) {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "notifications.channel_removed");
    if (err.statusCode != 200) return err;
    if (!deps_.notifications) return jsonError(503, "notifications_unavailable");

    std::string id;
    bool confirmed = false;
    if (method == "DELETE") {
      id = req.queryParam("id");
      confirmed = (req.queryParam("confirm") == "true" || req.queryParam("confirm") == "1");
    } else {
      JsonValue body;
      std::string parseErr;
      if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
        return jsonError(400, "invalid_json", parseErr);
      }
      id = body.getString("id");
      confirmed = body.getBool("confirm", false);
    }
    if (!confirmed) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (id.empty() || !deps_.notifications->deleteChannel(id)) {
      return jsonError(404, "channel_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "notifications.channel_removed", id, "allowed", "Canal externo removido");
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.notifications->getChannelsJson(), {}};
  }

  if (path == "/api/notifications/test" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "notifications.test");
    if (err.statusCode != 200) return err;
    if (!deps_.notifications) return jsonError(503, "notifications_unavailable");

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    const std::string id = body.getString("id");
    std::string actErr;
    const bool ok = deps_.notifications->sendTestNotification(id, actErr);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "notifications.test", id, ok ? "allowed" : "failed",
                       ok ? "Notificacao de teste enviada" : actErr);
    if (!ok) {
      return jsonError(400, "notification_delivery_failed", actErr);
    }
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.notifications->getDeliveriesJson(40), {}};
  }

  if (path == "/api/notifications/deliveries" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.notifications) return jsonError(503, "notifications_unavailable");
    size_t limit = 80;
    const std::string limitStr = req.queryParam("limit");
    if (!limitStr.empty()) {
      const long long v = std::strtoll(limitStr.c_str(), nullptr, 10);
      if (v > 0 && v <= 500) limit = static_cast<size_t>(v);
    }
    return HttpResponse{200, "application/json; charset=utf-8",
                        deps_.notifications->getDeliveriesJson(limit), {}};
  }

  if (path == "/api/alerts/toggle" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "alerts.toggled");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject() || !body.get("enabled")) {
      return jsonError(400, "invalid_payload");
    }
    bool next = body.getBool("enabled", true);
    deps_.history.setAlertsEnabled(next);
    auto cfg = deps_.settings.get();
    cfg.alertsEnabled = next;
    std::string serr;
    deps_.settings.update(cfg, serr);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "alerts.toggled", "alertsEnabled", "allowed", next ? "enabled" : "disabled");
    return HttpResponse{200, "application/json; charset=utf-8",
                        std::string("{\"alertsEnabled\":") + (next ? "true" : "false") + "}", {}};
  }

  if (path == "/api/settings" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.settings.toJson(), {}};
  }

  if (path == "/api/settings" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "settings.updated");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }

    auto nextCfg = deps_.settings.get();
    nextCfg.alertsEnabled = body.getBool("alertsEnabled", nextCfg.alertsEnabled);
    nextCfg.notifyServiceDown = body.getBool("notifyServiceDown", nextCfg.notifyServiceDown);
    nextCfg.notifyServiceDegraded = body.getBool("notifyServiceDegraded", nextCfg.notifyServiceDegraded);
    nextCfg.notifySensitivePort = body.getBool("notifySensitivePort", nextCfg.notifySensitivePort);
    nextCfg.notifyNewCountry = body.getBool("notifyNewCountry", nextCfg.notifyNewCountry);
    nextCfg.autoStart = body.getBool("autoStart", nextCfg.autoStart);
    std::string sView = body.getString("defaultView", nextCfg.defaultView);
    if (sView != "local" && sView != "global") {
      return jsonError(400, "invalid_default_view");
    }
    nextCfg.defaultView = sView;
    nextCfg.minimizeToTray = body.getBool("minimizeToTray", nextCfg.minimizeToTray);
    int64_t retDays = body.getInt("retentionDays", nextCfg.retentionDays);
    if (retDays < 1 || retDays > 365) {
      return jsonError(400, "invalid_retention_days", "retentionDays deve estar entre 1 e 365");
    }
    nextCfg.retentionDays = static_cast<int>(retDays);
    int64_t maxDbMb = body.getInt("maxDbSizeMb", nextCfg.maxDbSizeMb);
    if (maxDbMb < 32 || maxDbMb > 2048) {
      return jsonError(400, "invalid_max_db_size", "maxDbSizeMb deve estar entre 32 e 2048");
    }
    nextCfg.maxDbSizeMb = static_cast<int>(maxDbMb);

    std::string serr;
    if (!deps_.settings.update(nextCfg, serr)) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "settings.updated", "settings", "failed", serr);
      return jsonError(400, "settings_update_failed", serr);
    }
    if (deps_.onSettingsApplied) deps_.onSettingsApplied(nextCfg);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "settings.updated", "settings", "allowed",
                       "alerts=" + std::string(nextCfg.alertsEnabled ? "1" : "0") +
                       ", view=" + nextCfg.defaultView);
    return HttpResponse{200, "application/json; charset=utf-8", deps_.settings.toJson(), {}};
  }

  if (path == "/api/window/minimize-tray" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth);
    if (err.statusCode != 200) return err;
    bool ok = netpulse::minimizeMapWindowToTray();
    return HttpResponse{ok ? 200 : 409, "application/json; charset=utf-8",
                        std::string("{\"ok\":") + (ok ? "true" : "false") + "}", {}};
  }

  if (path == "/api/action/kill-process" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "process.terminate");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    if (!body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    int64_t pidVal = body.getInt("pid", -1);
    std::string proc = body.getString("proc");
    if (pidVal <= 0 || pidVal > 0xFFFFFFFFLL) {
      return jsonError(400, "invalid_pid");
    }

    uint32_t pid = static_cast<uint32_t>(pidVal);
    std::string actErr;
    if (!netpulse::terminateTargetProcess(pid, proc, actErr)) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "process.terminate", proc + "#" + std::to_string(pid), "failed", actErr);
      return jsonError(400, "terminate_failed", actErr);
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "process.terminate", proc + "#" + std::to_string(pid), "allowed", "Processo encerrado");
    deps_.history.recordManualAction("warn", "Processo encerrado", proc + " (PID " + std::to_string(pid) + ")");
    return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  if (path == "/api/action/block-ip" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "firewall.block_ip");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    if (!body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    std::string ip = body.getString("ip");
    if (!isValidIpAddress(ip) || isLoopbackOrUnspecifiedIp(ip)) {
      return jsonError(400, "invalid_ip", "Endereco IP invalido ou protegido");
    }

    std::string actErr;
    if (!netpulse::blockIpInWindowsFirewall(ip, netpulse::isProcessElevated(), actErr)) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "firewall.block_ip", ip, "failed", actErr);
      return jsonError(400, "firewall_block_failed", actErr);
    }

    uint64_t auditId = deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                                          "firewall.block_ip", ip, "allowed",
                                          "Regra de bloqueio de saida aplicada", true);
    {
      std::lock_guard lock(blocksMutex_);
      auto it = std::find_if(blockedIps_.begin(), blockedIps_.end(),
                             [&](const BlockedIpEntry& b) { return b.ip == ip; });
      if (it == blockedIps_.end()) {
        blockedIps_.push_back(BlockedIpEntry{ip, nowEpochMs(), auth.actor, auditId});
        saveBlockedIps();
      }
    }
    deps_.history.recordManualAction("warn", "IP bloqueado no Firewall", ip);
    return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  if (path == "/api/action/unblock-ip" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "firewall.unblock_ip");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    if (!body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    std::string ip = body.getString("ip");
    if (!isValidIpAddress(ip) || isLoopbackOrUnspecifiedIp(ip)) {
      return jsonError(400, "invalid_ip", "Endereco IP invalido ou protegido");
    }

    std::string actErr;
    if (!netpulse::unblockIpInWindowsFirewall(ip, netpulse::isProcessElevated(), actErr)) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "firewall.unblock_ip", ip, "failed", actErr);
      return jsonError(400, "firewall_unblock_failed", actErr);
    }

    deps_.audit.markTargetReverted("firewall.block_ip", ip);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "firewall.unblock_ip", ip, "allowed", "Regra de firewall revertida");
    {
      std::lock_guard lock(blocksMutex_);
      auto it = std::remove_if(blockedIps_.begin(), blockedIps_.end(),
                               [&](const BlockedIpEntry& b) { return b.ip == ip; });
      if (it != blockedIps_.end()) {
        blockedIps_.erase(it, blockedIps_.end());
        saveBlockedIps();
      }
    }
    deps_.history.recordManualAction("info", "Bloqueio de IP revertido", ip);
    return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  if (path == "/api/elevate" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "security.elevate");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.getBool("confirm", false)) {
      return jsonError(400, "confirmation_required", "Confirmacao explicita obrigatoria");
    }
    if (netpulse::isProcessElevated()) {
      return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true,\"alreadyElevated\":true}", {}};
    }
    if (!netpulse::relaunchAsAdministrator()) {
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "security.elevate", "uac", "failed", "Elevacao UAC cancelada");
      return jsonError(400, "elevation_cancelled", "Elevacao UAC cancelada");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "security.elevate", "uac", "allowed", "Reiniciando como Administrador");
    if (deps_.onRequestRestart) deps_.onRequestRestart();
    return HttpResponse{202, "application/json; charset=utf-8", "{\"ok\":true,\"restarting\":true}", {}};
  }

  if (path == "/api/security/audit" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.audit.toJson(200), {}};
  }

  if (path == "/api/security/blocks" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", listBlockedIpsJson(), {}};
  }

  if (path == "/api/auth/tokens" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.auth.listTokensJson(), {}};
  }

  if (path == "/api/auth/tokens" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "auth.token_created");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    std::string label = body.getString("label");
    std::string roleStr = body.getString("role", "viewer");
    int64_t ttlHours = body.getInt("ttlHours", 0);
    Role targetRole = Role::Viewer;
    if (!parseRole(roleStr, targetRole)) {
      return jsonError(400, "invalid_role", "Roles validos: viewer, operator, administrator");
    }
    uint64_t ttlMs = (ttlHours > 0) ? (static_cast<uint64_t>(ttlHours) * 3600ULL * 1000ULL) : 0ULL;

    std::string rawTok;
    ApiTokenRecord rec;
    if (!deps_.auth.createApiToken(label, targetRole, ttlMs, rawTok, rec)) {
      return jsonError(400, "invalid_token_request");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "auth.token_created", rec.id, "allowed",
                       "label=" + rec.label + ", role=" + roleToString(rec.role));

    HttpResponse resp;
    resp.statusCode = 201;
    resp.body = "{\"ok\":true,\"id\":";
    appendJsonEscaped(resp.body, rec.id);
    resp.body += ",\"token\":";
    appendJsonEscaped(resp.body, rawTok);
    resp.body += ",\"role\":\"";
    resp.body += roleToString(rec.role);
    resp.body += "\"}";
    return resp;
  }

  if (path == "/api/auth/tokens/revoke" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Administrator, auth, "auth.token_revoked");
    if (err.statusCode != 200) return err;

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }
    if (body.getBool("allSessions", false)) {
      deps_.auth.revokeAllSessions();
      deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                         "auth.sessions_revoked", "all", "allowed", "Todas as sessoes revogadas");
      return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
    }
    std::string tokenId = body.getString("id");
    if (tokenId.empty() || !deps_.auth.revokeApiToken(tokenId)) {
      return jsonError(404, "token_not_found");
    }
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "auth.token_revoked", tokenId, "allowed", "Token revogado");
    return HttpResponse{200, "application/json; charset=utf-8", "{\"ok\":true}", {}};
  }

  // ---- Satellite Tracking V1 ----
  if (path == "/api/satellites" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.satellitePositions) {
      return jsonError(503, "satellite_module_unavailable");
    }
    return HttpResponse{200, "application/json; charset=utf-8", deps_.satellitePositions->getSnapshotJson(), {}};
  }

  if (path == "/api/satellites/catalog" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    if (!deps_.satelliteManager) {
      return jsonError(503, "satellite_module_unavailable");
    }
    return HttpResponse{200, "application/json; charset=utf-8", deps_.satelliteManager->catalog().toCatalogJson(), {}};
  }

  if (path == "/api/satellites/config" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "satellite.config_updated");
    if (err.statusCode != 200) return err;
    if (!deps_.satelliteManager || !deps_.satellitePositions) {
      return jsonError(503, "satellite_module_unavailable");
    }

    JsonValue body;
    std::string parseErr;
    if (!JsonValue::parse(req.body, body, parseErr) || !body.isObject()) {
      return jsonError(400, "invalid_json", parseErr);
    }

    auto nextCfg = deps_.satelliteManager->config().get();
    nextCfg.enabled = body.getBool("enabled", nextCfg.enabled);
    nextCfg.showTrajectory = body.getBool("showTrajectory", nextCfg.showTrajectory);
    nextCfg.pastTrackMinutes = static_cast<int>(body.getInt("pastTrackMinutes", nextCfg.pastTrackMinutes));
    nextCfg.futureTrackMinutes = static_cast<int>(body.getInt("futureTrackMinutes", nextCfg.futureTrackMinutes));
    nextCfg.positionIntervalMs = static_cast<int>(body.getInt("positionIntervalMs", nextCfg.positionIntervalMs));
    nextCfg.catalogRefreshSec = static_cast<int>(body.getInt("catalogRefreshSec", nextCfg.catalogRefreshSec));

    if (body.getBool("selectAll", false)) {
      nextCfg.visibleNoradIds = deps_.satelliteManager->availableNoradIds();
    } else if (body.getBool("deselectAll", false)) {
      nextCfg.visibleNoradIds.clear();
    } else if (const JsonValue* visArr = body.get("visibleNoradIds"); visArr && visArr->isArray()) {
      nextCfg.visibleNoradIds.clear();
      for (const auto& item : visArr->asArray()) {
        int nid = static_cast<int>(item.asInt(0));
        if (nid > 0) nextCfg.visibleNoradIds.push_back(nid);
      }
    }

    if (const JsonValue* toggleId = body.get("toggleNoradId"); toggleId && toggleId->isNumber()) {
      const int nid = static_cast<int>(toggleId->asInt(0));
      const bool vis = body.getBool("visible", true);
      if (nid > 0) {
        auto it = std::find(nextCfg.visibleNoradIds.begin(), nextCfg.visibleNoradIds.end(), nid);
        if (vis && it == nextCfg.visibleNoradIds.end()) {
          nextCfg.visibleNoradIds.push_back(nid);
        } else if (!vis && it != nextCfg.visibleNoradIds.end()) {
          nextCfg.visibleNoradIds.erase(it);
        }
      }
    }

    std::string cfgErr;
    if (!deps_.satelliteManager->config().update(nextCfg, cfgErr)) {
      return jsonError(400, "invalid_satellite_config", cfgErr);
    }
    deps_.satellitePositions->notifyConfigChanged();
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "satellite.config_updated", "satellites", "allowed",
                       "enabled=" + std::string(nextCfg.enabled ? "1" : "0") +
                       ", count=" + std::to_string(nextCfg.visibleNoradIds.size()));
    return HttpResponse{200, "application/json; charset=utf-8", deps_.satellitePositions->getSnapshotJson(), {}};
  }

  if (path == "/api/satellites/refresh" && method == "POST") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Operator, auth, "satellite.catalog_refresh");
    if (err.statusCode != 200) return err;
    if (!deps_.satellitePositions) {
      return jsonError(503, "satellite_module_unavailable");
    }

    bool force = false;
    if (!req.body.empty()) {
      JsonValue body;
      std::string parseErr;
      if (JsonValue::parse(req.body, body, parseErr) && body.isObject()) {
        force = body.getBool("force", false);
      }
    }
    deps_.satellitePositions->requestCatalogRefreshAsync(force);
    deps_.audit.record(auth.actor, roleToString(auth.role), req.remoteIp,
                       "satellite.catalog_refresh", "celestrak", "allowed",
                       force ? "forced" : "scheduled");
    return HttpResponse{202, "application/json; charset=utf-8",
                        "{\"ok\":true,\"status\":\"refresh_queued\"}", {}};
  }

  return jsonError(404, "not_found");
}

} // namespace netpulse
