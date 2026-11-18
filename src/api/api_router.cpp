#include "api_router.hpp"
#include "../actions.hpp"
#include "../models.hpp"
#include "../net_monitor.hpp"
#include "../tray_host.hpp"

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
    if (!isValidIpAddress(ip) || !deps_.tracer.startTrace(ip)) {
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

  if (path == "/api/history/events" && method == "GET") {
    AuthContext auth;
    auto err = requireAuth(req, Role::Viewer, auth);
    if (err.statusCode != 200) return err;
    return HttpResponse{200, "application/json; charset=utf-8", deps_.history.getEventsJson(150), {}};
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

  return jsonError(404, "not_found");
}

} // namespace netpulse
