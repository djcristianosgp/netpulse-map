#include "prometheus_openapi.hpp"
#include "api_router.hpp"
#include "../models.hpp"
#include "../version.hpp"

#include <sstream>

namespace netpulse {

std::string escapePrometheusLabelValue(const std::string& val) {
  std::string out;
  out.reserve(val.size());
  for (char c : val) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else if (c != '\r') out.push_back(c);
  }
  return out;
}

std::string formatPrometheusMetrics(const ApiDependencies& deps) {
  std::ostringstream ss;

  ss << "# HELP netpulse_info NetPulse engine build metadata.\n";
  ss << "# TYPE netpulse_info gauge\n";
  ss << "netpulse_info{version=\"" << escapePrometheusLabelValue(kAppVersion) << "\"} 1\n";

  // Live telemetry stats parsed from latest JSON snapshot if available
  if (deps.getLatestSnapshotJson) {
    const std::string snapStr = deps.getLatestSnapshotJson();
    JsonValue snap;
    std::string perr;
    if (!snapStr.empty() && JsonValue::parse(snapStr, snap, perr, 524288) && snap.isObject()) {
      if (const JsonValue* stats = snap.get("stats"); stats && stats->isObject()) {
        ss << "# HELP netpulse_connections_active Active network sockets by scope.\n";
        ss << "# TYPE netpulse_connections_active gauge\n";
        ss << "netpulse_connections_active{scope=\"public\"} " << stats->getInt("publicConnections", 0) << "\n";
        ss << "netpulse_connections_active{scope=\"lan\"} " << stats->getInt("lanConnections", 0) << "\n";
        ss << "netpulse_connections_active{scope=\"listening\"} " << stats->getInt("listeningSockets", 0) << "\n";
        ss << "netpulse_connections_active{scope=\"total\"} " << stats->getInt("totalConnections", 0) << "\n";
      }
      if (const JsonValue* nic = snap.get("nic"); nic && nic->isObject()) {
        ss << "# HELP netpulse_nic_rx_bytes_per_sec Host NIC receive throughput in bytes/sec.\n";
        ss << "# TYPE netpulse_nic_rx_bytes_per_sec gauge\n";
        ss << "netpulse_nic_rx_bytes_per_sec " << nic->getDouble("rxBps", 0.0) << "\n";
        ss << "# HELP netpulse_nic_tx_bytes_per_sec Host NIC transmit throughput in bytes/sec.\n";
        ss << "# TYPE netpulse_nic_tx_bytes_per_sec gauge\n";
        ss << "netpulse_nic_tx_bytes_per_sec " << nic->getDouble("txBps", 0.0) << "\n";
      }
    }
  }

  // Quality Engine
  if (deps.quality) {
    const auto targets = deps.quality->getTargetsSnapshot();
    ss << "# HELP netpulse_quality_target_rtt_ms Current latency RTT per monitored target in ms.\n";
    ss << "# TYPE netpulse_quality_target_rtt_ms gauge\n";
    for (const auto& t : targets) {
      ss << "netpulse_quality_target_rtt_ms{id=\"" << escapePrometheusLabelValue(t.target.id)
         << "\",host=\"" << escapePrometheusLabelValue(t.target.host)
         << "\",category=\"" << escapePrometheusLabelValue(t.target.category)
         << "\"} " << t.metrics.currentLatencyMs << "\n";
    }
    ss << "# HELP netpulse_quality_target_packet_loss_pct Packet loss percentage per target.\n";
    ss << "# TYPE netpulse_quality_target_packet_loss_pct gauge\n";
    for (const auto& t : targets) {
      ss << "netpulse_quality_target_packet_loss_pct{id=\"" << escapePrometheusLabelValue(t.target.id)
         << "\",host=\"" << escapePrometheusLabelValue(t.target.host)
         << "\"} " << t.metrics.packetLossPct << "\n";
    }
    ss << "# HELP netpulse_quality_target_up Target reachability state (1=ok, 0.5=degraded, 0=down).\n";
    ss << "# TYPE netpulse_quality_target_up gauge\n";
    for (const auto& t : targets) {
      const double v = (t.status == "ok") ? 1.0 : (t.status == "degraded" ? 0.5 : 0.0);
      ss << "netpulse_quality_target_up{id=\"" << escapePrometheusLabelValue(t.target.id)
         << "\",host=\"" << escapePrometheusLabelValue(t.target.host) << "\"} " << v << "\n";
    }
  }

  // Interfaces Multi-WAN
  if (deps.interfaces) {
    const auto ifSnap = deps.interfaces->getSnapshot();
    ss << "# HELP netpulse_interface_rx_bps Receive rate in bytes/sec per network interface.\n";
    ss << "# TYPE netpulse_interface_rx_bps gauge\n";
    for (const auto& i : ifSnap.interfaces) {
      ss << "netpulse_interface_rx_bps{id=\"" << escapePrometheusLabelValue(i.id)
         << "\",name=\"" << escapePrometheusLabelValue(i.name)
         << "\",type=\"" << escapePrometheusLabelValue(i.type) << "\"} " << i.rxBps << "\n";
    }
    ss << "# HELP netpulse_interface_tx_bps Transmit rate in bytes/sec per network interface.\n";
    ss << "# TYPE netpulse_interface_tx_bps gauge\n";
    for (const auto& i : ifSnap.interfaces) {
      ss << "netpulse_interface_tx_bps{id=\"" << escapePrometheusLabelValue(i.id)
         << "\",name=\"" << escapePrometheusLabelValue(i.name)
         << "\",type=\"" << escapePrometheusLabelValue(i.type) << "\"} " << i.txBps << "\n";
    }
    ss << "# HELP netpulse_interface_up Interface operational status (1=up, 0=down).\n";
    ss << "# TYPE netpulse_interface_up gauge\n";
    for (const auto& i : ifSnap.interfaces) {
      ss << "netpulse_interface_up{id=\"" << escapePrometheusLabelValue(i.id)
         << "\",name=\"" << escapePrometheusLabelValue(i.name) << "\"} " << (i.operStatus == "up" ? 1 : 0) << "\n";
    }
  }

  // Discovery LAN
  if (deps.discovery) {
    const auto devs = deps.discovery->getDevicesSnapshot();
    size_t online = 0;
    for (const auto& d : devs) {
      if (d.online) ++online;
    }
    ss << "# HELP netpulse_discovery_devices_total Total discovered LAN devices in inventory.\n";
    ss << "# TYPE netpulse_discovery_devices_total gauge\n";
    ss << "netpulse_discovery_devices_total " << devs.size() << "\n";
    ss << "# HELP netpulse_discovery_devices_online Currently online LAN devices.\n";
    ss << "# TYPE netpulse_discovery_devices_online gauge\n";
    ss << "netpulse_discovery_devices_online " << online << "\n";
  }

  // Services Monitor
  const auto svcs = deps.services.getSnapshot();
  size_t upCnt = 0, degCnt = 0, downCnt = 0;
  for (const auto& s : svcs) {
    if (s.status == "up") ++upCnt;
    else if (s.status == "degraded") ++degCnt;
    else if (s.status == "down") ++downCnt;
  }
  ss << "# HELP netpulse_services_total Monitored anchor and custom TCP services.\n";
  ss << "# TYPE netpulse_services_total gauge\n";
  ss << "netpulse_services_total " << svcs.size() << "\n";
  ss << "# HELP netpulse_services_status Service count grouped by status.\n";
  ss << "# TYPE netpulse_services_status gauge\n";
  ss << "netpulse_services_status{status=\"up\"} " << upCnt << "\n";
  ss << "netpulse_services_status{status=\"degraded\"} " << degCnt << "\n";
  ss << "netpulse_services_status{status=\"down\"} " << downCnt << "\n";

  // Intelligence
  if (deps.intelligence) {
    const std::string intelStr = deps.intelligence->getOverviewJson(10, "", false);
    JsonValue intel;
    std::string perr;
    if (JsonValue::parse(intelStr, intel, perr, 131072) && intel.isObject()) {
      ss << "# HELP netpulse_intelligence_risk_score Deterministic behavioral risk score (0-100).\n";
      ss << "# TYPE netpulse_intelligence_risk_score gauge\n";
      ss << "netpulse_intelligence_risk_score " << intel.getInt("overallRiskScore", 0) << "\n";
      ss << "# HELP netpulse_intelligence_unacknowledged_alerts Unacknowledged deterministic behavioral alerts.\n";
      ss << "# TYPE netpulse_intelligence_unacknowledged_alerts gauge\n";
      ss << "netpulse_intelligence_unacknowledged_alerts " << intel.getInt("unacknowledgedCount", 0) << "\n";
      ss << "# HELP netpulse_intelligence_tracked_processes Processes tracked in EWMA baseline.\n";
      ss << "# TYPE netpulse_intelligence_tracked_processes gauge\n";
      ss << "netpulse_intelligence_tracked_processes " << intel.getInt("trackedProcessBaselines", 0) << "\n";
    }
  }

  // Notifications
  if (deps.notifications) {
    ss << "# HELP netpulse_notifications_sent_total External notifications dispatched by status.\n";
    ss << "# TYPE netpulse_notifications_sent_total counter\n";
    ss << "netpulse_notifications_sent_total{status=\"ok\"} " << deps.notifications->sentOkCount() << "\n";
    ss << "netpulse_notifications_sent_total{status=\"error\"} " << deps.notifications->sentErrorCount() << "\n";
  }

  // Satellite Tracking V1
  if (deps.satellitePositions && deps.satelliteManager) {
    const auto cfg = deps.satelliteManager->config().get();
    ss << "# HELP netpulse_satellite_module_enabled Satellite Tracking layer enabled (1=yes, 0=no).\n";
    ss << "# TYPE netpulse_satellite_module_enabled gauge\n";
    ss << "netpulse_satellite_module_enabled " << (cfg.enabled ? 1 : 0) << "\n";
    ss << "# HELP netpulse_satellite_computations_total Total SGP4 propagation cycles executed.\n";
    ss << "# TYPE netpulse_satellite_computations_total counter\n";
    ss << "netpulse_satellite_computations_total " << deps.satellitePositions->computationCount() << "\n";
  }

  return ss.str();
}

std::string buildOpenApiV1SpecJson(const std::string& version) {
  auto addOp = [](std::string& pathsOut,
                  bool& firstPath,
                  const std::string& path,
                  const std::string& method,
                  const std::string& tag,
                  const std::string& summary,
                  const std::string& roleNote,
                  bool needsBody = false,
                  bool requiresConfirm = false) {
    if (!firstPath) pathsOut += ",";
    firstPath = false;
    pathsOut += "\""; pathsOut += path; pathsOut += "\":{\""; pathsOut += method; pathsOut += "\":{";
    pathsOut += "\"tags\":["; appendJsonEscaped(pathsOut, tag); pathsOut += "]";
    pathsOut += ",\"summary\":"; appendJsonEscaped(pathsOut, summary);
    std::string desc = "Perfil minimo: " + roleNote + (requiresConfirm ? " | Requer confirm:true no payload + AuditLog." : ".");
    pathsOut += ",\"description\":"; appendJsonEscaped(pathsOut, desc);
    if (needsBody) {
      pathsOut += ",\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\"}}}}";
    }
    pathsOut += ",\"responses\":{\"200\":{\"description\":\"Sucesso\"},\"401\":{\"description\":\"Nao autenticado\"},\"403\":{\"description\":\"Permissao RBAC ou CSRF insuficiente\"}}";
    pathsOut += "}}";
  };

  std::string out = "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"NetPulse Platform API v1\",\"version\":";
  appendJsonEscaped(out, version);
  out += ",\"description\":";
  appendJsonEscaped(out, "API nativa deterministica em C++20 para observabilidade, diagnostico de rede, topologia LAN, seguranca, historico SQLite WAL, NOC e notificacoes (sem IA/LLMs).");
  out += "},\"servers\":[{\"url\":\"/\"}],\"components\":{\"securitySchemes\":{\"bearerAuth\":{\"type\":\"http\",\"scheme\":\"bearer\"},\"cookieAuth\":{\"type\":\"apiKey\",\"in\":\"cookie\",\"name\":\"np_session\"}}},\"security\":[{\"bearerAuth\":[]},{\"cookieAuth\":[]}],\"paths\":{";

  bool first = true;
  // System & Auth
  addOp(out, first, "/api/health", "get", "Health", "Health check basico do motor", "Publico");
  addOp(out, first, "/api/v1/auth/login", "post", "Auth", "Autenticar via token e abrir sessao HttpOnly", "Token valido", true);
  addOp(out, first, "/api/v1/auth/ws-ticket", "post", "Auth", "Emitir ticket efemero unico (30s) para WebSocket", "Viewer+");
  addOp(out, first, "/api/v1/security/audit", "get", "Security", "Consultar log de auditoria operacional", "Operator+");
  addOp(out, first, "/api/v1/security/blocks", "get", "Security", "Listar IPs bloqueados no firewall", "Viewer+");
  // Live & Services
  addOp(out, first, "/api/v1/snapshot", "get", "Telemetry", "Ultimo snapshot completo de sockets, processos e paises", "Viewer+");
  addOp(out, first, "/api/v1/services", "get", "Services", "Estado dos servicos monitorados", "Viewer+");
  addOp(out, first, "/api/v1/services/add", "post", "Services", "Adicionar servico TCP customizado", "Operator+", true);
  // Quality, Traceroute, Interfaces, Discovery, Topology
  addOp(out, first, "/api/v1/quality/status", "get", "Quality", "Metricas atuais, P50/P90/P95/P99, jitter, loss e diagnostico", "Viewer+");
  addOp(out, first, "/api/v1/quality/history", "get", "Quality", "Serie historica de qualidade por alvo", "Viewer+");
  addOp(out, first, "/api/v1/quality/targets", "post", "Quality", "Adicionar destino de qualidade", "Operator+", true);
  addOp(out, first, "/api/v1/trace/start", "post", "Traceroute", "Iniciar traceroute com enriquecimento ASN/GeoIP", "Operator+", true);
  addOp(out, first, "/api/v1/trace/history", "get", "Traceroute", "Listar execucoes historicas de traceroute", "Viewer+");
  addOp(out, first, "/api/v1/trace/diff", "get", "Traceroute", "Comparar duas rotas TTL a TTL (Route Diff)", "Viewer+");
  addOp(out, first, "/api/v1/interfaces", "get", "Interfaces", "Inventario Multi-WAN, gateways e taxas por interface", "Viewer+");
  addOp(out, first, "/api/v1/interfaces/history", "get", "Interfaces", "Historico RX/TX por interface", "Viewer+");
  addOp(out, first, "/api/v1/discovery/devices", "get", "Discovery", "Inventario LAN ARP, OUI e portas detectadas", "Viewer+");
  addOp(out, first, "/api/v1/discovery/scan", "post", "Discovery", "Disparar varredura ativa /24 na sub-rede LAN", "Operator+");
  addOp(out, first, "/api/v1/topology/lan", "get", "Topology", "Grafo topologico LAN com evidencia por aresta", "Viewer+");
  // Intelligence & Firewall
  addOp(out, first, "/api/v1/intelligence/overview", "get", "Intelligence", "Alertas deterministas, score de risco 0-100, regras e firewall", "Viewer+");
  addOp(out, first, "/api/v1/intelligence/ack", "post", "Intelligence", "Reconhecer alerta comportamental", "Operator+", true);
  addOp(out, first, "/api/v1/intelligence/rules", "post", "Intelligence", "Criar/atualizar regra comportamental determinista", "Administrator", true);
  addOp(out, first, "/api/v1/security/lists", "post", "Security", "Adicionar alvo em allowlist/blocklist", "Operator+", true);
  addOp(out, first, "/api/v1/security/firewall", "post", "Security", "Criar regra granular de firewall (IP/porta/exe)", "Administrator", true, true);
  addOp(out, first, "/api/v1/security/firewall/delete", "post", "Security", "Reverter e remover regra de firewall", "Administrator", true, true);
  // History, NOC, Notifications, Metrics, OpenAPI
  addOp(out, first, "/api/v1/history/connections", "get", "History", "Consultar historico paginado de conexoes no SQLite WAL", "Viewer+");
  addOp(out, first, "/api/v1/history/analytics", "get", "History", "Top 10 apps/destinos/paises e serie diaria RX/TX", "Viewer+");
  addOp(out, first, "/api/v1/history/storage", "get", "History", "Estado WAL, versao schema e contadores do banco", "Viewer+");
  addOp(out, first, "/api/v1/noc/overview", "get", "NOC", "Visao consolidada somente leitura para Wallboard TV", "Viewer+");
  addOp(out, first, "/api/v1/notifications/channels", "get", "Notifications", "Listar canais Webhook/Discord/Telegram (segredos mascarados)", "Viewer+");
  addOp(out, first, "/api/v1/notifications/channels/save", "post", "Notifications", "Salvar canal externo Webhook/Discord/Telegram", "Administrator", true);
  addOp(out, first, "/api/v1/notifications/channels/delete", "post", "Notifications", "Remover canal de notificacao", "Administrator", true, true);
  addOp(out, first, "/api/v1/notifications/test", "post", "Notifications", "Enviar notificacao de teste sincrona", "Operator+", true);
  addOp(out, first, "/api/v1/notifications/deliveries", "get", "Notifications", "Historico de entregas e falhas de notificacao", "Viewer+");
  addOp(out, first, "/api/v1/satellites", "get", "Satellites", "Posicoes SGP4 atuais, trajetorias e configuracao dos objetos orbitais", "Viewer+");
  addOp(out, first, "/api/v1/satellites/catalog", "get", "Satellites", "Elementos orbitais OMM/TLE em cache e estado de atualizacao", "Viewer+");
  addOp(out, first, "/api/v1/satellites/config", "post", "Satellites", "Configurar camada Satellite Tracking, selecao e frequencia", "Operator+", true);
  addOp(out, first, "/api/v1/satellites/refresh", "post", "Satellites", "Solicitar atualizacao assincrona dos elementos orbitais (CelesTrak)", "Operator+");
  addOp(out, first, "/metrics", "get", "Observability", "Exportador Prometheus exposition text/plain v0.0.4", "Viewer+");
  addOp(out, first, "/api/v1/openapi.json", "get", "Docs", "Especificacao OpenAPI 3.0.3 em JSON", "Viewer+");

  out += "}}";
  return out;
}

} // namespace netpulse
