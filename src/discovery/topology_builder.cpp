#include "topology_builder.hpp"
#include "../net_monitor.hpp"

#include <algorithm>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace netpulse {

namespace {

bool isIpv4Literal(const std::string& ip) {
  return !ip.empty() && ip.find(':') == std::string::npos;
}

std::string subnet24Prefix(const std::string& ip) {
  if (!isIpv4Literal(ip)) return {};
  auto d1 = ip.rfind('.');
  if (d1 == std::string::npos) return {};
  return ip.substr(0, d1) + ".0/24";
}

} // namespace

LanTopologySnapshot buildLanTopology(uint64_t nowMs,
                                     const std::string& localHostname,
                                     const InterfaceInventorySnapshot& ifSnap,
                                     const std::vector<LanDeviceRecord>& devices,
                                     const std::vector<QualityTargetSnapshot>& qualityTargets,
                                     const TelemetrySnapshot* telemetry) {
  LanTopologySnapshot snap;
  snap.generatedAtMs = nowMs;
  snap.localHostname = localHostname.empty() ? "Estação Local" : localHostname;
  snap.modelNote = "Topologia baseada exclusivamente em evidências reais (interfaces do SO, rota padrão, tabela ARP/vizinhos, sockets ativos e sondagens).";

  std::unordered_map<std::string, size_t> nodeIdxById;
  auto addNode = [&](TopoNode n) -> size_t {
    auto it = nodeIdxById.find(n.id);
    if (it != nodeIdxById.end()) return it->second;
    size_t idx = snap.nodes.size();
    nodeIdxById[n.id] = idx;
    snap.nodes.push_back(std::move(n));
    return idx;
  };

  std::unordered_set<std::string> edgeKeys;
  auto addEdge = [&](TopoEdge e) {
    if (nodeIdxById.find(e.source) == nodeIdxById.end() ||
        nodeIdxById.find(e.target) == nodeIdxById.end()) {
      return;
    }
    const std::string k = e.source + "->" + e.target + "|" + e.kind;
    if (!edgeKeys.insert(k).second) return;
    snap.edges.push_back(std::move(e));
  };

  // Index quality probe RTT by host IP
  std::unordered_map<std::string, const QualityTargetSnapshot*> qualByHost;
  double extAvgRtt = 0.0;
  size_t extCount = 0;
  for (const auto& q : qualityTargets) {
    qualByHost[q.target.host] = &q;
    if (q.target.category != "gateway" && q.metrics.okCount > 0 && q.metrics.p50Ms > 0.0) {
      extAvgRtt += q.metrics.p50Ms;
      extCount++;
    }
  }
  if (extCount > 0) extAvgRtt /= static_cast<double>(extCount);

  // Index active socket peers from TelemetrySnapshot
  struct SocketAgg {
    uint32_t count = 0;
    std::string sampleProc;
    std::string sampleProto;
    uint16_t samplePort = 0;
  };
  std::unordered_map<std::string, SocketAgg> activeByRemoteIp;
  uint32_t publicConns = 0;
  uint32_t totalConns = 0;
  if (telemetry) {
    totalConns = telemetry->totalConnections;
    publicConns = telemetry->publicConnections;
    for (const auto& c : telemetry->connections) {
      if (c.remoteIp.empty() || c.scope == IpScope::Loopback) continue;
      auto& agg = activeByRemoteIp[c.remoteIp];
      agg.count++;
      if (agg.sampleProc.empty()) {
        agg.sampleProc = c.processName;
        agg.sampleProto = c.protocol;
        agg.samplePort = c.remotePort;
      }
    }
  }
  snap.activeSockets = totalConns;

  // Index discovered LAN devices by IP
  std::unordered_map<std::string, const LanDeviceRecord*> devByIp;
  for (const auto& d : devices) {
    devByIp[d.ip] = &d;
  }

  // Layer 0: Local Host
  TopoNode hostNode;
  hostNode.id = "host:local";
  hostNode.kind = "host";
  hostNode.label = snap.localHostname;
  hostNode.sublabel = ifSnap.primaryIfName.empty() ? "Estação Local" : ("WAN: " + ifSnap.primaryIfName);
  hostNode.deviceType = "Estação Local";
  hostNode.status = "up";
  hostNode.layer = 0;
  hostNode.isPrimary = true;
  hostNode.rxBps = ifSnap.totalRxBps;
  hostNode.txBps = ifSnap.totalTxBps;
  hostNode.activeConns = totalConns;
  addNode(std::move(hostNode));

  // Layer 1: Network Interfaces (skip loopback unless needed)
  std::unordered_map<std::string, std::string> ifIdByName;
  std::unordered_map<std::string, std::string> ifIdBySubnet;
  std::string primaryIfaceNodeId;

  for (const auto& ifc : ifSnap.interfaces) {
    if (ifc.type == "loopback") continue;
    if (!ifc.isWanCandidate && ifc.ipv4.empty() && ifc.operStatus != "up") continue;

    std::string nodeId = "iface:" + ifc.id;
    ifIdByName[ifc.name] = nodeId;
    std::string primaryIp;
    for (const auto& ip4 : ifc.ipv4) {
      if (primaryIp.empty()) primaryIp = ip4;
      std::string sub = subnet24Prefix(ip4);
      if (!sub.empty()) ifIdBySubnet[sub] = nodeId;
    }

    TopoNode n;
    n.id = nodeId;
    n.kind = "interface";
    n.label = ifc.name;
    n.sublabel = primaryIp.empty() ? ifc.type : (ifc.type + " · " + primaryIp);
    n.ip = primaryIp;
    n.mac = ifc.macAddress;
    n.deviceType = ifc.type;
    n.status = ifc.operStatus;
    n.layer = 1;
    n.isPrimary = ifc.isDefaultRoute;
    n.linkSpeedBps = ifc.linkSpeedBps;
    n.rxBps = ifc.rxBps;
    n.txBps = ifc.txBps;
    n.subnet = primaryIp.empty() ? "" : subnet24Prefix(primaryIp);
    addNode(std::move(n));

    if (ifc.isDefaultRoute || primaryIfaceNodeId.empty()) {
      primaryIfaceNodeId = nodeId;
    }

    TopoEdge e;
    e.id = "edge:host:" + ifc.id;
    e.source = "host:local";
    e.target = nodeId;
    e.kind = "local_nic";
    e.label = ifc.isDefaultRoute ? "WAN Primária" : ifc.type;
    e.evidence = "Adaptador do SO (" + ifc.description + ", status=" + ifc.operStatus + ")";
    addEdge(std::move(e));
  }

  // Layer 2: Gateways & DNS Servers
  std::unordered_map<std::string, std::string> gwNodeByIp;
  std::unordered_map<std::string, std::string> gwNodeBySubnet;
  std::string primaryGwNodeId;

  for (const auto& ifc : ifSnap.interfaces) {
    if (ifc.type == "loopback" || ifc.operStatus != "up") continue;
    const std::string ifNodeId = "iface:" + ifc.id;

    for (const auto& gwIp : ifc.gateways) {
      if (!isIpv4Literal(gwIp)) continue;
      std::string gwNodeId = "gw:" + gwIp;
      gwNodeByIp[gwIp] = gwNodeId;
      std::string gwSub = subnet24Prefix(gwIp);
      if (!gwSub.empty()) gwNodeBySubnet[gwSub] = gwNodeId;

      TopoNode gn;
      gn.id = gwNodeId;
      gn.kind = "gateway";
      gn.ip = gwIp;
      gn.subnet = gwSub;
      gn.deviceType = "Roteador / Gateway";
      gn.layer = 2;
      gn.isPrimary = (ifc.isDefaultRoute && gwIp == ifSnap.primaryGateway);
      gn.status = "up";

      if (auto dIt = devByIp.find(gwIp); dIt != devByIp.end()) {
        const auto* d = dIt->second;
        gn.label = !d->customLabel.empty() ? d->customLabel : (!d->hostname.empty() ? d->hostname : ("Gateway " + gwIp));
        gn.mac = d->mac;
        gn.vendor = d->vendor;
        gn.openPorts = d->openPorts;
        gn.latencyMs = d->latencyMs;
        if (!d->online) gn.status = "degraded";
      } else {
        gn.label = "Gateway " + gwIp;
      }
      if (auto qIt = qualByHost.find(gwIp); qIt != qualByHost.end()) {
        const auto* q = qIt->second;
        if (q->metrics.okCount > 0) gn.latencyMs = q->metrics.p50Ms;
        if (q->status == "down") gn.status = "degraded"; // ICMP may be filtered while routing
      }
      if (auto aIt = activeByRemoteIp.find(gwIp); aIt != activeByRemoteIp.end()) {
        gn.activeConns = aIt->second.count;
      }
      gn.sublabel = gn.vendor.empty() ? gwIp : (gn.vendor + " · " + gwIp);
      addNode(std::move(gn));

      if (ifc.isDefaultRoute || primaryGwNodeId.empty()) {
        primaryGwNodeId = gwNodeId;
      }

      TopoEdge e;
      e.id = "edge:" + ifNodeId + ":" + gwNodeId;
      e.source = ifNodeId;
      e.target = gwNodeId;
      e.kind = ifc.isDefaultRoute ? "default_route" : "arp_subnet";
      e.label = ifc.isDefaultRoute ? "Rota Padrão (0.0.0.0/0)" : "Gateway";
      e.evidence = "Tabela de roteamento / GetAdaptersAddresses em " + ifc.name;
      if (auto qIt = qualByHost.find(gwIp); qIt != qualByHost.end() && qIt->second->metrics.okCount > 0) {
        e.rttMs = qIt->second->metrics.p50Ms;
      }
      addEdge(std::move(e));
    }

    // Attach configured DNS resolvers (up to 2 IPv4 per active interface)
    int dnsAdded = 0;
    for (const auto& dnsIp : ifc.dnsServers) {
      if (!isIpv4Literal(dnsIp) || dnsAdded >= 2) continue;
      dnsAdded++;
      std::string dnsNodeId = "dns:" + dnsIp;
      TopoNode dn;
      dn.id = dnsNodeId;
      dn.kind = "dns";
      dn.label = "DNS " + dnsIp;
      dn.sublabel = (classifyIpString(dnsIp) == IpScope::Lan) ? "Resolvedor LAN" : "Resolvedor Externo";
      dn.ip = dnsIp;
      dn.deviceType = "Servidor DNS";
      dn.layer = 2;
      dn.status = "up";
      if (auto qIt = qualByHost.find(dnsIp); qIt != qualByHost.end()) {
        dn.latencyMs = qIt->second->metrics.avgDnsMs > 0 ? qIt->second->metrics.avgDnsMs : qIt->second->metrics.p50Ms;
        if (qIt->second->status == "down") dn.status = "down";
      }
      if (auto aIt = activeByRemoteIp.find(dnsIp); aIt != activeByRemoteIp.end()) {
        dn.activeConns = aIt->second.count;
      }
      addNode(std::move(dn));

      const std::string srcId = (classifyIpString(dnsIp) == IpScope::Lan) ? ifNodeId : (!primaryGwNodeId.empty() ? primaryGwNodeId : ifNodeId);
      TopoEdge e;
      e.id = "edge:dns:" + srcId + ":" + dnsNodeId;
      e.source = srcId;
      e.target = dnsNodeId;
      e.kind = "dns_config";
      e.label = "DNS";
      e.evidence = "Resolvedor DNS atribuído em " + ifc.name;
      if (auto qIt = qualByHost.find(dnsIp); qIt != qualByHost.end()) {
        e.rttMs = qIt->second->metrics.avgDnsMs;
      }
      addEdge(std::move(e));
    }
  }

  // Layer 4 Upstream Internet Node (when we have primary gateway or public traffic)
  if (!primaryGwNodeId.empty() || !primaryIfaceNodeId.empty()) {
    TopoNode up;
    up.id = "upstream:internet";
    up.kind = "upstream";
    up.label = "Internet / WAN Upstream";
    up.sublabel = std::to_string(publicConns) + " conexões públicas ativas";
    up.deviceType = "Rede Externa / Internet";
    up.status = (extCount > 0 || publicConns > 0) ? "up" : "unknown";
    up.layer = 4;
    up.latencyMs = extAvgRtt;
    up.activeConns = publicConns;
    addNode(std::move(up));

    const std::string uplinkParent = !primaryGwNodeId.empty() ? primaryGwNodeId : primaryIfaceNodeId;
    TopoEdge e;
    e.id = "edge:upstream:" + uplinkParent;
    e.source = uplinkParent;
    e.target = "upstream:internet";
    e.kind = "default_route";
    e.label = "Saída WAN";
    e.evidence = !primaryGwNodeId.empty() ? "Encaminhamento padrão via gateway" : "Interface padrão do SO";
    e.rttMs = extAvgRtt;
    e.activeSessions = publicConns;
    addEdge(std::move(e));
  }

  // Layer 3: Discovered LAN Devices (attached strictly by ARP/interface/subnet evidence)
  for (const auto& d : devices) {
    if (d.isLocalHost) continue;
    if (gwNodeByIp.find(d.ip) != gwNodeByIp.end()) continue; // already represented as Gateway node
    if (nodeIdxById.find("dns:" + d.ip) != nodeIdxById.end()) continue; // already represented as DNS node

    snap.totalDevices++;
    if (d.online) snap.onlineDevices++;

    std::string nodeId = "dev:" + d.deviceKey;
    TopoNode dn;
    dn.id = nodeId;
    dn.kind = "lan_device";
    dn.label = !d.customLabel.empty() ? d.customLabel : (!d.hostname.empty() ? d.hostname : d.ip);
    dn.ip = d.ip;
    dn.mac = d.mac;
    dn.vendor = d.vendor;
    dn.deviceType = d.deviceType;
    dn.status = d.online ? "online" : "offline";
    dn.subnet = d.subnet;
    dn.openPorts = d.openPorts;
    dn.latencyMs = d.latencyMs;
    dn.layer = 3;

    std::string subDesc = d.ip;
    if (!d.vendor.empty()) subDesc += " · " + d.vendor;
    else if (!d.deviceType.empty()) subDesc += " · " + d.deviceType;
    dn.sublabel = std::move(subDesc);

    auto sockIt = activeByRemoteIp.find(d.ip);
    if (sockIt != activeByRemoteIp.end()) {
      dn.activeConns = sockIt->second.count;
    }
    addNode(std::move(dn));

    // Attach to matching subnet gateway first (most faithful logical L3/L2 hop) or matching NIC
    std::string parentId;
    std::string parentDesc = d.subnet;
    if (!d.subnet.empty() && gwNodeBySubnet.count(d.subnet)) {
      parentId = gwNodeBySubnet[d.subnet];
      parentDesc = "sub-rede " + d.subnet + " via ARP";
    } else if (!d.interfaceName.empty() && ifIdByName.count(d.interfaceName)) {
      parentId = ifIdByName[d.interfaceName];
      parentDesc = "interface " + d.interfaceName + " via ARP";
    } else if (!d.subnet.empty() && ifIdBySubnet.count(d.subnet)) {
      parentId = ifIdBySubnet[d.subnet];
      parentDesc = "sub-rede " + d.subnet;
    } else if (!primaryIfaceNodeId.empty()) {
      parentId = primaryIfaceNodeId;
      parentDesc = "descoberta ARP histórica";
    }

    if (!parentId.empty()) {
      TopoEdge e;
      e.id = "edge:arp:" + parentId + ":" + nodeId;
      e.source = parentId;
      e.target = nodeId;
      e.kind = "arp_subnet";
      e.label = d.online ? "ARP" : "Histórico";
      e.evidence = "Tabela ARP / descoberta na " + parentDesc + (d.mac.empty() ? "" : " (MAC " + d.mac + ")");
      e.rttMs = d.latencyMs;
      addEdge(std::move(e));
    }

    // Explicit active socket evidence edge directly from local host when kernel socket exists!
    if (sockIt != activeByRemoteIp.end() && sockIt->second.count > 0) {
      TopoEdge se;
      se.id = "edge:sock:" + nodeId;
      se.source = "host:local";
      se.target = nodeId;
      se.kind = "active_socket";
      se.label = std::to_string(sockIt->second.count) + " conn";
      se.evidence = "Socket ativo do kernel: " + sockIt->second.sampleProc + " (" +
                    sockIt->second.sampleProto + ":" + std::to_string(sockIt->second.samplePort) + ")";
      se.activeSessions = sockIt->second.count;
      addEdge(std::move(se));
    }
  }

  return snap;
}

std::string serializeLanTopologyJson(const LanTopologySnapshot& snap) {
  char num[32];
  auto appendNum = [&](std::string& dst, double v) {
    std::snprintf(num, sizeof(num), "%.1f", v);
    dst += num;
  };

  std::string out = "{\"generatedAt\":";
  out += std::to_string(snap.generatedAtMs);
  out += ",\"localHostname\":";
  appendJsonEscaped(out, snap.localHostname);
  out += ",\"modelNote\":";
  appendJsonEscaped(out, snap.modelNote);
  out += ",\"summary\":{\"nodes\":";
  out += std::to_string(snap.nodes.size());
  out += ",\"edges\":";
  out += std::to_string(snap.edges.size());
  out += ",\"onlineDevices\":";
  out += std::to_string(snap.onlineDevices);
  out += ",\"totalDevices\":";
  out += std::to_string(snap.totalDevices);
  out += ",\"activeSockets\":";
  out += std::to_string(snap.activeSockets);
  out += "},\"nodes\":[";

  for (size_t i = 0; i < snap.nodes.size(); ++i) {
    const auto& n = snap.nodes[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    appendJsonEscaped(out, n.id);
    out += ",\"kind\":";
    appendJsonEscaped(out, n.kind);
    out += ",\"label\":";
    appendJsonEscaped(out, n.label);
    out += ",\"sublabel\":";
    appendJsonEscaped(out, n.sublabel);
    out += ",\"ip\":";
    appendJsonEscaped(out, n.ip);
    out += ",\"mac\":";
    appendJsonEscaped(out, n.mac);
    out += ",\"vendor\":";
    appendJsonEscaped(out, n.vendor);
    out += ",\"deviceType\":";
    appendJsonEscaped(out, n.deviceType);
    out += ",\"status\":";
    appendJsonEscaped(out, n.status);
    out += ",\"subnet\":";
    appendJsonEscaped(out, n.subnet);
    out += ",\"openPorts\":";
    appendJsonEscaped(out, n.openPorts);
    out += ",\"layer\":";
    out += std::to_string(n.layer);
    out += ",\"isPrimary\":";
    out += (n.isPrimary ? "true" : "false");
    out += ",\"linkSpeedBps\":";
    out += std::to_string(n.linkSpeedBps);
    out += ",\"rxBps\":";
    appendNum(out, n.rxBps);
    out += ",\"txBps\":";
    appendNum(out, n.txBps);
    out += ",\"latencyMs\":";
    appendNum(out, n.latencyMs);
    out += ",\"activeConns\":";
    out += std::to_string(n.activeConns);
    out.push_back('}');
  }

  out += "],\"edges\":[";
  for (size_t i = 0; i < snap.edges.size(); ++i) {
    const auto& e = snap.edges[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    appendJsonEscaped(out, e.id);
    out += ",\"source\":";
    appendJsonEscaped(out, e.source);
    out += ",\"target\":";
    appendJsonEscaped(out, e.target);
    out += ",\"kind\":";
    appendJsonEscaped(out, e.kind);
    out += ",\"label\":";
    appendJsonEscaped(out, e.label);
    out += ",\"evidence\":";
    appendJsonEscaped(out, e.evidence);
    out += ",\"rttMs\":";
    appendNum(out, e.rttMs);
    out += ",\"activeSessions\":";
    out += std::to_string(e.activeSessions);
    out.push_back('}');
  }
  out += "]}";
  return out;
}

} // namespace netpulse
