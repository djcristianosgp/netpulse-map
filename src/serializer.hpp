#pragma once

#include "geo_dns.hpp"
#include "models.hpp"
#include "service_monitor.hpp"
#include "version.hpp"

#include <cstdio>
#include <string>
#include <unordered_set>

namespace netpulse {

inline std::string serializeSnapshotJson(const TelemetrySnapshot& snap,
                                         const GeoDnsService& geoDns,
                                         uint32_t intervalMs,
                                         size_t wsClients,
                                         const ServiceMonitor* serviceMon = nullptr) {
  std::string out;
  out.reserve(4096 + snap.connections.size() * 192);

  char numBuf[128];

  out += "{\"version\":";
  appendJsonEscaped(out, kAppVersion);
  out += ",\"ts\":";
  out += std::to_string(snap.timestampMs);
  out += ",\"pollUs\":";
  out += std::to_string(snap.pollLatencyUs);
  out += ",\"intervalMs\":";
  out += std::to_string(intervalMs);

  out += ",\"stats\":{\"total\":";
  out += std::to_string(snap.totalConnections);
  out += ",\"public\":";
  out += std::to_string(snap.publicConnections);
  out += ",\"lan\":";
  out += std::to_string(snap.lanConnections);
  out += ",\"listening\":";
  out += std::to_string(snap.listeningSockets);
  out += ",\"geoCached\":";
  out += std::to_string(geoDns.cachedGeoCount());
  out += ",\"dnsCached\":";
  out += std::to_string(geoDns.cachedDnsCount());
  out += ",\"wsClients\":";
  out += std::to_string(wsClients);
  out.push_back('}');

  std::snprintf(numBuf, sizeof(numBuf), "%.1f", snap.nic.rxBytesPerSec);
  out += ",\"nic\":{\"rxBps\":";
  out += numBuf;
  std::snprintf(numBuf, sizeof(numBuf), "%.1f", snap.nic.txBytesPerSec);
  out += ",\"txBps\":";
  out += numBuf;
  out += ",\"totalRx\":";
  out += std::to_string(snap.nic.totalRxBytes);
  out += ",\"totalTx\":";
  out += std::to_string(snap.nic.totalTxBytes);
  out += ",\"ifaces\":";
  out += std::to_string(snap.nic.activeInterfaces);
  out.push_back('}');

  out += ",\"host\":{\"resolved\":";
  out += (snap.hostGeo.resolved ? "true" : "false");
  out += ",\"ip\":";
  appendJsonEscaped(out, snap.hostGeo.publicIp);
  out += ",\"country\":";
  appendJsonEscaped(out, snap.hostGeo.country);
  out += ",\"cc\":";
  appendJsonEscaped(out, snap.hostGeo.countryCode);
  out += ",\"region\":";
  appendJsonEscaped(out, snap.hostGeo.region);
  out += ",\"city\":";
  appendJsonEscaped(out, snap.hostGeo.city);
  out += ",\"isp\":";
  appendJsonEscaped(out, snap.hostGeo.isp);
  std::snprintf(numBuf, sizeof(numBuf), "%.5f", snap.hostGeo.lat);
  out += ",\"lat\":";
  out += numBuf;
  std::snprintf(numBuf, sizeof(numBuf), "%.5f", snap.hostGeo.lon);
  out += ",\"lon\":";
  out += numBuf;
  out.push_back('}');

  // Deduplicated GeoIP & rDNS tables for IPs present in this snapshot.
  std::unordered_set<std::string> uniquePublicIps;
  for (const auto& c : snap.connections) {
    if (c.scope == IpScope::Public) {
      uniquePublicIps.insert(c.remoteIp);
    }
  }

  out += ",\"geo\":{";
  bool firstGeo = true;
  for (const auto& ip : uniquePublicIps) {
    auto g = geoDns.getGeo(ip);
    if (!g.has_value()) continue;
    if (!firstGeo) out.push_back(',');
    firstGeo = false;
    appendJsonEscaped(out, ip);
    out += ":{\"cc\":";
    appendJsonEscaped(out, g->countryCode);
    out += ",\"country\":";
    appendJsonEscaped(out, g->country);
    out += ",\"region\":";
    appendJsonEscaped(out, g->region);
    out += ",\"city\":";
    appendJsonEscaped(out, g->city);
    out += ",\"isp\":";
    appendJsonEscaped(out, g->isp);
    out += ",\"org\":";
    appendJsonEscaped(out, g->org);
    out += ",\"asn\":";
    appendJsonEscaped(out, g->asn);
    std::snprintf(numBuf, sizeof(numBuf), "%.5f", g->lat);
    out += ",\"lat\":";
    out += numBuf;
    std::snprintf(numBuf, sizeof(numBuf), "%.5f", g->lon);
    out += ",\"lon\":";
    out += numBuf;
    out.push_back('}');
  }
  out.push_back('}');

  out += ",\"dns\":{";
  bool firstDns = true;
  for (const auto& ip : uniquePublicIps) {
    auto host = geoDns.getHostname(ip);
    if (!host.has_value()) continue;
    if (!firstDns) out.push_back(',');
    firstDns = false;
    appendJsonEscaped(out, ip);
    out.push_back(':');
    appendJsonEscaped(out, *host);
  }
  out.push_back('}');

  out += ",\"conns\":[";
  for (size_t i = 0; i < snap.connections.size(); ++i) {
    const auto& c = snap.connections[i];
    if (i > 0) out.push_back(',');
    out += "{\"k\":";
    appendJsonEscaped(out, c.key);
    out += ",\"proto\":";
    appendJsonEscaped(out, c.protocol);
    out += ",\"v\":";
    out += std::to_string(c.ipVersion);
    out += ",\"lip\":";
    appendJsonEscaped(out, c.localIp);
    out += ",\"lport\":";
    out += std::to_string(c.localPort);
    out += ",\"rip\":";
    appendJsonEscaped(out, c.remoteIp);
    out += ",\"rport\":";
    out += std::to_string(c.remotePort);
    out += ",\"state\":";
    appendJsonEscaped(out, c.state);
    out += ",\"pid\":";
    out += std::to_string(c.pid);
    out += ",\"proc\":";
    appendJsonEscaped(out, c.processName);
    out += ",\"path\":";
    appendJsonEscaped(out, c.processPath);
    out += ",\"scope\":\"";
    out += scopeToString(c.scope);
    out += "\",\"life\":\"";
    out += lifecycleToString(c.lifecycle);
    out += "\",\"ageMs\":";
    uint64_t age = (c.lastSeenMs >= c.firstSeenMs) ? (c.lastSeenMs - c.firstSeenMs) : 0;
    out += std::to_string(age);
    out.push_back('}');
  }
  out.push_back(']');
  if (serviceMon) {
    out += ",\"services\":";
    out += serviceMon->getServicesJson();
  }
  out.push_back('}');
  return out;
}

} // namespace netpulse
