#include "satellite_manager.hpp"
#include "../models.hpp"

#include <algorithm>
#include <cstdio>

namespace netpulse::satellite {

SatelliteManager::SatelliteManager(SatelliteCatalog& catalog, SatelliteConfiguration& config)
    : catalog_(catalog), config_(config) {}

std::vector<int> SatelliteManager::availableNoradIds() const {
  const auto entries = catalog_.getEntriesSnapshot();
  std::vector<int> ids;
  ids.reserve(entries.size());
  for (const auto& e : entries) {
    ids.push_back(e.spec.noradId);
  }
  return ids;
}

bool SatelliteManager::hasActiveTargets() const {
  const auto cfg = config_.get();
  if (!cfg.enabled || cfg.visibleNoradIds.empty()) return false;
  const auto entries = catalog_.getEntriesSnapshot();
  for (const auto& e : entries) {
    if (std::find(cfg.visibleNoradIds.begin(), cfg.visibleNoradIds.end(), e.spec.noradId) !=
        cfg.visibleNoradIds.end()) {
      return true;
    }
  }
  return false;
}

std::vector<SatelliteRuntimeObject> SatelliteManager::computeSnapshot(uint64_t nowMs, bool includeTracks) const {
  const auto cfg = config_.get();
  const auto entries = catalog_.getEntriesSnapshot();

  std::vector<SatelliteRuntimeObject> out;
  out.reserve(entries.size());

  for (const auto& entry : entries) {
    SatelliteRuntimeObject obj;
    obj.spec = entry.spec;
    obj.enabled = std::find(cfg.visibleNoradIds.begin(), cfg.visibleNoradIds.end(), entry.spec.noradId) !=
                  cfg.visibleNoradIds.end();
    obj.dataState = entry.dataState;
    obj.lastAttemptMs = entry.lastAttemptMs;
    obj.lastSuccessMs = entry.lastSuccessMs;
    obj.lastError = entry.lastError;
    obj.hasElements = entry.elements.valid;

    if (entry.elements.valid) {
      obj.elementFormat = entry.elements.format;
      obj.elementSource = entry.elements.source;
      obj.elementEpochIso = entry.elements.epochIso;
      obj.elementEpochMs = entry.elements.epochMs;
      obj.elementsFetchedAtMs = entry.elements.fetchedAtMs;
      obj.inclinationDeg = entry.elements.inclinationDeg;
      obj.eccentricity = entry.elements.eccentricity;
      obj.meanMotionRevDay = entry.elements.meanMotionRevDay;

      if (cfg.enabled && obj.enabled) {
        std::string propErr;
        if (OrbitalPropagator::propagate(entry.elements, nowMs, obj.position, propErr)) {
          if (includeTracks && cfg.showTrajectory) {
            OrbitalPropagator::propagateTrack(
                entry.elements, nowMs, cfg.pastTrackMinutes, cfg.futureTrackMinutes, 60, obj.track, propErr);
          }
        } else if (obj.lastError.empty()) {
          obj.lastError = propErr;
        }
      }
    }

    out.push_back(std::move(obj));
  }
  return out;
}

std::string SatelliteManager::serializeSnapshotJson(const SatelliteTrackingConfig& cfg,
                                                    const std::vector<SatelliteRuntimeObject>& objects,
                                                    uint64_t generatedAtMs) {
  char buf[64];
  std::string out;
  out.reserve(8192);

  out += "{\"type\":\"satellites\",\"generatedAtMs\":" + std::to_string(generatedAtMs);
  out += ",\"config\":{";
  out += "\"enabled\":"; out += (cfg.enabled ? "true" : "false");
  out += ",\"showTrajectory\":"; out += (cfg.showTrajectory ? "true" : "false");
  out += ",\"pastTrackMinutes\":" + std::to_string(cfg.pastTrackMinutes);
  out += ",\"futureTrackMinutes\":" + std::to_string(cfg.futureTrackMinutes);
  out += ",\"positionIntervalMs\":" + std::to_string(cfg.positionIntervalMs);
  out += ",\"catalogRefreshSec\":" + std::to_string(cfg.catalogRefreshSec);
  out += ",\"visibleNoradIds\":[";
  for (size_t i = 0; i < cfg.visibleNoradIds.size(); ++i) {
    if (i > 0) out.push_back(',');
    out += std::to_string(cfg.visibleNoradIds[i]);
  }
  out += "]}";

  out += ",\"satellites\":[";
  for (size_t i = 0; i < objects.size(); ++i) {
    const auto& o = objects[i];
    if (i > 0) out.push_back(',');
    out += "{\"noradId\":" + std::to_string(o.spec.noradId);
    out += ",\"code\":"; appendJsonEscaped(out, o.spec.code);
    out += ",\"name\":"; appendJsonEscaped(out, o.spec.displayName);
    out += ",\"shortName\":"; appendJsonEscaped(out, o.spec.shortName);
    out += ",\"intlId\":"; appendJsonEscaped(out, o.spec.intlId);
    out += ",\"category\":"; appendJsonEscaped(out, o.spec.category);
    out += ",\"color\":"; appendJsonEscaped(out, o.spec.colorHex);
    out += ",\"enabled\":"; out += (o.enabled ? "true" : "false");
    out += ",\"active\":"; out += ((cfg.enabled && o.enabled && o.position.valid) ? "true" : "false");
    out += ",\"dataState\":"; appendJsonEscaped(out, catalogDataStateToString(o.dataState));
    out += ",\"lastAttemptMs\":" + std::to_string(o.lastAttemptMs);
    out += ",\"lastSuccessMs\":" + std::to_string(o.lastSuccessMs);
    out += ",\"lastError\":"; appendJsonEscaped(out, o.lastError);
    out += ",\"hasElements\":"; out += (o.hasElements ? "true" : "false");
    out += ",\"elementFormat\":"; appendJsonEscaped(out, o.elementFormat);
    out += ",\"elementSource\":"; appendJsonEscaped(out, o.elementSource);
    out += ",\"elementEpochIso\":"; appendJsonEscaped(out, o.elementEpochIso);
    out += ",\"elementEpochMs\":" + std::to_string(o.elementEpochMs);
    out += ",\"elementsFetchedAtMs\":" + std::to_string(o.elementsFetchedAtMs);

    std::snprintf(buf, sizeof(buf), "%.4f", o.inclinationDeg);
    out += ",\"inclinationDeg\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.7f", o.eccentricity);
    out += ",\"eccentricity\":"; out += buf;
    std::snprintf(buf, sizeof(buf), "%.8f", o.meanMotionRevDay);
    out += ",\"meanMotionRevDay\":"; out += buf;

    if (o.position.valid) {
      out += ",\"position\":{\"valid\":true";
      out += ",\"timestampMs\":" + std::to_string(o.position.timestampMs);
      std::snprintf(buf, sizeof(buf), "%.5f", o.position.latitudeDeg);
      out += ",\"lat\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.5f", o.position.longitudeDeg);
      out += ",\"lon\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.2f", o.position.altitudeKm);
      out += ",\"altitudeKm\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.3f", o.position.velocityKmS);
      out += ",\"velocityKmS\":"; out += buf;
      std::snprintf(buf, sizeof(buf), "%.2f", o.position.orbitalPeriodMin);
      out += ",\"orbitalPeriodMin\":"; out += buf;
      out.push_back('}');
    } else {
      out += ",\"position\":null";
    }

    auto serializeSegments = [&](const std::vector<std::vector<TrackPoint>>& segs) {
      out.push_back('[');
      for (size_t s = 0; s < segs.size(); ++s) {
        if (s > 0) out.push_back(',');
        out.push_back('[');
        for (size_t p = 0; p < segs[s].size(); ++p) {
          if (p > 0) out.push_back(',');
          std::snprintf(buf, sizeof(buf), "[%.4f,%.4f]", segs[s][p].lon, segs[s][p].lat);
          out += buf;
        }
        out.push_back(']');
      }
      out.push_back(']');
    };

    out += ",\"track\":{\"past\":";
    serializeSegments(o.track.pastSegments);
    out += ",\"future\":";
    serializeSegments(o.track.futureSegments);
    out.push_back('}');
    out.push_back('}');
  }
  out += "]}";
  return out;
}

} // namespace netpulse::satellite
