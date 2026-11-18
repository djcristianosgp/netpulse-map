#pragma once

#include "orbital_propagator.hpp"
#include "satellite_catalog.hpp"
#include "satellite_configuration.hpp"
#include "satellite_models.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace netpulse::satellite {

class SatelliteManager {
public:
  SatelliteManager(SatelliteCatalog& catalog, SatelliteConfiguration& config);

  SatelliteCatalog& catalog() { return catalog_; }
  const SatelliteCatalog& catalog() const { return catalog_; }
  SatelliteConfiguration& config() { return config_; }
  const SatelliteConfiguration& config() const { return config_; }

  std::vector<int> availableNoradIds() const;
  bool hasActiveTargets() const;

  // Computes runtime state for all registered satellites; only propagates active satellites when module is enabled.
  std::vector<SatelliteRuntimeObject> computeSnapshot(uint64_t nowMs, bool includeTracks) const;

  // Serializes complete runtime state (config + objects + positions + tracks) to JSON.
  static std::string serializeSnapshotJson(const SatelliteTrackingConfig& cfg,
                                           const std::vector<SatelliteRuntimeObject>& objects,
                                           uint64_t generatedAtMs);

private:
  SatelliteCatalog& catalog_;
  SatelliteConfiguration& config_;
};

} // namespace netpulse::satellite
