#pragma once

#include "satellite_models.hpp"

#include <filesystem>
#include <mutex>
#include <string>

namespace netpulse::satellite {

class SatelliteConfiguration {
public:
  explicit SatelliteConfiguration(std::filesystem::path configPath);

  SatelliteTrackingConfig get() const;
  bool update(const SatelliteTrackingConfig& next, std::string& outError);
  bool setModuleEnabled(bool enabled);
  bool setObjectVisible(int noradId, bool visible);
  bool setAllVisible(const std::vector<int>& allNoradIds, bool visible);

  bool isObjectVisible(int noradId) const;
  std::string toJson() const;

  static bool parseLine(const std::string& line, std::string& key, std::string& val);
  static SatelliteTrackingConfig sanitize(SatelliteTrackingConfig cfg);

private:
  void load();
  void saveLocked() const;

  std::filesystem::path path_;
  mutable std::mutex mutex_;
  SatelliteTrackingConfig config_;
};

} // namespace netpulse::satellite
