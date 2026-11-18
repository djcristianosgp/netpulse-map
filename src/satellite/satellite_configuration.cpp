#include "satellite_configuration.hpp"
#include "../models.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse::satellite {

bool SatelliteConfiguration::parseLine(const std::string& line, std::string& key, std::string& val) {
  if (line.empty() || line[0] == '#') return false;
  const size_t tab = line.find('\t');
  if (tab == std::string::npos) return false;
  key = line.substr(0, tab);
  val = line.substr(tab + 1);
  while (!val.empty() && (val.back() == '\r' || val.back() == '\n')) val.pop_back();
  return !key.empty();
}

SatelliteTrackingConfig SatelliteConfiguration::sanitize(SatelliteTrackingConfig cfg) {
  cfg.pastTrackMinutes = std::clamp(cfg.pastTrackMinutes, 5, 180);
  cfg.futureTrackMinutes = std::clamp(cfg.futureTrackMinutes, 10, 360);
  cfg.positionIntervalMs = std::clamp(cfg.positionIntervalMs, 500, 30000);
  cfg.catalogRefreshSec = std::clamp(cfg.catalogRefreshSec, 900, 86400);

  std::vector<int> dedup;
  dedup.reserve(cfg.visibleNoradIds.size());
  for (int id : cfg.visibleNoradIds) {
    if (id <= 0) continue;
    if (std::find(dedup.begin(), dedup.end(), id) == dedup.end()) {
      dedup.push_back(id);
    }
  }
  cfg.visibleNoradIds = std::move(dedup);
  return cfg;
}

SatelliteConfiguration::SatelliteConfiguration(std::filesystem::path configPath)
    : path_(std::move(configPath)) {
  load();
}

void SatelliteConfiguration::load() {
  std::lock_guard lock(mutex_);
  std::error_code ec;
  if (!std::filesystem::exists(path_, ec)) {
    config_ = sanitize(config_);
    return;
  }

  std::ifstream in(path_);
  if (!in.is_open()) return;

  std::string line;
  while (std::getline(in, line)) {
    std::string k, v;
    if (!parseLine(line, k, v)) continue;
    if (k == "enabled") {
      config_.enabled = (v == "1" || v == "true");
    } else if (k == "showTrajectory") {
      config_.showTrajectory = (v == "1" || v == "true");
    } else if (k == "pastTrackMinutes") {
      config_.pastTrackMinutes = std::atoi(v.c_str());
    } else if (k == "futureTrackMinutes") {
      config_.futureTrackMinutes = std::atoi(v.c_str());
    } else if (k == "positionIntervalMs") {
      config_.positionIntervalMs = std::atoi(v.c_str());
    } else if (k == "catalogRefreshSec") {
      config_.catalogRefreshSec = std::atoi(v.c_str());
    } else if (k == "visibleNoradIds") {
      config_.visibleNoradIds.clear();
      if (v != "none" && !v.empty()) {
        std::istringstream ss(v);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
          int id = std::atoi(tok.c_str());
          if (id > 0) config_.visibleNoradIds.push_back(id);
        }
      }
    }
  }
  config_ = sanitize(config_);
}

void SatelliteConfiguration::saveLocked() const {
  std::error_code ec;
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path(), ec);
  }
  const auto tmpPath = std::filesystem::path(path_.string() + ".tmp");
  std::ofstream out(tmpPath, std::ios::trunc);
  if (!out.is_open()) return;

  out << "enabled\t" << (config_.enabled ? "1" : "0") << '\n'
      << "showTrajectory\t" << (config_.showTrajectory ? "1" : "0") << '\n'
      << "pastTrackMinutes\t" << config_.pastTrackMinutes << '\n'
      << "futureTrackMinutes\t" << config_.futureTrackMinutes << '\n'
      << "positionIntervalMs\t" << config_.positionIntervalMs << '\n'
      << "catalogRefreshSec\t" << config_.catalogRefreshSec << '\n'
      << "visibleNoradIds\t";
  if (config_.visibleNoradIds.empty()) {
    out << "none";
  } else {
    for (size_t i = 0; i < config_.visibleNoradIds.size(); ++i) {
      if (i > 0) out << ',';
      out << config_.visibleNoradIds[i];
    }
  }
  out << '\n';
  out.close();

  std::filesystem::rename(tmpPath, path_, ec);
  if (ec) {
    std::filesystem::remove(path_, ec);
    std::filesystem::rename(tmpPath, path_, ec);
  }
}

SatelliteTrackingConfig SatelliteConfiguration::get() const {
  std::lock_guard lock(mutex_);
  return config_;
}

bool SatelliteConfiguration::update(const SatelliteTrackingConfig& next, std::string& outError) {
  std::lock_guard lock(mutex_);
  if (next.pastTrackMinutes < 5 || next.pastTrackMinutes > 180) {
    outError = "pastTrackMinutes deve estar entre 5 e 180";
    return false;
  }
  if (next.futureTrackMinutes < 10 || next.futureTrackMinutes > 360) {
    outError = "futureTrackMinutes deve estar entre 10 e 360";
    return false;
  }
  if (next.positionIntervalMs < 500 || next.positionIntervalMs > 30000) {
    outError = "positionIntervalMs deve estar entre 500 e 30000";
    return false;
  }
  if (next.catalogRefreshSec < 900 || next.catalogRefreshSec > 86400) {
    outError = "catalogRefreshSec deve estar entre 900 e 86400";
    return false;
  }
  config_ = sanitize(next);
  saveLocked();
  return true;
}

bool SatelliteConfiguration::setModuleEnabled(bool enabled) {
  std::lock_guard lock(mutex_);
  config_.enabled = enabled;
  saveLocked();
  return true;
}

bool SatelliteConfiguration::setObjectVisible(int noradId, bool visible) {
  if (noradId <= 0) return false;
  std::lock_guard lock(mutex_);
  auto& ids = config_.visibleNoradIds;
  auto it = std::find(ids.begin(), ids.end(), noradId);
  if (visible && it == ids.end()) {
    ids.push_back(noradId);
  } else if (!visible && it != ids.end()) {
    ids.erase(it);
  }
  saveLocked();
  return true;
}

bool SatelliteConfiguration::setAllVisible(const std::vector<int>& allNoradIds, bool visible) {
  std::lock_guard lock(mutex_);
  if (visible) {
    config_.visibleNoradIds = allNoradIds;
    config_ = sanitize(config_);
  } else {
    config_.visibleNoradIds.clear();
  }
  saveLocked();
  return true;
}

bool SatelliteConfiguration::isObjectVisible(int noradId) const {
  std::lock_guard lock(mutex_);
  return std::find(config_.visibleNoradIds.begin(), config_.visibleNoradIds.end(), noradId) !=
         config_.visibleNoradIds.end();
}

std::string SatelliteConfiguration::toJson() const {
  std::lock_guard lock(mutex_);
  std::string out = "{";
  out += "\"enabled\":";
  out += (config_.enabled ? "true" : "false");
  out += ",\"showTrajectory\":";
  out += (config_.showTrajectory ? "true" : "false");
  out += ",\"pastTrackMinutes\":" + std::to_string(config_.pastTrackMinutes);
  out += ",\"futureTrackMinutes\":" + std::to_string(config_.futureTrackMinutes);
  out += ",\"positionIntervalMs\":" + std::to_string(config_.positionIntervalMs);
  out += ",\"catalogRefreshSec\":" + std::to_string(config_.catalogRefreshSec);
  out += ",\"visibleNoradIds\":[";
  for (size_t i = 0; i < config_.visibleNoradIds.size(); ++i) {
    if (i > 0) out.push_back(',');
    out += std::to_string(config_.visibleNoradIds[i]);
  }
  out += "]}";
  return out;
}

} // namespace netpulse::satellite
