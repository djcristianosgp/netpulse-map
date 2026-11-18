#pragma once

#include "satellite_models.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace netpulse::satellite {

struct HttpFetchResult {
  bool ok = false;
  int statusCode = 0;
  std::string body;
  std::string error;
};

using HttpFetchFn = std::function<HttpFetchResult(const std::string& url)>;

class SatelliteCatalog {
public:
  explicit SatelliteCatalog(std::filesystem::path cachePath);

  void setTargetSpecs(std::vector<SatelliteTargetSpec> specs);
  void setHttpFetcher(HttpFetchFn fetcher);
  void setPrimaryEndpoints(std::string stationsOmmUrl, std::string catnrJsonTemplateUrl, std::string catnrTleTemplateUrl);

  // Loads cached orbital elements from disk (does not hit network).
  bool loadCache();

  // Checks if automatic refresh is due based on refreshIntervalSec and last attempt/fetch time.
  bool shouldAutoRefresh(uint64_t nowMs, int refreshIntervalSec) const;

  // Fetches and validates orbital elements from CelesTrak (or injected fetcher).
  // Preserves last valid elements on any failure.
  bool refreshFromSource(uint64_t nowMs, bool force, std::string& outSummaryError);

  // Direct injection helper (useful for tests or offline import).
  bool upsertValidatedElements(const OrbitalElements& el, CatalogDataState state, uint64_t nowMs, std::string& outError);

  std::vector<CatalogEntry> getEntriesSnapshot() const;
  std::optional<CatalogEntry> getEntry(int noradId) const;
  std::string toCatalogJson() const;

  // Pure parsing & validation helpers (exposed for unit tests).
  static int computeTleChecksum(const std::string& line);
  static bool parseIsoUtc(const std::string& iso, double& outJd, double& outJdFrac, uint64_t& outUnixMs);
  static bool parseTleEpoch(const std::string& epochStr, double& outJd, double& outJdFrac, uint64_t& outUnixMs, std::string& outIso);
  static bool parseOmmJson(const std::string& jsonBody, std::vector<OrbitalElements>& out, std::string& outError);
  static bool parseTleText(const std::string& tleText, std::vector<OrbitalElements>& out, std::string& outError);
  static bool validateOrbitalElements(const OrbitalElements& el, std::string& outError);
  static HttpFetchResult defaultHttpsGet(const std::string& url);

private:
  void initDefaultSpecsLocked();
  void saveCacheLocked() const;
  bool applyParsedElementsLocked(const std::vector<OrbitalElements>& parsed,
                                 CatalogDataState newState,
                                 uint64_t nowMs,
                                 std::vector<int>& updatedIds);

  std::filesystem::path cachePath_;
  HttpFetchFn fetcher_;
  std::string stationsOmmUrl_ = "https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=json";
  std::string catnrJsonUrlTpl_ = "https://celestrak.org/NORAD/elements/gp.php?CATNR={CATNR}&FORMAT=json";
  std::string catnrTleUrlTpl_ = "https://celestrak.org/NORAD/elements/gp.php?CATNR={CATNR}&FORMAT=tle";

  mutable std::mutex mutex_;
  std::vector<CatalogEntry> entries_;
  uint64_t lastManualFetchMs_ = 0;
};

} // namespace netpulse::satellite
