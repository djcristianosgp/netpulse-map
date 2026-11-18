#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace netpulse::satellite {

inline constexpr int kNoradIss = 25544;
inline constexpr int kNoradTiangong = 48274;

struct SatelliteTargetSpec {
  int noradId = 0;
  std::string code;         // "ISS" | "TIANGONG"
  std::string displayName;  // "ISS — Estação Espacial Internacional"
  std::string shortName;    // "ISS" | "Tiangong"
  std::string intlId;       // "1998-067A" | "2021-035A"
  std::string category;     // "Estação Espacial (LEO)"
  std::string colorHex;     // "#22d3ee" | "#fbbf24"
};

struct OrbitalElements {
  int noradId = 0;
  std::string objectName;
  std::string intlDesignator;
  std::string epochIso;          // UTC ISO-8601
  double epochJd = 0.0;          // Integer/half-day Julian Date (UTC)
  double epochJdFrac = 0.0;      // Fractional day Julian Date (UTC)
  uint64_t epochMs = 0;          // Epoch in Unix milliseconds (UTC)

  double meanMotionRevDay = 0.0; // Mean motion (rev/day)
  double eccentricity = 0.0;     // [0, 1)
  double inclinationDeg = 0.0;   // [0, 180]
  double raanDeg = 0.0;          // Right ascension of ascending node (deg)
  double argPerigeeDeg = 0.0;    // Argument of perigee (deg)
  double meanAnomalyDeg = 0.0;   // Mean anomaly (deg)
  double bstar = 0.0;            // Drag term (1 / Earth radii)
  double ndot = 0.0;             // First derivative of mean motion (rev/day^2)
  double nddot = 0.0;            // Second derivative of mean motion (rev/day^3)

  char classification = 'U';
  int ephemerisType = 0;
  int elementSetNo = 0;
  int revAtEpoch = 0;

  std::string format;            // "OMM_JSON" | "TLE"
  std::string source;            // e.g. "CelesTrak"
  uint64_t fetchedAtMs = 0;
  std::string tleLine1;
  std::string tleLine2;
  bool valid = false;
};

enum class CatalogDataState : uint8_t {
  Unavailable = 0,
  Live = 1,
  Cached = 2,
  CachedFallback = 3,
};

inline const char* catalogDataStateToString(CatalogDataState s) {
  switch (s) {
    case CatalogDataState::Live:
      return "live";
    case CatalogDataState::Cached:
      return "cached";
    case CatalogDataState::CachedFallback:
      return "cached_fallback";
    default:
      return "unavailable";
  }
}

struct CatalogEntry {
  SatelliteTargetSpec spec;
  OrbitalElements elements;
  CatalogDataState dataState = CatalogDataState::Unavailable;
  uint64_t lastAttemptMs = 0;
  uint64_t lastSuccessMs = 0;
  std::string lastError;
};

struct Vec3 {
  double x = 0.0;
  double y = 0.0;
  double z = 0.0;
};

struct GeodeticState {
  double latitudeDeg = 0.0;
  double longitudeDeg = 0.0;
  double altitudeKm = 0.0;
};

struct SatellitePosition {
  bool valid = false;
  uint64_t timestampMs = 0;
  double tsinceMin = 0.0;

  double latitudeDeg = 0.0;
  double longitudeDeg = 0.0;
  double altitudeKm = 0.0;
  double velocityKmS = 0.0;
  double inclinationDeg = 0.0;
  double orbitalPeriodMin = 0.0;

  Vec3 rTemeKm{};
  Vec3 vTemeKmS{};
};

struct TrackPoint {
  double lon = 0.0;
  double lat = 0.0;
  double altKm = 0.0;
  int64_t offsetSec = 0;
};

struct SatelliteTrack {
  // Segments pre-split across the antimeridian (+/- 180 deg) with exact boundary interpolation.
  std::vector<std::vector<TrackPoint>> pastSegments;
  std::vector<std::vector<TrackPoint>> futureSegments;
};

struct SatelliteRuntimeObject {
  SatelliteTargetSpec spec;
  bool enabled = true;
  CatalogDataState dataState = CatalogDataState::Unavailable;
  uint64_t lastAttemptMs = 0;
  uint64_t lastSuccessMs = 0;
  std::string lastError;

  bool hasElements = false;
  std::string elementFormat;
  std::string elementSource;
  std::string elementEpochIso;
  uint64_t elementEpochMs = 0;
  uint64_t elementsFetchedAtMs = 0;
  double inclinationDeg = 0.0;
  double eccentricity = 0.0;
  double meanMotionRevDay = 0.0;

  SatellitePosition position;
  SatelliteTrack track;
};

struct SatelliteTrackingConfig {
  bool enabled = true;
  std::vector<int> visibleNoradIds = {kNoradIss, kNoradTiangong};
  bool showTrajectory = true;
  int pastTrackMinutes = 45;
  int futureTrackMinutes = 90;
  int positionIntervalMs = 2000;
  int catalogRefreshSec = 21600; // 6 hours
};

} // namespace netpulse::satellite
