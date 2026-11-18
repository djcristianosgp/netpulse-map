#pragma once

#include "satellite_models.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace netpulse::satellite {

class OrbitalPropagator {
public:
  // Time scale helpers (UTC <-> Julian Date)
  static void unixMsToJulianDate(uint64_t unixMs, double& outJd, double& outJdFrac);
  static bool calendarUtcToJulianDate(int year,
                                      int month,
                                      int day,
                                      int hour,
                                      int minute,
                                      double second,
                                      double& outJd,
                                      double& outJdFrac,
                                      uint64_t& outUnixMs);

  // Greenwich Mean Sidereal Time (IAU 1982 / Vallado gstime) in [0, 2*pi)
  static double computeGmstRadians(double jdUt1, double jdUt1Frac);

  // TEME (km) -> PEF/ECEF (km) -> WGS-84 Geodetic (lat deg, lon deg, alt km)
  static GeodeticState temeToGeodetic(const Vec3& rTemeKm, double jdUtc, double jdUtcFrac);

  // Propagates a single state at `timestampMs` (Unix ms UTC) using SGP4 (WGS-72).
  static bool propagate(const OrbitalElements& el,
                        uint64_t timestampMs,
                        SatellitePosition& outPos,
                        std::string& outError);

  // Propagates directly at `tsinceMin` (minutes from epoch) in TEME; useful for reference vector verification.
  static bool propagateTemeAtTsince(const OrbitalElements& el,
                                    double tsinceMin,
                                    Vec3& outRTemeKm,
                                    Vec3& outVTemeKmS,
                                    std::string& outError);

  // Generates past & future ground tracks split cleanly across the antimeridian (+/- 180 deg).
  static bool propagateTrack(const OrbitalElements& el,
                             uint64_t centerTimestampMs,
                             int pastMinutes,
                             int futureMinutes,
                             int stepSeconds,
                             SatelliteTrack& outTrack,
                             std::string& outError);

  // Splits a sequence of geographic track points at +/- 180 deg with exact boundary interpolation.
  static std::vector<std::vector<TrackPoint>> splitAntimeridianSegments(const std::vector<TrackPoint>& pts);
};

} // namespace netpulse::satellite
