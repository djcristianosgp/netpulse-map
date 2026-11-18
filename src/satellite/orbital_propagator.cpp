#include "orbital_propagator.hpp"

#include <algorithm>
#include <cmath>

namespace netpulse::satellite {

namespace {

constexpr double kPi = 3.14159265358979323846;
constexpr double kTwoPi = 2.0 * kPi;
constexpr double kDeg2Rad = kPi / 180.0;
constexpr double kRad2Deg = 180.0 / kPi;
constexpr double kX2o3 = 2.0 / 3.0;

// WGS-72 constants (standard NORAD/CelesTrak SGP4 convention, Vallado AIAA 2006-6753)
constexpr double kMuWgs72 = 398600.8;          // km^3 / s^2
constexpr double kEarthRadiusWgs72 = 6378.135; // km
constexpr double kJ2Wgs72 = 0.001082616;
constexpr double kJ3Wgs72 = -0.00000253881;
constexpr double kJ4Wgs72 = -0.00000165597;
constexpr double kJ3oJ2Wgs72 = kJ3Wgs72 / kJ2Wgs72;

// WGS-84 ellipsoid constants for Geodetic (lat, lon, alt)
constexpr double kWgs84A = 6378.137;                 // km
constexpr double kWgs84F = 1.0 / 298.257223563;
constexpr double kWgs84E2 = kWgs84F * (2.0 - kWgs84F);

int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? static_cast<unsigned>(-3) : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool isValidCalendarDate(int year, int month, int day, int hour, int minute, double second) {
  if (year < 1957 || year > 2100) return false;
  if (month < 1 || month > 12) return false;
  static constexpr int kDaysInMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int maxDay = kDaysInMonth[month - 1];
  if (month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
    maxDay = 29;
  }
  if (day < 1 || day > maxDay) return false;
  if (hour < 0 || hour > 23) return false;
  if (minute < 0 || minute > 59) return false;
  if (!std::isfinite(second) || second < 0.0 || second >= 61.0) return false;
  return true;
}

struct Sgp4State {
  double a = 0.0;
  double alta = 0.0;
  double altp = 0.0;
  double aycof = 0.0;
  double cc1 = 0.0;
  double cc4 = 0.0;
  double cc5 = 0.0;
  double con41 = 0.0;
  double d2 = 0.0;
  double d3 = 0.0;
  double d4 = 0.0;
  double delmo = 0.0;
  double eta = 0.0;
  double argpdot = 0.0;
  double omgcof = 0.0;
  double sinmao = 0.0;
  double t2cof = 0.0;
  double t3cof = 0.0;
  double t4cof = 0.0;
  double t5cof = 0.0;
  double x1mth2 = 0.0;
  double x7thm1 = 0.0;
  double mdot = 0.0;
  double nodedot = 0.0;
  double xlcof = 0.0;
  double xmcof = 0.0;
  double nodecf = 0.0;
  double no_unkozai = 0.0;
  double ecco = 0.0;
  double inclo = 0.0;
  double nodeo = 0.0;
  double argpo = 0.0;
  double mo = 0.0;
  double bstar = 0.0;
  double xke = 0.0;
  int isimp = 0;
};

bool initSgp4(const OrbitalElements& el, Sgp4State& sat, std::string& outError) {
  if (!el.valid) {
    outError = "invalid_orbital_elements";
    return false;
  }
  if (el.eccentricity < 0.0 || el.eccentricity >= 1.0) {
    outError = "eccentricity_out_of_range";
    return false;
  }
  if (el.meanMotionRevDay <= 0.0 || !std::isfinite(el.meanMotionRevDay)) {
    outError = "invalid_mean_motion";
    return false;
  }

  const double xke = 60.0 / std::sqrt((kEarthRadiusWgs72 * kEarthRadiusWgs72 * kEarthRadiusWgs72) / kMuWgs72);
  sat.xke = xke;
  sat.ecco = el.eccentricity;
  sat.inclo = el.inclinationDeg * kDeg2Rad;
  sat.nodeo = el.raanDeg * kDeg2Rad;
  sat.argpo = el.argPerigeeDeg * kDeg2Rad;
  sat.mo = el.meanAnomalyDeg * kDeg2Rad;
  sat.bstar = el.bstar;

  const double no_kozai = el.meanMotionRevDay * kTwoPi / 1440.0;
  const double eccsq = sat.ecco * sat.ecco;
  const double omeosq = 1.0 - eccsq;
  if (omeosq <= 0.0) {
    outError = "invalid_eccentricity_omeosq";
    return false;
  }
  const double rteosq = std::sqrt(omeosq);
  const double cosio = std::cos(sat.inclo);
  const double cosio2 = cosio * cosio;
  const double sinio = std::sin(sat.inclo);

  // Recover Brouwer mean motion (Vallado initl)
  const double ak = std::pow(xke / no_kozai, kX2o3);
  const double d1 = 0.75 * kJ2Wgs72 * (3.0 * cosio2 - 1.0) / (rteosq * omeosq);
  double del = d1 / (ak * ak);
  const double adel = ak * (1.0 - del * del - del * (1.0 / 3.0 + 134.0 * del * del / 81.0));
  del = d1 / (adel * adel);
  sat.no_unkozai = no_kozai / (1.0 + del);
  if (sat.no_unkozai <= 0.0) {
    outError = "invalid_recovered_mean_motion";
    return false;
  }

  // V1 supports near-Earth SGP4 (period < 225 min)
  if ((kTwoPi / sat.no_unkozai) >= 225.0) {
    outError = "deep_space_sdp4_not_supported_in_v1";
    return false;
  }

  const double ao = std::pow(xke / sat.no_unkozai, kX2o3);
  const double po = ao * omeosq;
  const double con42 = 1.0 - 5.0 * cosio2;
  sat.con41 = -con42 - cosio2 - cosio2;
  const double posq = po * po;
  const double rp = ao * (1.0 - sat.ecco);

  sat.a = ao;
  sat.alta = ao * (1.0 + sat.ecco) - 1.0;
  sat.altp = ao * (1.0 - sat.ecco) - 1.0;

  const double ss = 78.0 / kEarthRadiusWgs72 + 1.0;
  const double qzms2ttemp = (120.0 - 78.0) / kEarthRadiusWgs72;
  const double qzms2t = qzms2ttemp * qzms2ttemp * qzms2ttemp * qzms2ttemp;

  double sfour = ss;
  double qzms24 = qzms2t;
  const double perige = (rp - 1.0) * kEarthRadiusWgs72;
  if (perige < 156.0) {
    sfour = perige - 78.0;
    if (perige < 98.0) {
      sfour = 20.0;
    }
    const double qzms24temp = (120.0 - sfour) / kEarthRadiusWgs72;
    qzms24 = qzms24temp * qzms24temp * qzms24temp * qzms24temp;
    sfour = sfour / kEarthRadiusWgs72 + 1.0;
  }

  const double pinvsq = 1.0 / posq;
  const double tsi = 1.0 / (ao - sfour);
  sat.eta = ao * sat.ecco * tsi;
  const double etasq = sat.eta * sat.eta;
  const double eeta = sat.ecco * sat.eta;
  const double psisq = std::abs(1.0 - etasq);
  const double coef = qzms24 * std::pow(tsi, 4.0);
  const double coef1 = coef / std::pow(psisq, 3.5);
  const double cc2 = coef1 * sat.no_unkozai *
                     (ao * (1.0 + 1.5 * etasq + eeta * (4.0 + etasq)) +
                      0.375 * kJ2Wgs72 * tsi / psisq * sat.con41 * (8.0 + 3.0 * etasq * (8.0 + etasq)));
  sat.cc1 = sat.bstar * cc2;
  double cc3 = 0.0;
  if (sat.ecco > 1.0e-4) {
    cc3 = -2.0 * coef * tsi * kJ3oJ2Wgs72 * sat.no_unkozai * sinio / sat.ecco;
  }
  sat.x1mth2 = 1.0 - cosio2;
  sat.cc4 = 2.0 * sat.no_unkozai * coef1 * ao * omeosq *
            (sat.eta * (2.0 + 0.5 * etasq) + sat.ecco * (0.5 + 2.0 * etasq) -
             kJ2Wgs72 * tsi / (ao * psisq) *
                 (-3.0 * sat.con41 * (1.0 - 2.0 * eeta + etasq * (1.5 - 0.5 * eeta)) +
                  0.75 * sat.x1mth2 * (2.0 * etasq - eeta * (1.0 + etasq)) * std::cos(2.0 * sat.argpo)));
  sat.cc5 = 2.0 * coef1 * ao * omeosq * (1.0 + 2.75 * (etasq + eeta) + eeta * etasq);

  const double cosio4 = cosio2 * cosio2;
  const double temp1 = 1.5 * kJ2Wgs72 * pinvsq * sat.no_unkozai;
  const double temp2 = 0.5 * temp1 * kJ2Wgs72 * pinvsq;
  const double temp3 = -0.46875 * kJ4Wgs72 * pinvsq * pinvsq * sat.no_unkozai;
  sat.mdot = sat.no_unkozai + 0.5 * temp1 * rteosq * sat.con41 +
             0.0625 * temp2 * rteosq * (13.0 - 78.0 * cosio2 + 137.0 * cosio4);
  sat.argpdot = -0.5 * temp1 * con42 +
                0.0625 * temp2 * (7.0 - 114.0 * cosio2 + 395.0 * cosio4) +
                temp3 * (3.0 - 36.0 * cosio2 + 49.0 * cosio4);
  const double xhdot1 = -temp1 * cosio;
  sat.nodedot = xhdot1 + (0.5 * temp2 * (4.0 - 19.0 * cosio2) + 2.0 * temp3 * (3.0 - 7.0 * cosio2)) * cosio;

  sat.omgcof = sat.bstar * cc3 * std::cos(sat.argpo);
  sat.xmcof = 0.0;
  if (sat.ecco > 1.0e-4) {
    sat.xmcof = -kX2o3 * coef * sat.bstar / eeta;
  }
  sat.nodecf = 3.5 * omeosq * xhdot1 * sat.cc1;
  sat.t2cof = 1.5 * sat.cc1;
  if (std::abs(cosio + 1.0) > 1.5e-12) {
    sat.xlcof = -0.25 * kJ3oJ2Wgs72 * sinio * (3.0 + 5.0 * cosio) / (1.0 + cosio);
  } else {
    sat.xlcof = -0.25 * kJ3oJ2Wgs72 * sinio * (3.0 + 5.0 * cosio) / 1.5e-12;
  }
  sat.aycof = -0.5 * kJ3oJ2Wgs72 * sinio;
  const double delmotemp = 1.0 + sat.eta * std::cos(sat.mo);
  sat.delmo = delmotemp * delmotemp * delmotemp;
  sat.sinmao = std::sin(sat.mo);
  sat.x7thm1 = 7.0 * cosio2 - 1.0;

  sat.isimp = (rp < (220.0 / kEarthRadiusWgs72 + 1.0)) ? 1 : 0;
  if (sat.isimp == 0) {
    const double cc1sq = sat.cc1 * sat.cc1;
    sat.d2 = 4.0 * ao * tsi * cc1sq;
    const double temp = sat.d2 * tsi * sat.cc1 / 3.0;
    sat.d3 = (17.0 * ao + sfour) * temp;
    sat.d4 = 0.5 * temp * ao * tsi * (221.0 * ao + 31.0 * sfour) * sat.cc1;
    sat.t3cof = sat.d2 + 2.0 * cc1sq;
    sat.t4cof = 0.25 * (3.0 * sat.d3 + sat.cc1 * (12.0 * sat.d2 + 10.0 * cc1sq));
    sat.t5cof = 0.2 * (3.0 * sat.d4 + 12.0 * sat.cc1 * sat.d3 + 6.0 * sat.d2 * sat.d2 +
                       15.0 * cc1sq * (2.0 * sat.d2 + cc1sq));
  }
  return true;
}

bool evalSgp4(const Sgp4State& sat,
              double tsinceMin,
              Vec3& outRTemeKm,
              Vec3& outVTemeKmS,
              std::string& outError) {
  const double t = tsinceMin;
  const double xmdf = sat.mo + sat.mdot * t;
  const double argpdf = sat.argpo + sat.argpdot * t;
  const double nodedf = sat.nodeo + sat.nodedot * t;

  double argpm = argpdf;
  double mm = xmdf;
  const double t2 = t * t;
  double nodem = nodedf + sat.nodecf * t2;
  double tempa = 1.0 - sat.cc1 * t;
  double tempe = sat.bstar * sat.cc4 * t;
  double templ = sat.t2cof * t2;

  if (sat.isimp == 0) {
    const double delomg = sat.omgcof * t;
    const double delmtemp = 1.0 + sat.eta * std::cos(xmdf);
    const double delm = sat.xmcof * (delmtemp * delmtemp * delmtemp - sat.delmo);
    const double temp = delomg + delm;
    mm = xmdf + temp;
    argpm = argpdf - temp;
    const double t3 = t2 * t;
    const double t4 = t3 * t;
    tempa = tempa - sat.d2 * t2 - sat.d3 * t3 - sat.d4 * t4;
    tempe = tempe + sat.bstar * sat.cc5 * (std::sin(mm) - sat.sinmao);
    templ = templ + sat.t3cof * t3 + t4 * (sat.t4cof + t * sat.t5cof);
  }

  double nm = sat.no_unkozai;
  double em = sat.ecco;
  const double inclm = sat.inclo;

  if (nm <= 0.0) {
    outError = "sgp4_mean_motion_non_positive";
    return false;
  }

  const double am = std::pow(sat.xke / nm, kX2o3) * tempa * tempa;
  nm = sat.xke / std::pow(am, 1.5);
  em = em - tempe;
  if (em >= 1.0 || em < -0.001 || am < 0.95) {
    outError = "sgp4_eccentricity_or_sma_out_of_bounds";
    return false;
  }
  if (em < 1.0e-6) em = 1.0e-6;

  mm = mm + sat.no_unkozai * templ;
  double xlm = mm + argpm + nodem;
  nodem = std::fmod(nodem, kTwoPi);
  argpm = std::fmod(argpm, kTwoPi);
  xlm = std::fmod(xlm, kTwoPi);
  mm = std::fmod(xlm - argpm - nodem, kTwoPi);
  (void)mm;

  const double cosim = std::cos(inclm);
  const double sinim = std::sin(inclm);

  // Long-period periodics
  const double axnl = em * std::cos(argpm);
  double temp = 1.0 / (am * (1.0 - em * em));
  const double aynl = em * std::sin(argpm) + temp * sat.aycof;
  const double xl = xlm + temp * sat.xlcof * axnl;

  // Solve Kepler's equation
  const double u = std::fmod(xl - nodem, kTwoPi);
  double eo1 = u;
  double tem5 = 9999.9;
  int ktr = 1;
  double sineo1 = 0.0;
  double coseo1 = 1.0;
  while (std::abs(tem5) >= 1.0e-12 && ktr <= 10) {
    sineo1 = std::sin(eo1);
    coseo1 = std::cos(eo1);
    tem5 = 1.0 - coseo1 * axnl - sineo1 * aynl;
    tem5 = (u - aynl * coseo1 + axnl * sineo1 - eo1) / tem5;
    if (std::abs(tem5) >= 0.95) {
      tem5 = (tem5 > 0.0) ? 0.95 : -0.95;
    }
    eo1 += tem5;
    ++ktr;
  }

  // Short-period preliminaries
  const double ecose = axnl * coseo1 + aynl * sineo1;
  const double esine = axnl * sineo1 - aynl * coseo1;
  const double el2 = axnl * axnl + aynl * aynl;
  const double pl = am * (1.0 - el2);
  if (pl < 0.0) {
    outError = "sgp4_semilatus_negative";
    return false;
  }

  const double rl = am * (1.0 - ecose);
  const double rdotl = std::sqrt(am) * esine / rl;
  const double rvdotl = std::sqrt(pl) / rl;
  const double betal = std::sqrt(1.0 - el2);
  temp = esine / (1.0 + betal);
  const double sinu = am / rl * (sineo1 - aynl - axnl * temp);
  const double cosu = am / rl * (coseo1 - axnl + aynl * temp);
  double su = std::atan2(sinu, cosu);
  const double sin2u = (cosu + cosu) * sinu;
  const double cos2u = 1.0 - 2.0 * sinu * sinu;
  temp = 1.0 / pl;
  const double temp1 = 0.5 * kJ2Wgs72 * temp;
  const double temp2 = temp1 * temp;

  // Short-period periodics
  const double mrt = rl * (1.0 - 1.5 * temp2 * betal * sat.con41) + 0.5 * temp1 * sat.x1mth2 * cos2u;
  su = su - 0.25 * temp2 * sat.x7thm1 * sin2u;
  const double xnode = nodem + 1.5 * temp2 * cosim * sin2u;
  const double xinck = inclm + 1.5 * temp2 * cosim * sinim * cos2u;
  const double rdotk = rdotl - nm * temp1 * sat.x1mth2 * sin2u / sat.xke;
  const double rvdotk = rvdotl + nm * temp1 * (sat.x1mth2 * cos2u + 1.5 * sat.con41) / sat.xke;

  if (mrt < 1.0) {
    outError = "sgp4_satellite_decayed";
    return false;
  }

  // Orientation vectors
  const double sinsu = std::sin(su);
  const double cossu = std::cos(su);
  const double snod = std::sin(xnode);
  const double cnod = std::cos(xnode);
  const double sini = std::sin(xinck);
  const double cosi = std::cos(xinck);
  const double xmx = -snod * cosi;
  const double xmy = cnod * cosi;
  const double ux = xmx * sinsu + cnod * cossu;
  const double uy = xmy * sinsu + snod * cossu;
  const double uz = sini * sinsu;
  const double vx = xmx * cossu - cnod * sinsu;
  const double vy = xmy * cossu - snod * sinsu;
  const double vz = sini * cossu;

  const double vkmpersec = kEarthRadiusWgs72 * sat.xke / 60.0;
  outRTemeKm.x = mrt * ux * kEarthRadiusWgs72;
  outRTemeKm.y = mrt * uy * kEarthRadiusWgs72;
  outRTemeKm.z = mrt * uz * kEarthRadiusWgs72;
  outVTemeKmS.x = (rdotk * ux + rvdotk * vx) * vkmpersec;
  outVTemeKmS.y = (rdotk * uy + rvdotk * vy) * vkmpersec;
  outVTemeKmS.z = (rdotk * uz + rvdotk * vz) * vkmpersec;
  return true;
}

} // namespace

void OrbitalPropagator::unixMsToJulianDate(uint64_t unixMs, double& outJd, double& outJdFrac) {
  const uint64_t days = unixMs / 86400000ULL;
  const uint64_t remMs = unixMs % 86400000ULL;
  outJd = 2440587.5 + static_cast<double>(days);
  outJdFrac = static_cast<double>(remMs) / 86400000.0;
}

bool OrbitalPropagator::calendarUtcToJulianDate(int year,
                                                int month,
                                                int day,
                                                int hour,
                                                int minute,
                                                double second,
                                                double& outJd,
                                                double& outJdFrac,
                                                uint64_t& outUnixMs) {
  if (!isValidCalendarDate(year, month, day, hour, minute, second)) {
    return false;
  }
  const int64_t daysSinceUnixEpoch = daysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
  const double secInDay = static_cast<double>(hour) * 3600.0 + static_cast<double>(minute) * 60.0 + second;
  outJd = 2440587.5 + static_cast<double>(daysSinceUnixEpoch);
  outJdFrac = secInDay / 86400.0;

  const double totalMs = static_cast<double>(daysSinceUnixEpoch) * 86400000.0 + secInDay * 1000.0;
  if (totalMs < 0.0) {
    outUnixMs = 0;
  } else {
    outUnixMs = static_cast<uint64_t>(std::llround(totalMs));
  }
  return true;
}

double OrbitalPropagator::computeGmstRadians(double jdUt1, double jdUt1Frac) {
  const double tut1 = ((jdUt1 - 2451545.0) + jdUt1Frac) / 36525.0;
  double temp = -6.2e-6 * tut1 * tut1 * tut1 +
                0.093104 * tut1 * tut1 +
                (876600.0 * 3600.0 + 8640184.812866) * tut1 +
                67310.54841;
  temp = std::fmod(temp * (kDeg2Rad / 240.0), kTwoPi);
  if (temp < 0.0) temp += kTwoPi;
  return temp;
}

GeodeticState OrbitalPropagator::temeToGeodetic(const Vec3& rTemeKm, double jdUtc, double jdUtcFrac) {
  const double gmst = computeGmstRadians(jdUtc, jdUtcFrac);
  const double cosG = std::cos(gmst);
  const double sinG = std::sin(gmst);

  // Rotate TEME -> PEF/ECEF around Z axis by +GMST
  const double xEcef = rTemeKm.x * cosG + rTemeKm.y * sinG;
  const double yEcef = -rTemeKm.x * sinG + rTemeKm.y * cosG;
  const double zEcef = rTemeKm.z;

  double lonRad = std::atan2(yEcef, xEcef);
  const double p = std::hypot(xEcef, yEcef);

  double latRad = std::atan2(zEcef, p * (1.0 - kWgs84E2));
  double N = kWgs84A;
  for (int i = 0; i < 8; ++i) {
    const double sinLat = std::sin(latRad);
    N = kWgs84A / std::sqrt(1.0 - kWgs84E2 * sinLat * sinLat);
    const double nextLat = std::atan2(zEcef + kWgs84E2 * N * sinLat, p);
    if (std::abs(nextLat - latRad) < 1.0e-12) {
      latRad = nextLat;
      break;
    }
    latRad = nextLat;
  }

  const double sinLat = std::sin(latRad);
  const double cosLat = std::cos(latRad);
  N = kWgs84A / std::sqrt(1.0 - kWgs84E2 * sinLat * sinLat);
  double altKm = 0.0;
  if (std::abs(cosLat) > 1.0e-6) {
    altKm = p / cosLat - N;
  } else {
    altKm = std::abs(zEcef) / std::max(1.0e-12, std::abs(sinLat)) - N * (1.0 - kWgs84E2);
  }

  double lonDeg = lonRad * kRad2Deg;
  if (lonDeg > 180.0) lonDeg -= 360.0;
  if (lonDeg < -180.0) lonDeg += 360.0;

  GeodeticState out;
  out.latitudeDeg = std::clamp(latRad * kRad2Deg, -90.0, 90.0);
  out.longitudeDeg = lonDeg;
  out.altitudeKm = altKm;
  return out;
}

bool OrbitalPropagator::propagateTemeAtTsince(const OrbitalElements& el,
                                              double tsinceMin,
                                              Vec3& outRTemeKm,
                                              Vec3& outVTemeKmS,
                                              std::string& outError) {
  Sgp4State sat;
  if (!initSgp4(el, sat, outError)) {
    return false;
  }
  return evalSgp4(sat, tsinceMin, outRTemeKm, outVTemeKmS, outError);
}

bool OrbitalPropagator::propagate(const OrbitalElements& el,
                                  uint64_t timestampMs,
                                  SatellitePosition& outPos,
                                  std::string& outError) {
  Sgp4State sat;
  if (!initSgp4(el, sat, outError)) {
    return false;
  }

  double jdNow = 0.0;
  double jdNowFrac = 0.0;
  unixMsToJulianDate(timestampMs, jdNow, jdNowFrac);
  const double tsinceMin = ((jdNow - el.epochJd) + (jdNowFrac - el.epochJdFrac)) * 1440.0;

  Vec3 rTeme{}, vTeme{};
  if (!evalSgp4(sat, tsinceMin, rTeme, vTeme, outError)) {
    return false;
  }

  const GeodeticState geo = temeToGeodetic(rTeme, jdNow, jdNowFrac);
  outPos.valid = true;
  outPos.timestampMs = timestampMs;
  outPos.tsinceMin = tsinceMin;
  outPos.latitudeDeg = geo.latitudeDeg;
  outPos.longitudeDeg = geo.longitudeDeg;
  outPos.altitudeKm = geo.altitudeKm;
  outPos.velocityKmS = std::sqrt(vTeme.x * vTeme.x + vTeme.y * vTeme.y + vTeme.z * vTeme.z);
  outPos.inclinationDeg = el.inclinationDeg;
  outPos.orbitalPeriodMin = 1440.0 / el.meanMotionRevDay;
  outPos.rTemeKm = rTeme;
  outPos.vTemeKmS = vTeme;
  return true;
}

std::vector<std::vector<TrackPoint>> OrbitalPropagator::splitAntimeridianSegments(const std::vector<TrackPoint>& pts) {
  std::vector<std::vector<TrackPoint>> segments;
  if (pts.empty()) return segments;

  segments.emplace_back();
  segments.back().push_back(pts.front());

  for (size_t i = 1; i < pts.size(); ++i) {
    const TrackPoint& prev = pts[i - 1];
    const TrackPoint& cur = pts[i];
    const double dLon = cur.lon - prev.lon;

    if (std::abs(dLon) > 180.0) {
      if (dLon < -180.0) {
        // Crossing eastward over +180 -> -180
        const double unwrappedLon = cur.lon + 360.0;
        const double denom = unwrappedLon - prev.lon;
        const double t = (std::abs(denom) > 1e-9) ? std::clamp((180.0 - prev.lon) / denom, 0.0, 1.0) : 0.5;
        const double crossLat = prev.lat + t * (cur.lat - prev.lat);
        const double crossAlt = prev.altKm + t * (cur.altKm - prev.altKm);
        const int64_t crossSec = prev.offsetSec + static_cast<int64_t>(std::llround(t * static_cast<double>(cur.offsetSec - prev.offsetSec)));

        segments.back().push_back(TrackPoint{180.0, crossLat, crossAlt, crossSec});
        segments.emplace_back();
        segments.back().push_back(TrackPoint{-180.0, crossLat, crossAlt, crossSec});
      } else {
        // Crossing westward over -180 -> +180
        const double unwrappedLon = cur.lon - 360.0;
        const double denom = unwrappedLon - prev.lon;
        const double t = (std::abs(denom) > 1e-9) ? std::clamp((-180.0 - prev.lon) / denom, 0.0, 1.0) : 0.5;
        const double crossLat = prev.lat + t * (cur.lat - prev.lat);
        const double crossAlt = prev.altKm + t * (cur.altKm - prev.altKm);
        const int64_t crossSec = prev.offsetSec + static_cast<int64_t>(std::llround(t * static_cast<double>(cur.offsetSec - prev.offsetSec)));

        segments.back().push_back(TrackPoint{-180.0, crossLat, crossAlt, crossSec});
        segments.emplace_back();
        segments.back().push_back(TrackPoint{180.0, crossLat, crossAlt, crossSec});
      }
    }
    segments.back().push_back(cur);
  }
  return segments;
}

bool OrbitalPropagator::propagateTrack(const OrbitalElements& el,
                                       uint64_t centerTimestampMs,
                                       int pastMinutes,
                                       int futureMinutes,
                                       int stepSeconds,
                                       SatelliteTrack& outTrack,
                                       std::string& outError) {
  Sgp4State sat;
  if (!initSgp4(el, sat, outError)) {
    return false;
  }

  const int clampedStep = std::clamp(stepSeconds, 15, 300);
  const int pastSec = std::max(0, pastMinutes) * 60;
  const int futureSec = std::max(0, futureMinutes) * 60;

  auto samplePoint = [&](int64_t offsetSec, TrackPoint& pt) -> bool {
    const int64_t signedTsMs = static_cast<int64_t>(centerTimestampMs) + offsetSec * 1000LL;
    if (signedTsMs < 0) return false;
    const uint64_t tsMs = static_cast<uint64_t>(signedTsMs);
    double jd = 0.0;
    double jdFrac = 0.0;
    unixMsToJulianDate(tsMs, jd, jdFrac);
    const double tsinceMin = ((jd - el.epochJd) + (jdFrac - el.epochJdFrac)) * 1440.0;
    Vec3 r{}, v{};
    std::string err;
    if (!evalSgp4(sat, tsinceMin, r, v, err)) {
      return false;
    }
    const GeodeticState geo = temeToGeodetic(r, jd, jdFrac);
    pt.lon = geo.longitudeDeg;
    pt.lat = geo.latitudeDeg;
    pt.altKm = geo.altitudeKm;
    pt.offsetSec = offsetSec;
    return true;
  };

  std::vector<TrackPoint> pastPts;
  for (int s = -pastSec; s <= 0; s += clampedStep) {
    TrackPoint pt;
    if (samplePoint(s, pt)) pastPts.push_back(pt);
  }
  if (pastPts.empty() || pastPts.back().offsetSec != 0) {
    TrackPoint pt;
    if (samplePoint(0, pt)) pastPts.push_back(pt);
  }

  std::vector<TrackPoint> futurePts;
  for (int s = 0; s <= futureSec; s += clampedStep) {
    TrackPoint pt;
    if (samplePoint(s, pt)) futurePts.push_back(pt);
  }
  if (futurePts.empty() || futurePts.back().offsetSec != futureSec) {
    TrackPoint pt;
    if (samplePoint(futureSec, pt)) futurePts.push_back(pt);
  }

  outTrack.pastSegments = splitAntimeridianSegments(pastPts);
  outTrack.futureSegments = splitAntimeridianSegments(futurePts);
  return true;
}

} // namespace netpulse::satellite
