// Zero-dependency TopoJSON decoder, 2D Full-Planet Projections, Great-Circle & Solar Terminator math

export function decodeTopoJson(topology, objectName = 'countries') {
  const { transform, arcs, objects } = topology;
  const scale = transform ? transform.scale : [1, 1];
  const translate = transform ? transform.translate : [0, 0];

  const decodedArcs = arcs.map((arc) => {
    let x = 0;
    let y = 0;
    const pts = new Array(arc.length);
    for (let i = 0; i < arc.length; i++) {
      x += arc[i][0];
      y += arc[i][1];
      pts[i] = [x * scale[0] + translate[0], y * scale[1] + translate[1]];
    }
    return pts;
  });

  function stitchRing(arcIndices) {
    const ring = [];
    for (let i = 0; i < arcIndices.length; i++) {
      const idx = arcIndices[i];
      const rev = idx < 0;
      const pts = decodedArcs[rev ? ~idx : idx];
      if (!pts || pts.length === 0) continue;
      if (rev) {
        for (let j = pts.length - 1; j >= 0; j--) {
          if (i > 0 && j === pts.length - 1) continue;
          ring.push(pts[j]);
        }
      } else {
        for (let j = 0; j < pts.length; j++) {
          if (i > 0 && j === 0) continue;
          ring.push(pts[j]);
        }
      }
    }
    return ring;
  }

  function computeBbox(polygons) {
    let minLon = 180;
    let maxLon = -180;
    let minLat = 90;
    let maxLat = -90;
    for (const poly of polygons) {
      for (const ring of poly) {
        for (const [lon, lat] of ring) {
          if (lon < minLon) minLon = lon;
          if (lon > maxLon) maxLon = lon;
          if (lat < minLat) minLat = lat;
          if (lat > maxLat) maxLat = lat;
        }
      }
    }
    return [minLon, minLat, maxLon, maxLat];
  }

  const obj = objects[objectName];
  if (!obj || !obj.geometries) return [];

  const features = [];
  for (const geom of obj.geometries) {
    let polygons = [];
    if (geom.type === 'Polygon') {
      polygons = [geom.arcs.map(stitchRing)];
    } else if (geom.type === 'MultiPolygon') {
      polygons = geom.arcs.map((polyArcs) => polyArcs.map(stitchRing));
    }
    if (polygons.length === 0) continue;

    features.push({
      id: geom.id ?? '',
      name: (geom.properties && geom.properties.name) || 'Unknown',
      polygons,
      bbox: computeBbox(polygons),
    });
  }
  return features;
}

const DEG2RAD = Math.PI / 180;
const RAD2DEG = 180 / Math.PI;

// Natural Earth projection coefficients (Tom Patterson / d3-geo)
function naturalEarthRaw(lambda, phi) {
  const phi2 = phi * phi;
  const phi4 = phi2 * phi2;
  const x =
    lambda *
    (0.8707 - 0.131979 * phi2 + phi4 * (-0.013791 + phi4 * (0.003971 * phi2 - 0.001529 * phi4)));
  const y =
    phi *
    (1.007226 + phi2 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi2 - 0.005916 * phi4)));
  return [x, y];
}

function naturalEarthInvertRaw(x, y) {
  let phi = y;
  for (let i = 0; i < 12; i++) {
    const phi2 = phi * phi;
    const phi4 = phi2 * phi2;
    const fy =
      phi *
        (1.007226 + phi2 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi2 - 0.005916 * phi4))) -
      y;
    const dy =
      1.007226 + phi2 * (0.045255 + phi4 * (-0.311325 + 0.259866 * phi2 - 0.065076 * phi4));
    const delta = fy / dy;
    phi -= delta;
    if (Math.abs(delta) < 1e-7) break;
  }
  const phi2 = phi * phi;
  const phi4 = phi2 * phi2;
  const lambda =
    x /
    (0.8707 - 0.131979 * phi2 + phi4 * (-0.013791 + phi4 * (0.003971 * phi2 - 0.001529 * phi4)));
  return [lambda, phi];
}

// Each projection maps (lon, lat) -> normalized [0..1, 0..aspect] world coordinates.
export const PROJECTIONS = {
  naturalEarth: {
    id: 'naturalEarth',
    label: 'Natural Earth',
    aspect: 1.92, // width / height
    project(lon, lat) {
      const lam = Math.max(-180, Math.min(180, lon)) * DEG2RAD;
      const phi = Math.max(-90, Math.min(90, lat)) * DEG2RAD;
      const [rx, ry] = naturalEarthRaw(lam, phi);
      // Max rx at lam=pi, phi=0 is pi * 0.8707 = 2.73538
      // Max ry at phi=pi/2 is ~1.4216
      const nx = (rx / 2.73538 + 1) * 0.5;
      const ny = (1 - ry / 1.4216) * 0.5;
      return [nx, ny];
    },
    unproject(nx, ny) {
      const rx = (nx * 2 - 1) * 2.73538;
      const ry = (1 - ny * 2) * 1.4216;
      const [lam, phi] = naturalEarthInvertRaw(rx, ry);
      const lon = lam * RAD2DEG;
      const lat = phi * RAD2DEG;
      if (lon < -180 || lon > 180 || lat < -90 || lat > 90) return null;
      return [lon, lat];
    },
  },

  equirectangular: {
    id: 'equirectangular',
    label: 'Equirectangular',
    aspect: 2.0,
    project(lon, lat) {
      const nx = (Math.max(-180, Math.min(180, lon)) + 180) / 360;
      const ny = (90 - Math.max(-90, Math.min(90, lat))) / 180;
      return [nx, ny];
    },
    unproject(nx, ny) {
      if (nx < 0 || nx > 1 || ny < 0 || ny > 1) return null;
      return [nx * 360 - 180, 90 - ny * 180];
    },
  },

  mercator: {
    id: 'mercator',
    label: 'Mercator',
    aspect: 1.48,
    project(lon, lat) {
      const clampedLat = Math.max(-83.5, Math.min(83.5, lat));
      const nx = (Math.max(-180, Math.min(180, lon)) + 180) / 360;
      const rad = clampedLat * DEG2RAD;
      const mercY = Math.log(Math.tan(Math.PI / 4 + rad / 2));
      const maxMercY = Math.log(Math.tan(Math.PI / 4 + (83.5 * DEG2RAD) / 2));
      const ny = (1 - mercY / maxMercY) * 0.5;
      return [nx, ny];
    },
    unproject(nx, ny) {
      if (nx < 0 || nx > 1 || ny < 0 || ny > 1) return null;
      const maxMercY = Math.log(Math.tan(Math.PI / 4 + (83.5 * DEG2RAD) / 2));
      const mercY = (1 - ny * 2) * maxMercY;
      const lat = (2 * Math.atan(Math.exp(mercY)) - Math.PI / 2) * RAD2DEG;
      return [nx * 360 - 180, lat];
    },
  },
};

// Spherical great-circle interpolation split into segments if crossing the antimeridian (+/- 180 deg).
export function buildGreatCircleSegments(lon1, lat1, lon2, lat2, steps = 40) {
  const phi1 = lat1 * DEG2RAD;
  const lam1 = lon1 * DEG2RAD;
  const phi2 = lat2 * DEG2RAD;
  const lam2 = lon2 * DEG2RAD;

  const x1 = Math.cos(phi1) * Math.cos(lam1);
  const y1 = Math.cos(phi1) * Math.sin(lam1);
  const z1 = Math.sin(phi1);

  const x2 = Math.cos(phi2) * Math.cos(lam2);
  const y2 = Math.cos(phi2) * Math.sin(lam2);
  const z2 = Math.sin(phi2);

  const dot = Math.max(-1, Math.min(1, x1 * x2 + y1 * y2 + z1 * z2));
  const omega = Math.acos(dot);

  const pts = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    let x, y, z;
    if (omega < 1e-4) {
      x = x1 + (x2 - x1) * t;
      y = y1 + (y2 - y1) * t;
      z = z1 + (z2 - z1) * t;
    } else {
      const sinO = Math.sin(omega);
      const a = Math.sin((1 - t) * omega) / sinO;
      const b = Math.sin(t * omega) / sinO;
      x = a * x1 + b * x2;
      y = a * y1 + b * y2;
      z = a * z1 + b * z2;
    }
    const len = Math.hypot(x, y, z) || 1;
    const lat = Math.asin(Math.max(-1, Math.min(1, z / len))) * RAD2DEG;
    const lon = Math.atan2(y, x) * RAD2DEG;
    pts.push([lon, lat]);
  }

  // Split at antimeridian jumps
  const segments = [[]];
  for (let i = 0; i < pts.length; i++) {
    const cur = pts[i];
    if (i > 0) {
      const prev = pts[i - 1];
      if (Math.abs(cur[0] - prev[0]) > 180) {
        segments.push([]);
      }
    }
    segments[segments.length - 1].push(cur);
  }
  return segments;
}

export function pointInRing(lon, lat, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0];
    const yi = ring[i][1];
    const xj = ring[j][0];
    const yj = ring[j][1];
    if (Math.abs(xi - xj) > 180) continue; // skip antimeridian wrap edge
    const intersect = yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi + 1e-12) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

export function findCountryAt(features, lon, lat) {
  for (let fIdx = features.length - 1; fIdx >= 0; fIdx--) {
    const f = features[fIdx];
    const [minLon, minLat, maxLon, maxLat] = f.bbox;
    if (lon < minLon || lon > maxLon || lat < minLat || lat > maxLat) continue;
    for (const poly of f.polygons) {
      if (poly.length === 0) continue;
      if (pointInRing(lon, lat, poly[0])) {
        let inHole = false;
        for (let h = 1; h < poly.length; h++) {
          if (pointInRing(lon, lat, poly[h])) {
            inHole = true;
            break;
          }
        }
        if (!inHole) return f;
      }
    }
  }
  return null;
}

// Computes the night-side polygon for real-time solar terminator rendering.
export function computeSolarTerminatorPolygon(date = new Date()) {
  const julianDay = date.getTime() / 86400000 + 2440587.5;
  const n = julianDay - 2451545.0;
  const L = (280.46 + 0.9856474 * n) % 360;
  const g = ((357.528 + 0.9856003 * n) % 360) * DEG2RAD;
  const lambdaSun = (L + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g)) * DEG2RAD;
  const obliquity = (23.439 - 0.0000004 * n) * DEG2RAD;
  const dec = Math.asin(Math.sin(obliquity) * Math.sin(lambdaSun));

  // Subsolar longitude
  const utcHours =
    date.getUTCHours() + date.getUTCMinutes() / 60 + date.getUTCSeconds() / 3600;
  const gmst = (6.697375 + 0.0657098242 * n + utcHours) % 24;
  const ra = Math.atan2(Math.cos(obliquity) * Math.sin(lambdaSun), Math.cos(lambdaSun)) * RAD2DEG / 15;
  let subsolarLon = (ra - gmst) * 15;
  while (subsolarLon > 180) subsolarLon -= 360;
  while (subsolarLon < -180) subsolarLon += 360;

  const curve = [];
  const tanDec = Math.tan(dec);
  for (let lon = -180; lon <= 180; lon += 3) {
    const ha = (lon - subsolarLon) * DEG2RAD;
    const lat =
      Math.abs(tanDec) < 1e-6
        ? 0
        : Math.atan(-Math.cos(ha) / tanDec) * RAD2DEG;
    curve.push([lon, lat]);
  }

  // Close polygon toward the night pole (South if sun is North, North if sun is South)
  const nightPoleLat = dec >= 0 ? -90 : 90;
  const polygon = [...curve, [180, nightPoleLat], [-180, nightPoleLat]];
  return polygon;
}
