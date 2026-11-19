import {
  PROJECTIONS,
  buildGreatCircleSegments,
  computeSolarTerminatorPolygon,
  findCountryAt,
} from './topo.js';
import { SatelliteMapOverlay } from './satellite-overlay.js';

const WORLD_W = 1000;

const STATE_COLORS = {
  ESTABLISHED: '#22d3ee',
  SYN_SENT: '#fbbf24',
  SYN_RCVD: '#fbbf24',
  TIME_WAIT: '#fb7185',
  CLOSE_WAIT: '#f97316',
  FIN_WAIT1: '#fb7185',
  FIN_WAIT2: '#fb7185',
  CLOSED: '#f43f5e',
};

function colorForState(state, life) {
  if (life === 'closed') return '#f43f5e';
  if (life === 'new') return '#34d399';
  return STATE_COLORS[state] || '#38bdf8';
}

const BACKBONE_PAIRS = [
  ['cont-sa', 'cont-na'],
  ['cont-sa', 'cont-eu'],
  ['cont-sa', 'cont-af'],
  ['cont-na', 'cont-eu'],
  ['cont-na', 'cont-as'],
  ['cont-eu', 'cont-af'],
  ['cont-eu', 'cont-as'],
  ['cont-af', 'cont-as'],
  ['cont-as', 'cont-oc'],
];

function statusColor(status) {
  if (status === 'up') return '#10b981';
  if (status === 'degraded') return '#fbbf24';
  if (status === 'down') return '#f43f5e';
  return '#94a3b8';
}

function continentFromGeo(g) {
  if (!g) return 'GLOBAL';
  const { lat, lon, cc } = g;
  if (['BR', 'AR', 'CL', 'CO', 'PE', 'UY', 'PY', 'BO', 'EC', 'VE', 'GY', 'SR'].includes(cc)) return 'SA';
  if (['US', 'CA', 'MX', 'PA', 'CR', 'GT', 'CU', 'DO', 'PR'].includes(cc)) return 'NA';
  if (['AU', 'NZ', 'FJ', 'PG'].includes(cc)) return 'OC';
  if (['ZA', 'NG', 'EG', 'KE', 'MA', 'AO', 'GH', 'ET', 'TZ', 'TN', 'DZ'].includes(cc)) return 'AF';
  if (['JP', 'SG', 'CN', 'HK', 'TW', 'KR', 'IN', 'ID', 'TH', 'VN', 'MY', 'PH', 'AE', 'SA', 'IL', 'TR'].includes(cc)) return 'AS';
  if (lat < 13 && lon >= -85 && lon <= -30) return 'SA';
  if (lat >= 13 && lon >= -170 && lon <= -50) return 'NA';
  if (lat <= -10 && lon >= 110) return 'OC';
  if (lat >= -36 && lat <= 36 && lon >= -20 && lon <= 52) return 'AF';
  if (lon > 45) return 'AS';
  return 'EU';
}

export class PlanetMapCanvas {
  constructor(canvas, callbacks = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d', { alpha: false });
    this.callbacks = callbacks;

    this.features = [];
    this.projectionId = 'naturalEarth';
    this.projection = PROJECTIONS.naturalEarth;

    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.viewW = 1280;
    this.viewH = 720;

    this.zoom = 1;
    this.panX = 0;
    this.panY = 0;
    this.targetCamera = null;

    this.showTerminator = true;
    this.showArcs = true;
    this.showLan = false;
    this.showLabels = true;
    this.showAnimations = true;
    this.viewMode = 'local'; // 'local' | 'global'

    this.nodes = [];
    this.lanNodes = [];
    this.ripples = []; // expanding sonar shockwaves on new connections
    this.prevNodeCounts = new Map();
    this.stars = Array.from({ length: 85 }, (_, i) => ({
      rx: ((i * 73 + 19) % 997) / 997,
      ry: ((i * 137 + 43) % 991) / 991,
      r: 0.6 + ((i * 29) % 12) / 10,
      phase: i * 1.1,
      speed: 0.7 + ((i * 17) % 15) / 10,
    }));
    this.hasIntroPlayed = false;
    this.services = [];
    this.backboneArcs = [];
    this.traceRoute = null; // { targetIp, hops: [{ttl, ip, rttMs, lat, lon, label}], segments: [...] }
    this.continentTraffic = new Map();
    this.countryCounts = new Map(); // countryCode / countryName -> count
    this.host = { lat: -23.55, lon: -46.63, city: 'Local Host', country: 'Local', resolved: false };

    this.hoveredNode = null;
    this.selectedNodeKey = null;
    this.hoveredService = null;
    this.selectedServiceId = null;
    this.hoveredCountry = null;
    this.selectedCountryName = null;
    this.satelliteOverlay = new SatelliteMapOverlay();

    this.isDragging = false;
    this.dragMoved = false;
    this.lastMouse = { x: 0, y: 0 };
    this.mousePos = { x: -1, y: -1 };

    this.baseLayerCanvas = document.createElement('canvas');
    this.baseLayerDirty = true;

    this.terminatorPoly = computeSolarTerminatorPolygon(new Date());
    this.lastTerminatorUpdate = Date.now();

    this.rafId = 0;
    this.bindEvents();
    this.resize();
  }

  setFeatures(features) {
    this.features = features;
    this.baseLayerDirty = true;
    this.fitPlanet(true);
  }

  setProjection(id) {
    if (!PROJECTIONS[id] || this.projectionId === id) return;
    this.projectionId = id;
    this.projection = PROJECTIONS[id];
    this.baseLayerDirty = true;
    this.fitPlanet();
  }

  worldHeight() {
    return WORLD_W / this.projection.aspect;
  }

  getSafePadding() {
    const isNarrow = this.viewW < 920;
    const leftOpen = document.body.classList.contains('left-open') && !isNarrow;
    const rightOpen = document.body.classList.contains('right-open') && !isNarrow;
    return {
      top: 108,
      bottom: 54,
      left: leftOpen ? 372 : 24,
      right: rightOpen ? 360 : 24,
    };
  }

  fitPlanet(animate = false) {
    const pad = this.getSafePadding();
    const availW = Math.max(240, this.viewW - pad.left - pad.right);
    const availH = Math.max(200, this.viewH - pad.top - pad.bottom);
    const wh = this.worldHeight();
    const scale = Math.min(availW / WORLD_W, availH / wh) * 0.96;
    const targetZoom = Math.max(0.4, scale);
    const targetPanX = pad.left + (availW - WORLD_W * targetZoom) * 0.5;
    const targetPanY = pad.top + (availH - wh * targetZoom) * 0.5;

    if (animate && this.showAnimations) {
      if (!this.hasIntroPlayed) {
        this.hasIntroPlayed = true;
        this.zoom = targetZoom * 0.78;
        this.panX = pad.left + (availW - WORLD_W * this.zoom) * 0.5;
        this.panY = pad.top + (availH - wh * this.zoom) * 0.5;
      }
      this.targetCamera = { zoom: targetZoom, panX: targetPanX, panY: targetPanY };
    } else {
      this.zoom = targetZoom;
      this.panX = targetPanX;
      this.panY = targetPanY;
      this.targetCamera = null;
    }
    this.callbacks.onZoomChange?.(this.zoom);
  }

  zoomBy(factor, cx = this.viewW * 0.5, cy = this.viewH * 0.5) {
    const nextZoom = Math.max(0.35, Math.min(28, this.zoom * factor));
    const wx = (cx - this.panX) / this.zoom;
    const wy = (cy - this.panY) / this.zoom;
    this.zoom = nextZoom;
    this.panX = cx - wx * this.zoom;
    this.panY = cy - wy * this.zoom;
    this.targetCamera = null;
    this.callbacks.onZoomChange?.(this.zoom);
  }

  flyTo(lon, lat, minZoom = 2.8) {
    const [nx, ny] = this.projection.project(lon, lat);
    const wh = this.worldHeight();
    const targetZoom = Math.max(this.zoom, minZoom);
    const pad = this.getSafePadding();
    const cx = pad.left + (this.viewW - pad.left - pad.right) * 0.5;
    const cy = pad.top + (this.viewH - pad.top - pad.bottom) * 0.5;
    this.targetCamera = {
      zoom: targetZoom,
      panX: cx - nx * WORLD_W * targetZoom,
      panY: cy - ny * wh * targetZoom,
    };
  }

  projectToScreen(lon, lat) {
    const [nx, ny] = this.projection.project(lon, lat);
    return [
      nx * WORLD_W * this.zoom + this.panX,
      ny * this.worldHeight() * this.zoom + this.panY,
    ];
  }

  screenToLonLat(sx, sy) {
    const nx = (sx - this.panX) / (WORLD_W * this.zoom);
    const ny = (sy - this.panY) / (this.worldHeight() * this.zoom);
    return this.projection.unproject(nx, ny);
  }

  updateTelemetry(data) {
    if (data.host) {
      this.host = data.host.resolved
        ? data.host
        : { ...data.host, lat: -23.5505, lon: -46.6333 };
    }

    // Aggregate public connections by destination coordinate bucket
    const nodeMap = new Map();
    const lanList = [];
    const countryTotals = new Map();

    for (const c of data.filteredConns) {
      if (c.scope === 'public') {
        const g = data.geo[c.rip];
        if (!g) continue;
        const key = `${g.lat.toFixed(2)},${g.lon.toFixed(2)}`;
        let node = nodeMap.get(key);
        if (!node) {
          node = {
            key,
            lat: g.lat,
            lon: g.lon,
            cc: g.cc || '--',
            country: g.country || 'Unknown',
            city: g.city || '',
            region: g.region || '',
            isp: g.isp || '',
            org: g.org || '',
            asn: g.asn || '',
            conns: [],
            processes: new Set(),
            totalBps: 0,
            hasNew: false,
            hasEstablished: false,
            allClosed: true,
            dominantState: c.state,
            segments: null,
          };
          nodeMap.set(key, node);
        }
        node.conns.push(c);
        node.processes.add(c.proc);
        node.totalBps += (c.rxBps || 0) + (c.txBps || 0);
        if (c.life === 'new') node.hasNew = true;
        if (c.state === 'ESTABLISHED') node.hasEstablished = true;
        if (c.life !== 'closed') node.allClosed = false;

        const cName = (g.country || '').toLowerCase();
        if (cName) {
          countryTotals.set(cName, (countryTotals.get(cName) || 0) + 1);
        }
      } else if (this.showLan) {
        lanList.push(c);
      }
    }

    // Build great-circle segments once per node
    const hostLon = this.host.lon;
    const hostLat = this.host.lat;
    const nextNodes = [];
    const nextCounts = new Map();
    const nowPerf = performance.now();

    for (const node of nodeMap.values()) {
      node.segments = buildGreatCircleSegments(hostLon, hostLat, node.lon, node.lat, 36);
      node.life = node.hasNew ? 'new' : node.allClosed ? 'closed' : 'active';
      node.color = node.hasEstablished
        ? colorForState('ESTABLISHED', node.life)
        : colorForState(node.dominantState, node.life);
      nextNodes.push(node);

      const prevCount = this.prevNodeCounts.get(node.key) || 0;
      nextCounts.set(node.key, node.conns.length);
      if (this.showAnimations && (node.hasNew || node.conns.length > prevCount) && this.ripples.length < 40) {
        this.ripples.push({
          lat: node.lat,
          lon: node.lon,
          color: node.color,
          bornMs: nowPerf,
          durationMs: 1400,
        });
      }
    }

    this.prevNodeCounts = nextCounts;
    this.nodes = nextNodes;
    this.lanNodes = lanList;
    this.countryCounts = countryTotals;

    // Aggregate active user connections per continent
    const contTotals = new Map([
      ['SA', 0],
      ['NA', 0],
      ['EU', 0],
      ['AF', 0],
      ['AS', 0],
      ['OC', 0],
    ]);
    for (const c of data.allConns || data.filteredConns) {
      if (c.scope !== 'public') continue;
      const cont = continentFromGeo(data.geo[c.rip]);
      if (contTotals.has(cont)) {
        contTotals.set(cont, contTotals.get(cont) + 1);
      }
    }
    this.continentTraffic = contTotals;

    if (Array.isArray(data.services)) {
      // Spread non-continent services slightly if sharing exact coordinates so every pin is clickable
      const coordBuckets = new Map();
      this.services = data.services.map((s) => {
        let plotLat = s.lat;
        let plotLon = s.lon;
        if (s.category !== 'continent') {
          const bKey = `${s.lat.toFixed(1)},${s.lon.toFixed(1)}`;
          const idx = coordBuckets.get(bKey) || 0;
          coordBuckets.set(bKey, idx + 1);
          if (idx > 0) {
            const ang = (idx * 2.2) % (Math.PI * 2);
            const dist = 3.2 + Math.floor(idx / 3) * 2.2;
            plotLat = Math.max(-75, Math.min(75, s.lat + Math.sin(ang) * dist));
            plotLon = Math.max(-175, Math.min(175, s.lon + Math.cos(ang) * dist * 1.3));
          }
        }
        return { ...s, _lat: plotLat, _lon: plotLon };
      });

      const byId = new Map(this.services.map((s) => [s.id, s]));
      this.backboneArcs = BACKBONE_PAIRS.map(([aId, bId]) => {
        const a = byId.get(aId);
        const b = byId.get(bId);
        if (!a || !b) return null;
        return {
          a,
          b,
          segments: buildGreatCircleSegments(a.lon, a.lat, b.lon, b.lat, 38),
        };
      }).filter(Boolean);
    }
  }

  setViewMode(mode) {
    if (mode !== 'local' && mode !== 'global') return;
    this.viewMode = mode;
    this.hoveredNode = null;
    this.hoveredService = null;
  }

  setTraceRoute(targetIp, geoHops) {
    if (!geoHops || geoHops.length === 0) {
      this.traceRoute = null;
      return;
    }
    const chain = [{ lat: this.host.lat, lon: this.host.lon, ttl: 0, label: 'Você', rttMs: 0 }];
    for (const h of geoHops) {
      chain.push(h);
    }
    const segs = [];
    for (let i = 0; i + 1 < chain.length; i++) {
      const a = chain[i];
      const b = chain[i + 1];
      if (Math.hypot(a.lat - b.lat, a.lon - b.lon) < 0.05) continue;
      segs.push(...buildGreatCircleSegments(a.lon, a.lat, b.lon, b.lat, 28));
    }
    this.traceRoute = { targetIp, hops: geoHops, segments: segs };
  }

  clearTraceRoute() {
    this.traceRoute = null;
  }

  updateSatellites(payload) {
    this.satelliteOverlay.updateData(payload);
  }

  resize() {
    const rect = this.canvas.getBoundingClientRect();
    this.viewW = Math.max(320, rect.width || window.innerWidth);
    this.viewH = Math.max(240, rect.height || window.innerHeight);
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(this.viewW * this.dpr);
    this.canvas.height = Math.floor(this.viewH * this.dpr);
    if (this.zoom === 1 && this.panX === 0) {
      this.fitPlanet();
    }
  }

  start() {
    if (this.rafId) return;
    const loop = (now) => {
      this.render(now * 0.001);
      this.rafId = requestAnimationFrame(loop);
    };
    this.rafId = requestAnimationFrame(loop);
  }

  stop() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = 0;
    }
  }

  buildBaseLayer() {
    const texW = 3200;
    const texH = Math.round(texW / this.projection.aspect);
    this.baseLayerCanvas.width = texW;
    this.baseLayerCanvas.height = texH;

    const bctx = this.baseLayerCanvas.getContext('2d');
    bctx.clearRect(0, 0, texW, texH);

    // Outer globe boundary path for clipping ocean & graticule
    const clipGlobe = () => {
      bctx.beginPath();
      // Left edge (-180, -90..90), top, right edge (+180, 90..-90), bottom
      const steps = 60;
      for (let i = 0; i <= steps; i++) {
        const lat = -90 + (180 * i) / steps;
        const [nx, ny] = this.projection.project(-180, lat);
        if (i === 0) bctx.moveTo(nx * texW, ny * texH);
        else bctx.lineTo(nx * texW, ny * texH);
      }
      for (let i = 0; i <= steps; i++) {
        const lat = 90 - (180 * i) / steps;
        const [nx, ny] = this.projection.project(180, lat);
        bctx.lineTo(nx * texW, ny * texH);
      }
      bctx.closePath();
    };

    bctx.save();
    clipGlobe();
    bctx.clip();

    // Ocean gradient
    const grad = bctx.createRadialGradient(
      texW * 0.5,
      texH * 0.48,
      texW * 0.05,
      texW * 0.5,
      texH * 0.5,
      texW * 0.6
    );
    grad.addColorStop(0, '#0a192f');
    grad.addColorStop(0.65, '#071224');
    grad.addColorStop(1, '#040b16');
    bctx.fillStyle = grad;
    bctx.fillRect(0, 0, texW, texH);

    // Graticule grid (every 30 deg)
    bctx.lineWidth = 1;
    bctx.strokeStyle = 'rgba(56, 189, 248, 0.09)';
    for (let lon = -150; lon <= 150; lon += 30) {
      bctx.beginPath();
      for (let lat = -90; lat <= 90; lat += 3) {
        const [nx, ny] = this.projection.project(lon, lat);
        if (lat === -90) bctx.moveTo(nx * texW, ny * texH);
        else bctx.lineTo(nx * texW, ny * texH);
      }
      bctx.stroke();
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      bctx.beginPath();
      bctx.strokeStyle = lat === 0 ? 'rgba(34, 211, 238, 0.22)' : 'rgba(56, 189, 248, 0.09)';
      for (let lon = -180; lon <= 180; lon += 4) {
        const [nx, ny] = this.projection.project(lon, lat);
        if (lon === -180) bctx.moveTo(nx * texW, ny * texH);
        else bctx.lineTo(nx * texW, ny * texH);
      }
      bctx.stroke();
    }

    // Countries
    bctx.lineJoin = 'round';
    for (const f of this.features) {
      bctx.beginPath();
      for (const poly of f.polygons) {
        for (const ring of poly) {
          for (let i = 0; i < ring.length; i++) {
            const [lon, lat] = ring[i];
            const [nx, ny] = this.projection.project(lon, lat);
            if (i === 0) bctx.moveTo(nx * texW, ny * texH);
            else bctx.lineTo(nx * texW, ny * texH);
          }
          bctx.closePath();
        }
      }
      bctx.fillStyle = '#13263e';
      bctx.fill('evenodd');
      bctx.lineWidth = 1.1;
      bctx.strokeStyle = 'rgba(103, 232, 249, 0.22)';
      bctx.stroke();
    }

    bctx.restore();

    // Outer planetary rim
    clipGlobe();
    bctx.lineWidth = 2.2;
    bctx.strokeStyle = 'rgba(34, 211, 238, 0.35)';
    bctx.stroke();

    this.baseLayerDirty = false;
  }

  drawCountryFeature(ctx, feature, fillStyle, strokeStyle, lineWidth) {
    ctx.beginPath();
    for (const poly of feature.polygons) {
      for (const ring of poly) {
        for (let i = 0; i < ring.length; i++) {
          const [sx, sy] = this.projectToScreen(ring[i][0], ring[i][1]);
          if (i === 0) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        }
        ctx.closePath();
      }
    }
    if (fillStyle) {
      ctx.fillStyle = fillStyle;
      ctx.fill('evenodd');
    }
    if (strokeStyle) {
      ctx.lineWidth = lineWidth;
      ctx.strokeStyle = strokeStyle;
      ctx.stroke();
    }
  }

  drawTerminator(ctx) {
    if (!this.showTerminator || this.terminatorPoly.length < 3) return;
    if (Date.now() - this.lastTerminatorUpdate > 30000) {
      this.terminatorPoly = computeSolarTerminatorPolygon(new Date());
      this.lastTerminatorUpdate = Date.now();
    }

    ctx.save();
    // Clip to planet boundary
    ctx.beginPath();
    const steps = 40;
    for (let i = 0; i <= steps; i++) {
      const [sx, sy] = this.projectToScreen(-180, -90 + (180 * i) / steps);
      if (i === 0) ctx.moveTo(sx, sy);
      else ctx.lineTo(sx, sy);
    }
    for (let i = 0; i <= steps; i++) {
      const [sx, sy] = this.projectToScreen(180, 90 - (180 * i) / steps);
      ctx.lineTo(sx, sy);
    }
    ctx.closePath();
    ctx.clip();

    ctx.beginPath();
    for (let i = 0; i < this.terminatorPoly.length; i++) {
      const [lon, lat] = this.terminatorPoly[i];
      const [sx, sy] = this.projectToScreen(lon, lat);
      if (i === 0) ctx.moveTo(sx, sy);
      else ctx.lineTo(sx, sy);
    }
    ctx.closePath();
    ctx.fillStyle = 'rgba(2, 6, 16, 0.36)';
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'rgba(250, 204, 21, 0.16)';
    ctx.stroke();
    ctx.restore();
  }

  render(timeSec) {
    if (this.baseLayerDirty && this.features.length > 0) {
      this.buildBaseLayer();
    }

    // Smooth camera fly-to interpolation
    if (this.targetCamera) {
      const ease = 0.16;
      this.zoom += (this.targetCamera.zoom - this.zoom) * ease;
      this.panX += (this.targetCamera.panX - this.panX) * ease;
      this.panY += (this.targetCamera.panY - this.panY) * ease;
      if (
        Math.abs(this.targetCamera.zoom - this.zoom) < 0.005 &&
        Math.hypot(this.targetCamera.panX - this.panX, this.targetCamera.panY - this.panY) < 0.5
      ) {
        this.zoom = this.targetCamera.zoom;
        this.panX = this.targetCamera.panX;
        this.panY = this.targetCamera.panY;
        this.targetCamera = null;
      }
      this.callbacks.onZoomChange?.(this.zoom);
    }

    const ctx = this.ctx;
    ctx.save();
    ctx.scale(this.dpr, this.dpr);

    // Deep space background + twinkling starfield
    ctx.fillStyle = '#030712';
    ctx.fillRect(0, 0, this.viewW, this.viewH);

    if (this.showAnimations) {
      for (const st of this.stars) {
        const a = 0.16 + 0.34 * (0.5 + 0.5 * Math.sin(timeSec * st.speed + st.phase));
        ctx.fillStyle = `rgba(186, 230, 253, ${a.toFixed(2)})`;
        ctx.beginPath();
        ctx.arc(st.rx * this.viewW, st.ry * this.viewH, st.r, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // Draw cached world map
    const drawW = WORLD_W * this.zoom;
    const drawH = this.worldHeight() * this.zoom;
    ctx.drawImage(this.baseLayerCanvas, this.panX, this.panY, drawW, drawH);

    // Subtle longitude radar telemetry sweep across planet
    if (this.showAnimations) {
      const scanLon = -180 + ((timeSec * 26) % 360);
      ctx.save();
      ctx.beginPath();
      for (let lat = -90; lat <= 90; lat += 6) {
        const [sx, sy] = this.projectToScreen(scanLon, lat);
        if (lat === -90) ctx.moveTo(sx, sy);
        else ctx.lineTo(sx, sy);
      }
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.16)';
      ctx.lineWidth = 2;
      ctx.shadowColor = '#22d3ee';
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.restore();
    }

    // Crisp vector border pass when zoomed in closely
    if (this.zoom > 2.6 && this.features.length > 0) {
      const topLeft = this.screenToLonLat(0, 0);
      const botRight = this.screenToLonLat(this.viewW, this.viewH);
      for (const f of this.features) {
        if (topLeft && botRight) {
          const [minLon, minLat, maxLon, maxLat] = f.bbox;
          if (maxLon < topLeft[0] - 5 || minLon > botRight[0] + 5) continue;
          if (maxLat < botRight[1] - 5 || minLat > topLeft[1] + 5) continue;
        }
        this.drawCountryFeature(ctx, f, null, 'rgba(103, 232, 249, 0.28)', 0.9);
      }
    }

    // Active country shading (subtle breathing tint for countries with active connections)
    if (this.countryCounts.size > 0) {
      const breath = this.showAnimations ? 0.06 + 0.04 * (0.5 + 0.5 * Math.sin(timeSec * 2.1)) : 0.08;
      const fillCol = `rgba(34, 211, 238, ${breath.toFixed(3)})`;
      for (const f of this.features) {
        const count = this.countryCounts.get(f.name.toLowerCase());
        if (count) {
          this.drawCountryFeature(ctx, f, fillCol, 'rgba(34, 211, 238, 0.35)', 1.0);
        }
      }
    }

    // Hovered / Selected country highlight
    if (this.hoveredCountry) {
      this.drawCountryFeature(
        ctx,
        this.hoveredCountry,
        'rgba(56, 189, 248, 0.16)',
        'rgba(125, 211, 252, 0.75)',
        1.5
      );
    }
    if (this.selectedCountryName) {
      const sel = this.features.find(
        (f) => f.name.toLowerCase() === this.selectedCountryName.toLowerCase()
      );
      if (sel) {
        this.drawCountryFeature(ctx, sel, 'rgba(251, 191, 36, 0.12)', '#fbbf24', 1.8);
      }
    }

    // Day/night terminator
    this.drawTerminator(ctx);

    if (this.viewMode === 'global') {
      this.renderGlobalLayer(ctx, timeSec);
    } else {
      this.renderLocalLayer(ctx, timeSec);
    }

    this.renderRipples(ctx);
    this.renderTraceOverlay(ctx, timeSec);
    this.satelliteOverlay.render(ctx, this, timeSec);

    ctx.restore();
  }

  drawCometTrail(ctx, pts, phase, color, headRadius = 2.6, reverse = false) {
    if (!pts || pts.length < 2) return;
    const p = reverse ? 1 - phase : phase;
    const n = pts.length - 1;
    const tailLen = 6;
    ctx.save();
    for (let t = tailLen; t >= 0; t--) {
      const tp = p - (reverse ? -1 : 1) * (t * 0.015);
      if (tp < 0 || tp > 1) continue;
      const idx = Math.min(n, Math.max(0, Math.floor(tp * n)));
      const [px, py] = pts[idx];
      const frac = 1 - t / (tailLen + 1);
      ctx.beginPath();
      ctx.arc(px, py, Math.max(0.8, headRadius * frac), 0, Math.PI * 2);
      ctx.fillStyle = t === 0 ? '#f0f9ff' : color;
      ctx.globalAlpha = t === 0 ? 0.98 : frac * 0.55;
      if (t === 0) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 10;
      } else {
        ctx.shadowBlur = 0;
      }
      ctx.fill();
    }
    ctx.restore();
  }

  renderRipples(ctx) {
    if (!this.showAnimations || this.ripples.length === 0) return;
    const now = performance.now();
    ctx.save();
    for (let i = this.ripples.length - 1; i >= 0; i--) {
      const rp = this.ripples[i];
      const t = (now - rp.bornMs) / rp.durationMs;
      if (t >= 1) {
        this.ripples.splice(i, 1);
        continue;
      }
      const [rx, ry] = this.projectToScreen(rp.lon, rp.lat);
      const radius = 5 + t * 28;
      ctx.beginPath();
      ctx.arc(rx, ry, radius, 0, Math.PI * 2);
      ctx.strokeStyle = rp.color;
      ctx.globalAlpha = (1 - t) * 0.75;
      ctx.lineWidth = 1.8 * (1 - t) + 0.5;
      ctx.stroke();

      if (t > 0.2) {
        const t2 = (t - 0.2) / 0.8;
        ctx.beginPath();
        ctx.arc(rx, ry, 5 + t2 * 20, 0, Math.PI * 2);
        ctx.globalAlpha = (1 - t2) * 0.45;
        ctx.lineWidth = 1.0;
        ctx.stroke();
      }
    }
    ctx.restore();
  }

  renderTraceOverlay(ctx, timeSec) {
    if (!this.traceRoute || !this.traceRoute.hops || this.traceRoute.hops.length === 0) return;

    ctx.save();
    // Draw golden hop-by-hop geodesic route
    ctx.lineWidth = 2.6;
    ctx.strokeStyle = '#fbbf24';
    ctx.shadowColor = '#f59e0b';
    ctx.shadowBlur = 10;
    ctx.setLineDash([6, 4]);
    ctx.lineDashOffset = -timeSec * 28;

    const allPts = [];
    for (const seg of this.traceRoute.segments) {
      if (seg.length < 2) continue;
      ctx.beginPath();
      for (let i = 0; i < seg.length; i++) {
        const [sx, sy] = this.projectToScreen(seg[i][0], seg[i][1]);
        allPts.push([sx, sy]);
        if (i === 0) ctx.moveTo(sx, sy);
        else ctx.lineTo(sx, sy);
      }
      ctx.stroke();
    }
    ctx.setLineDash([]);
    ctx.shadowBlur = 0;

    // Animated packet along trace chain
    if (allPts.length >= 2) {
      const idx = Math.min(allPts.length - 1, Math.floor(((timeSec * 0.45) % 1) * (allPts.length - 1)));
      const [px, py] = allPts[idx];
      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#fef3c7';
      ctx.fill();
    }

    // Draw numbered hop waypoints
    for (const h of this.traceRoute.hops) {
      const [hx, hy] = this.projectToScreen(h.lon, h.lat);
      ctx.beginPath();
      ctx.arc(hx, hy, 8, 0, Math.PI * 2);
      ctx.fillStyle = '#f59e0b';
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = '#030712';
      ctx.stroke();

      ctx.font = '700 9px "JetBrains Mono", Consolas, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#030712';
      ctx.fillText(String(h.ttl), hx, hy + 0.5);

      const lbl = `#${h.ttl} ${h.label} (${Math.round(h.rttMs)}ms)`;
      ctx.font = '600 10.5px Inter, system-ui, sans-serif';
      ctx.textAlign = 'left';
      const tw = ctx.measureText(lbl).width + 10;
      ctx.fillStyle = 'rgba(2, 6, 23, 0.88)';
      ctx.fillRect(hx + 11, hy - 9, tw, 18);
      ctx.strokeStyle = 'rgba(251, 191, 36, 0.65)';
      ctx.lineWidth = 1;
      ctx.strokeRect(hx + 11, hy - 9, tw, 18);
      ctx.fillStyle = '#fef3c7';
      ctx.fillText(lbl, hx + 16, hy);
    }
    ctx.restore();
  }

  renderGlobalLayer(ctx, timeSec) {
    const [hx, hy] = this.projectToScreen(this.host.lon, this.host.lat);

    // Subtle background context of your local connections
    if (this.showArcs) {
      ctx.save();
      ctx.globalAlpha = 0.16;
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = '#38bdf8';
      for (const node of this.nodes) {
        for (const seg of node.segments) {
          if (seg.length < 2) continue;
          ctx.beginPath();
          for (let i = 0; i < seg.length; i++) {
            const [sx, sy] = this.projectToScreen(seg[i][0], seg[i][1]);
            if (i === 0) ctx.moveTo(sx, sy);
            else ctx.lineTo(sx, sy);
          }
          ctx.stroke();
        }
      }
      ctx.restore();
    }

    // Intercontinental backbone corridors
    for (let bIdx = 0; bIdx < this.backboneArcs.length; bIdx++) {
      const link = this.backboneArcs[bIdx];
      const aDown = link.a.status === 'down' || link.b.status === 'down';
      const aDeg = link.a.status === 'degraded' || link.b.status === 'degraded';
      const isHot =
        this.hoveredService &&
        (this.hoveredService.id === link.a.id || this.hoveredService.id === link.b.id);
      const col = aDown ? '#f43f5e' : aDeg ? '#fbbf24' : '#38bdf8';

      ctx.save();
      ctx.lineWidth = isHot ? 2.6 : 1.7;
      ctx.strokeStyle = isHot ? '#ffffff' : col;
      ctx.globalAlpha = isHot ? 0.95 : 0.62;
      if (isHot) {
        ctx.shadowColor = col;
        ctx.shadowBlur = 10;
      }

      const pts = [];
      for (const seg of link.segments) {
        if (seg.length < 2) continue;
        ctx.beginPath();
        for (let i = 0; i < seg.length; i++) {
          const [sx, sy] = this.projectToScreen(seg[i][0], seg[i][1]);
          pts.push([sx, sy]);
          if (i === 0) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        }
        ctx.stroke();
      }
      ctx.restore();

      // Bidirectional comet pulses along intercontinental corridors
      if (this.showAnimations && !aDown && pts.length >= 2) {
        for (let dir = 0; dir < 2; dir++) {
          const phase = (timeSec * 0.22 + bIdx * 0.17 + dir * 0.5) % 1;
          this.drawCometTrail(ctx, pts, phase, dir === 0 ? '#67e8f9' : '#6ee7b7', isHot ? 3.2 : 2.4, dir === 1);
        }
      }
    }

    // Draw non-continent services first, then continental hubs on top
    const ordered = [
      ...this.services.filter((s) => s.category !== 'continent'),
      ...this.services.filter((s) => s.category === 'continent'),
    ];

    for (const s of ordered) {
      const [sx, sy] = this.projectToScreen(s._lon, s._lat);
      s._sx = sx;
      s._sy = sy;

      const isCont = s.category === 'continent';
      const isHot =
        (this.hoveredService && this.hoveredService.id === s.id) ||
        this.selectedServiceId === s.id;
      const col = statusColor(s.status);
      const r = (isCont ? 9 : 5.2) + (isHot ? 2 : 0);

      if (isCont) {
        const pulse = (timeSec * 0.8 + (Math.abs(s.lon) % 1)) % 1;
        ctx.beginPath();
        ctx.arc(sx, sy, r + pulse * 14, 0, Math.PI * 2);
        ctx.strokeStyle = col;
        ctx.globalAlpha = (1 - pulse) * 0.55;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      ctx.beginPath();
      ctx.arc(sx, sy, r + 3, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.globalAlpha = isHot ? 0.42 : 0.22;
      ctx.fill();
      ctx.globalAlpha = 1;

      ctx.beginPath();
      ctx.arc(sx, sy, r, 0, Math.PI * 2);
      ctx.fillStyle = isHot ? '#ffffff' : col;
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = '#030712';
      ctx.stroke();

      if (isCont) {
        ctx.font = '700 9px "JetBrains Mono", Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#030712';
        ctx.fillText(s.continent, sx, sy + 0.5);

        const localCount = this.continentTraffic.get(s.continent) || 0;
        const rttTxt = s.status === 'down' ? 'OFF' : s.checksTotal > 0 ? `${Math.round(s.latencyMs)}ms` : '...';
        const label = `${s.continent} · ${rttTxt}${localCount > 0 ? ` · ${localCount} conn` : ''}`;

        ctx.font = '600 10.5px "JetBrains Mono", Consolas, monospace';
        ctx.textAlign = 'left';
        const tw = ctx.measureText(label).width + 10;
        ctx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        ctx.fillRect(sx + r + 5, sy - 9, tw, 18);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
        ctx.lineWidth = 1;
        ctx.strokeRect(sx + r + 5, sy - 9, tw, 18);
        ctx.fillStyle = '#f8fafc';
        ctx.fillText(label, sx + r + 10, sy);
      } else if (this.showLabels && (isHot || this.zoom >= 1.35)) {
        const rttTxt = s.status === 'down' ? 'OFF' : s.checksTotal > 0 ? `${Math.round(s.latencyMs)}ms` : '...';
        const label = `${s.name} · ${rttTxt}`;
        ctx.font = '500 10.5px Inter, system-ui, sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        const tw = ctx.measureText(label).width + 9;
        ctx.fillStyle = 'rgba(2, 6, 23, 0.82)';
        ctx.fillRect(sx + r + 4, sy - 8.5, tw, 17);
        ctx.fillStyle = '#e2e8f0';
        ctx.fillText(label, sx + r + 8, sy);
      }
    }

    // Host beacon marker
    ctx.save();
    ctx.beginPath();
    ctx.arc(hx, hy, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = '#10b981';
    ctx.strokeStyle = '#ecfdf5';
    ctx.lineWidth = 1.5;
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }

  renderLocalLayer(ctx, timeSec) {
    // Geodesic Connection Arcs + Animated Pulses
    const [hx, hy] = this.projectToScreen(this.host.lon, this.host.lat);

    if (this.showArcs) {
      for (const node of this.nodes) {
        const isHot =
          (this.hoveredNode && this.hoveredNode.key === node.key) ||
          this.selectedNodeKey === node.key;
        const baseColor = isHot ? '#ffffff' : node.color;
        const bwBoost = node.totalBps > 0 ? Math.min(2.0, Math.log10(node.totalBps + 1) * 0.32) : 0;
        const lineW = isHot ? 2.6 : Math.min(3.4, 0.9 + Math.log2(node.conns.length + 1) * 0.42 + bwBoost);

        ctx.save();
        ctx.lineWidth = lineW;
        ctx.strokeStyle = baseColor;
        ctx.globalAlpha = isHot ? 0.95 : node.life === 'closed' ? 0.35 : 0.48;
        if (isHot) {
          ctx.shadowColor = node.color;
          ctx.shadowBlur = 10;
        }

        const totalSegPts = [];
        for (const seg of node.segments) {
          if (seg.length < 2) continue;
          ctx.beginPath();
          for (let i = 0; i < seg.length; i++) {
            const [sx, sy] = this.projectToScreen(seg[i][0], seg[i][1]);
            totalSegPts.push([sx, sy]);
            if (i === 0) ctx.moveTo(sx, sy);
            else ctx.lineTo(sx, sy);
          }
          ctx.stroke();
        }
        ctx.restore();

        // Animated comet-tail packet pulses traveling along the geodesic arc
        if (this.showAnimations && node.life !== 'closed' && totalSegPts.length >= 2) {
          const speed = 0.26 + Math.min(0.48, node.conns.length * 0.045);
          const packetCount = node.conns.length >= 4 || node.totalBps > 50000 ? 2 : 1;
          for (let pk = 0; pk < packetCount; pk++) {
            const phase = (timeSec * speed + (Math.abs(node.lon) % 1) + pk * 0.5) % 1;
            this.drawCometTrail(ctx, totalSegPts, phase, node.color, isHot ? 3.4 : 2.5, pk === 1);
          }
        }
      }
    }

    // LAN Orbital Ring (when showLan enabled)
    if (this.showLan && this.lanNodes.length > 0) {
      const orbitR = 34;
      ctx.save();
      ctx.beginPath();
      ctx.setLineDash([4, 4]);
      ctx.arc(hx, hy, orbitR, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(167, 139, 250, 0.45)';
      ctx.lineWidth = 1.2;
      ctx.stroke();
      ctx.setLineDash([]);

      const maxSat = Math.min(this.lanNodes.length, 24);
      for (let i = 0; i < maxSat; i++) {
        const ang = (i / maxSat) * Math.PI * 2 + timeSec * 0.25;
        const sx = hx + Math.cos(ang) * orbitR;
        const sy = hy + Math.sin(ang) * orbitR;
        ctx.beginPath();
        ctx.arc(sx, sy, 2.8, 0, Math.PI * 2);
        ctx.fillStyle = '#a78bfa';
        ctx.fill();
      }
      ctx.restore();
    }

    // Remote Nodes
    for (const node of this.nodes) {
      const [nx, ny] = this.projectToScreen(node.lon, node.lat);
      node._sx = nx;
      node._sy = ny;

      const isHot =
        (this.hoveredNode && this.hoveredNode.key === node.key) ||
        this.selectedNodeKey === node.key;
      const r = Math.min(11, 3.6 + Math.sqrt(node.conns.length) * 1.4) + (isHot ? 2 : 0);

      // Arrival / active pulse ring
      if (node.life === 'new' || isHot) {
        const pulse = (timeSec * 1.8) % 1;
        ctx.beginPath();
        ctx.arc(nx, ny, r + pulse * 14, 0, Math.PI * 2);
        ctx.strokeStyle = node.color;
        ctx.globalAlpha = 1 - pulse;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Outer halo
      ctx.beginPath();
      ctx.arc(nx, ny, r + 3, 0, Math.PI * 2);
      ctx.fillStyle = node.color;
      ctx.globalAlpha = isHot ? 0.38 : 0.2;
      ctx.fill();
      ctx.globalAlpha = 1;

      // Core dot
      ctx.beginPath();
      ctx.arc(nx, ny, r, 0, Math.PI * 2);
      ctx.fillStyle = isHot ? '#ffffff' : node.color;
      ctx.fill();
      ctx.lineWidth = 1.2;
      ctx.strokeStyle = '#030712';
      ctx.stroke();

      // Count badge or city label
      if (node.conns.length > 1) {
        ctx.font = '600 10px "JetBrains Mono", Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#030712';
        ctx.fillText(String(node.conns.length), nx, ny + 0.5);
      }

      if (this.showLabels && (isHot || (this.zoom >= 1.5 && node.conns.length >= 2) || this.zoom >= 2.8)) {
        const label = node.city ? `${node.city} (${node.cc})` : node.country;
        ctx.font = '500 11px Inter, system-ui, sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = 'rgba(2, 6, 23, 0.78)';
        const w = ctx.measureText(label).width + 10;
        ctx.fillRect(nx + r + 5, ny - 9, w, 18);
        ctx.fillStyle = '#e2e8f0';
        ctx.fillText(label, nx + r + 10, ny);
      }
    }

    // Local Host Origin Beacon
    const beaconPulse = (timeSec * 0.9) % 1;
    ctx.save();
    ctx.beginPath();
    ctx.arc(hx, hy, 6 + beaconPulse * 20, 0, Math.PI * 2);
    ctx.strokeStyle = '#10b981';
    ctx.globalAlpha = (1 - beaconPulse) * 0.7;
    ctx.lineWidth = 1.6;
    ctx.stroke();
    ctx.globalAlpha = 1;

    ctx.beginPath();
    ctx.arc(hx, hy, 6.5, 0, Math.PI * 2);
    ctx.fillStyle = '#10b981';
    ctx.shadowColor = '#10b981';
    ctx.shadowBlur = 14;
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = '#ecfdf5';
    ctx.stroke();

    if (this.showLabels) {
      const originLabel = this.host.resolved ? `Você · ${this.host.city}` : 'Você (Local)';
      ctx.font = '600 11px Inter, system-ui, sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      const w = ctx.measureText(originLabel).width + 12;
      ctx.fillStyle = 'rgba(6, 78, 59, 0.85)';
      ctx.fillRect(hx + 11, hy - 10, w, 20);
      ctx.strokeStyle = 'rgba(16, 185, 129, 0.7)';
      ctx.lineWidth = 1;
      ctx.strokeRect(hx + 11, hy - 10, w, 20);
      ctx.fillStyle = '#ecfdf5';
      ctx.fillText(originLabel, hx + 17, hy);
    }
    ctx.restore();
  }

  hitTestNode(mx, my) {
    let best = null;
    let bestDist = 16;
    for (const node of this.nodes) {
      if (node._sx === undefined) continue;
      const d = Math.hypot(mx - node._sx, my - node._sy);
      if (d < bestDist) {
        bestDist = d;
        best = node;
      }
    }
    return best;
  }

  hitTestService(mx, my) {
    let best = null;
    let bestDist = 18;
    for (const s of this.services) {
      if (s._sx === undefined) continue;
      const d = Math.hypot(mx - s._sx, my - s._sy);
      if (d < bestDist) {
        bestDist = d;
        best = s;
      }
    }
    return best;
  }

  bindEvents() {
    window.addEventListener('resize', () => this.resize());

    this.canvas.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      this.isDragging = true;
      this.dragMoved = false;
      this.targetCamera = null;
      this.lastMouse = { x: e.clientX, y: e.clientY };
      this.canvas.style.cursor = 'grabbing';
    });

    window.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      this.mousePos = { x: mx, y: my };

      if (this.isDragging) {
        const dx = e.clientX - this.lastMouse.x;
        const dy = e.clientY - this.lastMouse.y;
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) this.dragMoved = true;
        this.panX += dx;
        this.panY += dy;
        this.lastMouse = { x: e.clientX, y: e.clientY };
        return;
      }

      const ll = this.screenToLonLat(mx, my);
      this.callbacks.onCursorCoords?.(ll);

      let hitSat = this.satelliteOverlay.hitTest(mx, my);
      this.satelliteOverlay.hoveredNoradId = hitSat ? hitSat.noradId : null;

      let hitNode = null;
      let hitSvc = null;
      if (!hitSat) {
        if (this.viewMode === 'global') {
          hitSvc = this.hitTestService(mx, my);
        } else {
          hitNode = this.hitTestNode(mx, my);
        }
      }
      this.hoveredNode = hitNode;
      this.hoveredService = hitSvc;

      let hitCountry = null;
      if (!hitSat && !hitNode && !hitSvc && ll && this.features.length > 0) {
        hitCountry = findCountryAt(this.features, ll[0], ll[1]);
      }
      this.hoveredCountry = hitCountry;

      this.canvas.style.cursor = hitSat || hitNode || hitSvc || hitCountry ? 'pointer' : 'grab';
      this.callbacks.onHover?.({
        x: e.clientX,
        y: e.clientY,
        satellite: hitSat,
        node: hitNode,
        service: hitSvc,
        country: hitCountry,
        countryCount: hitCountry ? this.countryCounts.get(hitCountry.name.toLowerCase()) || 0 : 0,
      });
    });

    window.addEventListener('mouseup', (e) => {
      if (!this.isDragging) return;
      this.isDragging = false;
      this.canvas.style.cursor =
        this.hoveredNode || this.hoveredService || this.hoveredCountry ? 'pointer' : 'grab';

      if (!this.dragMoved && e.target === this.canvas) {
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const hitSat = this.satelliteOverlay.hitTest(mx, my);
        if (hitSat) {
          this.satelliteOverlay.selectedNoradId = hitSat.noradId;
          this.selectedNodeKey = null;
          this.selectedServiceId = null;
          this.selectedCountryName = null;
          this.callbacks.onSelectSatellite?.(hitSat);
          return;
        }
        if (this.viewMode === 'global') {
          const hitSvc = this.hitTestService(mx, my);
          if (hitSvc) {
            this.selectedServiceId = hitSvc.id;
            this.selectedCountryName = null;
            this.callbacks.onSelectService?.(hitSvc);
            return;
          }
        } else {
          const hitNode = this.hitTestNode(mx, my);
          if (hitNode) {
            this.selectedNodeKey = hitNode.key;
            this.selectedCountryName = null;
            this.callbacks.onSelectNode?.(hitNode);
            return;
          }
        }
        const ll = this.screenToLonLat(mx, my);
        const hitCountry = ll ? findCountryAt(this.features, ll[0], ll[1]) : null;
        if (hitCountry) {
          this.selectedCountryName =
            this.selectedCountryName === hitCountry.name ? null : hitCountry.name;
          this.selectedNodeKey = null;
          this.callbacks.onSelectCountry?.(this.selectedCountryName);
          return;
        }
        // Clicked ocean -> clear map selection
        this.satelliteOverlay.selectedNoradId = null;
        this.selectedNodeKey = null;
        this.selectedCountryName = null;
        this.callbacks.onClearSelection?.();
      }
    });

    this.canvas.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const factor = e.deltaY < 0 ? 1.18 : 1 / 1.18;
        this.zoomBy(factor, mx, my);
      },
      { passive: false }
    );

    this.canvas.addEventListener('dblclick', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.zoomBy(1.75, e.clientX - rect.left, e.clientY - rect.top);
    });
  }
}
