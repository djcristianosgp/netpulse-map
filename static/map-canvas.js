import {
  PROJECTIONS,
  buildGreatCircleSegments,
  computeSolarTerminatorPolygon,
  findCountryAt,
} from './topo.js';

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

    this.nodes = [];
    this.lanNodes = [];
    this.countryCounts = new Map(); // countryCode / countryName -> count
    this.host = { lat: -23.55, lon: -46.63, city: 'Local Host', country: 'Local', resolved: false };

    this.hoveredNode = null;
    this.selectedNodeKey = null;
    this.hoveredCountry = null;
    this.selectedCountryName = null;

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
    this.fitPlanet();
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
      top: 72,
      bottom: 54,
      left: leftOpen ? 372 : 24,
      right: rightOpen ? 360 : 24,
    };
  }

  fitPlanet() {
    const pad = this.getSafePadding();
    const availW = Math.max(240, this.viewW - pad.left - pad.right);
    const availH = Math.max(200, this.viewH - pad.top - pad.bottom);
    const wh = this.worldHeight();
    const scale = Math.min(availW / WORLD_W, availH / wh) * 0.96;
    this.zoom = Math.max(0.4, scale);
    this.panX = pad.left + (availW - WORLD_W * this.zoom) * 0.5;
    this.panY = pad.top + (availH - wh * this.zoom) * 0.5;
    this.targetCamera = null;
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
    for (const node of nodeMap.values()) {
      node.segments = buildGreatCircleSegments(hostLon, hostLat, node.lon, node.lat, 36);
      node.life = node.hasNew ? 'new' : node.allClosed ? 'closed' : 'active';
      node.color = node.hasEstablished
        ? colorForState('ESTABLISHED', node.life)
        : colorForState(node.dominantState, node.life);
      nextNodes.push(node);
    }

    this.nodes = nextNodes;
    this.lanNodes = lanList;
    this.countryCounts = countryTotals;
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

    // Deep space background
    ctx.fillStyle = '#030712';
    ctx.fillRect(0, 0, this.viewW, this.viewH);

    // Draw cached world map
    const drawW = WORLD_W * this.zoom;
    const drawH = this.worldHeight() * this.zoom;
    ctx.drawImage(this.baseLayerCanvas, this.panX, this.panY, drawW, drawH);

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

    // Active country shading (subtle tint for countries with active connections)
    if (this.countryCounts.size > 0) {
      for (const f of this.features) {
        const count = this.countryCounts.get(f.name.toLowerCase());
        if (count) {
          this.drawCountryFeature(
            ctx,
            f,
            'rgba(34, 211, 238, 0.08)',
            'rgba(34, 211, 238, 0.35)',
            1.0
          );
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

    // Geodesic Connection Arcs + Animated Pulses
    const [hx, hy] = this.projectToScreen(this.host.lon, this.host.lat);

    if (this.showArcs) {
      for (const node of this.nodes) {
        const isHot =
          (this.hoveredNode && this.hoveredNode.key === node.key) ||
          this.selectedNodeKey === node.key;
        const baseColor = isHot ? '#ffffff' : node.color;
        const lineW = isHot ? 2.4 : Math.min(2.6, 0.9 + Math.log2(node.conns.length + 1) * 0.45);

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

        // Animated packet pulse traveling along the longest arc segment
        if (node.life !== 'closed' && totalSegPts.length >= 2) {
          const speed = 0.28 + Math.min(0.45, node.conns.length * 0.05);
          const phase = (timeSec * speed + (Math.abs(node.lon) % 1)) % 1;
          const idx = Math.min(
            totalSegPts.length - 1,
            Math.floor(phase * (totalSegPts.length - 1))
          );
          const [px, py] = totalSegPts[idx];
          ctx.save();
          ctx.beginPath();
          ctx.arc(px, py, isHot ? 3.5 : 2.3, 0, Math.PI * 2);
          ctx.fillStyle = '#e0f2fe';
          ctx.shadowColor = node.color;
          ctx.shadowBlur = 10;
          ctx.fill();
          ctx.restore();
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

      const hitNode = this.hitTestNode(mx, my);
      this.hoveredNode = hitNode;

      let hitCountry = null;
      if (!hitNode && ll && this.features.length > 0) {
        hitCountry = findCountryAt(this.features, ll[0], ll[1]);
      }
      this.hoveredCountry = hitCountry;

      this.canvas.style.cursor = hitNode || hitCountry ? 'pointer' : 'grab';
      this.callbacks.onHover?.({
        x: e.clientX,
        y: e.clientY,
        node: hitNode,
        country: hitCountry,
        countryCount: hitCountry ? this.countryCounts.get(hitCountry.name.toLowerCase()) || 0 : 0,
      });
    });

    window.addEventListener('mouseup', (e) => {
      if (!this.isDragging) return;
      this.isDragging = false;
      this.canvas.style.cursor = this.hoveredNode || this.hoveredCountry ? 'pointer' : 'grab';

      if (!this.dragMoved && e.target === this.canvas) {
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const hitNode = this.hitTestNode(mx, my);
        if (hitNode) {
          this.selectedNodeKey = hitNode.key;
          this.selectedCountryName = null;
          this.callbacks.onSelectNode?.(hitNode);
          return;
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
