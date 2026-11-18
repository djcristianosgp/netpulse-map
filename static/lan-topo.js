export class LanTopologyCanvas {
  constructor(canvas, onSelectNode) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.onSelectNode = onSelectNode;
    this.nodes = [];
    this.edges = [];
    this.nodeById = new Map();
    this.positions = new Map(); // id -> {x, y, r}
    this.selectedId = null;
    this.hoverId = null;
    this.search = '';
    this.filterMode = 'active_infra'; // 'active_infra' | 'online' | 'all'
    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.dragging = false;
    this.dragMoved = false;
    this.lastX = 0;
    this.lastY = 0;
    this.phase = 0;
    this.rafId = null;

    this.bindEvents();
  }

  bindEvents() {
    this.canvas.addEventListener('mousedown', (e) => {
      this.dragging = true;
      this.dragMoved = false;
      this.lastX = e.clientX;
      this.lastY = e.clientY;
    });

    window.addEventListener('mousemove', (e) => {
      if (this.dragging) {
        const dx = e.clientX - this.lastX;
        const dy = e.clientY - this.lastY;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) this.dragMoved = true;
        this.panX += dx;
        this.panY += dy;
        this.lastX = e.clientX;
        this.lastY = e.clientY;
        this.draw();
        return;
      }
      if (!this.canvas.offsetParent) return;
      const hit = this.hitTest(e.clientX, e.clientY);
      const nextId = hit ? hit.id : null;
      if (nextId !== this.hoverId) {
        this.hoverId = nextId;
        this.canvas.style.cursor = nextId ? 'pointer' : 'grab';
        this.draw();
      }
    });

    window.addEventListener('mouseup', (e) => {
      if (!this.dragging) return;
      const moved = this.dragMoved;
      this.dragging = false;
      if (!moved) {
        const hit = this.hitTest(e.clientX, e.clientY);
        this.selectedId = hit ? hit.id : null;
        if (this.onSelectNode) {
          this.onSelectNode(hit || null, this.getEdgesForNode(this.selectedId));
        }
        this.draw();
      }
    });

    this.canvas.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.14 : 0.88;
        const next = Math.max(0.35, Math.min(3.5, this.zoom * factor));
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left - rect.width / 2;
        const my = e.clientY - rect.top - rect.height / 2;
        this.panX = mx - ((mx - this.panX) * next) / this.zoom;
        this.panY = my - ((my - this.panY) * next) / this.zoom;
        this.zoom = next;
        this.draw();
      },
      { passive: false }
    );
  }

  screenToWorld(clientX, clientY) {
    const rect = this.canvas.getBoundingClientRect();
    const scaleX = this.canvas.width / Math.max(1, rect.width);
    const scaleY = this.canvas.height / Math.max(1, rect.height);
    const cx = (clientX - rect.left) * scaleX;
    const cy = (clientY - rect.top) * scaleY;
    const wx = (cx - this.canvas.width / 2 - this.panX) / this.zoom;
    const wy = (cy - this.canvas.height / 2 - this.panY) / this.zoom;
    return [wx, wy];
  }

  hitTest(clientX, clientY) {
    const [wx, wy] = this.screenToWorld(clientX, clientY);
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const pos = this.positions.get(n.id);
      if (!pos) continue;
      const dx = wx - pos.x;
      const dy = wy - pos.y;
      const hitR = pos.r + 7;
      if (dx * dx + dy * dy <= hitR * hitR) return n;
    }
    return null;
  }

  getEdgesForNode(nodeId) {
    if (!nodeId) return [];
    return this.edges.filter((e) => e.source === nodeId || e.target === nodeId);
  }

  fitView() {
    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;
    if (this.nodes.length > 18) {
      this.zoom = 0.86;
    }
    this.draw();
  }

  setData(topo, filterMode, search) {
    this.filterMode = filterMode || 'active_infra';
    this.search = (search || '').trim().toLowerCase();

    const rawNodes = topo?.nodes || [];
    const rawEdges = topo?.edges || [];

    const keptIds = new Set();
    for (const n of rawNodes) {
      if (n.kind !== 'lan_device') {
        keptIds.add(n.id);
        continue;
      }
      if (this.filterMode === 'all') {
        keptIds.add(n.id);
      } else if (this.filterMode === 'online') {
        if (n.status === 'online') keptIds.add(n.id);
      } else {
        // active_infra: keep online devices with open ports, active sockets, or identified vendor/name
        if (n.status === 'online' && (n.activeConns > 0 || (n.openPorts && n.openPorts.length > 0) || n.vendor)) {
          keptIds.add(n.id);
        }
      }
    }

    this.nodes = rawNodes.filter((n) => keptIds.has(n.id));
    this.edges = rawEdges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target));
    this.nodeById = new Map(this.nodes.map((n) => [n.id, n]));

    this.computeLayout();
    if (this.selectedId && !this.nodeById.has(this.selectedId)) {
      this.selectedId = null;
      if (this.onSelectNode) this.onSelectNode(null, []);
    } else if (this.selectedId && this.onSelectNode) {
      this.onSelectNode(this.nodeById.get(this.selectedId), this.getEdgesForNode(this.selectedId));
    }
    this.draw();
  }

  computeLayout() {
    this.positions.clear();
    const byKind = { host: [], interface: [], gwDns: [], upstream: [], lan: [] };
    for (const n of this.nodes) {
      if (n.kind === 'host') byKind.host.push(n);
      else if (n.kind === 'interface') byKind.interface.push(n);
      else if (n.kind === 'gateway' || n.kind === 'dns') byKind.gwDns.push(n);
      else if (n.kind === 'upstream') byKind.upstream.push(n);
      else byKind.lan.push(n);
    }

    // Layer 0: Host Local
    byKind.host.forEach((n, idx) => {
      this.positions.set(n.id, { x: -330, y: idx * 80, r: 22 });
    });

    // Layer 1: Interfaces
    const ifGap = 76;
    const ifStartY = -((byKind.interface.length - 1) * ifGap) / 2;
    byKind.interface.forEach((n, idx) => {
      this.positions.set(n.id, { x: -165, y: ifStartY + idx * ifGap, r: n.isPrimary ? 17 : 14 });
    });

    // Layer 2: Gateways & DNS
    const gwGap = 78;
    const gwStartY = -((byKind.gwDns.length - 1) * gwGap) / 2;
    byKind.gwDns.forEach((n, idx) => {
      this.positions.set(n.id, { x: 10, y: gwStartY + idx * gwGap, r: n.kind === 'gateway' ? 18 : 13 });
    });

    // Layer 4 Upstream placed cleanly top-right above LAN grid
    byKind.upstream.forEach((n, idx) => {
      this.positions.set(n.id, { x: 210, y: -185 + idx * 60, r: 20 });
    });

    // Layer 3: LAN devices packed in clean grid to the right so large /24 networks remain legible
    const lanCount = byKind.lan.length;
    const cols = lanCount <= 8 ? 2 : lanCount <= 24 ? 4 : 6;
    const colW = 86;
    const rowH = 66;
    const rows = Math.max(1, Math.ceil(lanCount / cols));
    const gridStartX = 165;
    const gridStartY = byKind.upstream.length ? -95 : -((rows - 1) * rowH) / 2;

    byKind.lan.forEach((n, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const r = n.activeConns > 0 ? 12 : n.openPorts ? 10 : 8;
      this.positions.set(n.id, {
        x: gridStartX + col * colW,
        y: gridStartY + row * rowH,
        r,
      });
    });
  }

  startAnimation() {
    if (this.rafId) return;
    const tick = () => {
      this.phase = (this.phase + 0.03) % 1000;
      if (this.canvas.offsetParent) {
        this.draw();
      }
      this.rafId = requestAnimationFrame(tick);
    };
    this.rafId = requestAnimationFrame(tick);
  }

  stopAnimation() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }

  nodeMatchesSearch(n) {
    if (!this.search) return false;
    const hay = `${n.label} ${n.ip} ${n.mac} ${n.vendor} ${n.deviceType} ${n.openPorts}`.toLowerCase();
    return hay.includes(this.search);
  }

  draw() {
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;
    ctx.clearRect(0, 0, w, h);

    // Subtle blueprint grid background
    ctx.save();
    ctx.fillStyle = 'rgba(2, 6, 23, 0.92)';
    ctx.fillRect(0, 0, w, h);

    ctx.translate(w / 2 + this.panX, h / 2 + this.panY);
    ctx.scale(this.zoom, this.zoom);

    const activeId = this.hoverId || this.selectedId;

    // 1. Edges
    for (const e of this.edges) {
      const p1 = this.positions.get(e.source);
      const p2 = this.positions.get(e.target);
      if (!p1 || !p2) continue;

      const touchesSelected = activeId && (e.source === activeId || e.target === activeId);
      let stroke = 'rgba(148, 163, 184, 0.24)';
      let width = 1.2;

      if (e.kind === 'active_socket') {
        stroke = 'rgba(52, 211, 153, 0.72)';
        width = 2.0;
      } else if (e.kind === 'default_route') {
        stroke = 'rgba(56, 189, 248, 0.68)';
        width = 2.2;
      } else if (e.kind === 'dns_config') {
        stroke = 'rgba(167, 139, 250, 0.45)';
        width = 1.4;
      }

      if (touchesSelected) {
        stroke = '#facc15';
        width = 2.5;
      }

      ctx.save();
      ctx.strokeStyle = stroke;
      ctx.lineWidth = width;
      if (e.kind === 'active_socket' || e.kind === 'default_route') {
        ctx.setLineDash([7, 5]);
        ctx.lineDashOffset = -this.phase * 18;
      }
      ctx.beginPath();
      const midX = (p1.x + p2.x) / 2;
      ctx.moveTo(p1.x, p1.y);
      ctx.bezierCurveTo(midX, p1.y, midX, p2.y, p2.x, p2.y);
      ctx.stroke();
      ctx.restore();
    }

    // 2. Nodes
    for (const n of this.nodes) {
      const p = this.positions.get(n.id);
      if (!p) continue;

      const isSel = n.id === this.selectedId;
      const isHover = n.id === this.hoverId;
      const matched = this.nodeMatchesSearch(n);

      let fill = '#1e293b';
      let ring = '#38bdf8';
      if (n.kind === 'host') {
        fill = '#0f172a';
        ring = '#22d3ee';
      } else if (n.kind === 'interface') {
        fill = n.status === 'up' ? '#083344' : '#334155';
        ring = n.status === 'up' ? '#38bdf8' : '#f43f5e';
      } else if (n.kind === 'gateway') {
        fill = '#1e1b4b';
        ring = n.status === 'degraded' ? '#fbbf24' : '#818cf8';
      } else if (n.kind === 'dns') {
        fill = '#2e1065';
        ring = n.status === 'down' ? '#f43f5e' : '#a78bfa';
      } else if (n.kind === 'upstream') {
        fill = '#064e3b';
        ring = '#34d399';
      } else if (n.kind === 'lan_device') {
        fill = n.status === 'online' ? '#0f172a' : '#1e293b';
        ring = n.activeConns > 0 ? '#34d399' : n.status === 'online' ? '#38bdf8' : '#64748b';
      }

      if (matched) ring = '#facc15';
      if (isSel || isHover) ring = '#ffffff';

      if (n.isPrimary || matched || isSel) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r + 5, 0, Math.PI * 2);
        ctx.fillStyle = matched ? 'rgba(250, 204, 21, 0.22)' : 'rgba(56, 189, 248, 0.18)';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = fill;
      ctx.fill();
      ctx.lineWidth = isSel ? 2.6 : 1.8;
      ctx.strokeStyle = ring;
      ctx.stroke();

      // Draw concise label for key nodes or when zoomed in
      const showLabel = n.kind !== 'lan_device' || this.nodes.length <= 28 || this.zoom >= 1.15 || isSel || isHover || matched;
      if (showLabel) {
        ctx.fillStyle = '#e2e8f0';
        ctx.font = n.kind === 'host' || n.kind === 'gateway' ? 'bold 10.5px sans-serif' : '9.5px sans-serif';
        ctx.textAlign = 'center';
        const shortLbl = n.label.length > 18 ? n.label.slice(0, 17) + '…' : n.label;
        ctx.fillText(shortLbl, p.x, p.y + p.r + 12);
      }
    }

    ctx.restore();
  }
}
