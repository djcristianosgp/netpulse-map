import { LanTopologyCanvas } from './lan-topo.js';

function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtBps(bps) {
  if (!bps || bps < 1) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let i = 0;
  let v = bps;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function fmtBytes(bytes) {
  if (!bytes || bytes < 1) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export class NocDashboardController {
  constructor({ apiFetch, onClose }) {
    this.apiFetch = apiFetch;
    this.onClose = onClose;
    this.active = false;
    this.intervalSec = 5;
    this.range = '24h';
    this.autoRotate = false;
    this.focusView = 'all'; // 'all' | 'quality' | 'topology'
    this.refreshTimer = null;
    this.clockTimer = null;
    this.rotateTimer = null;
    this.countdownSec = 5;
    this.topoCanvas = null;
    this.lastData = null;

    this.bindUi();
  }

  el(id) {
    return document.getElementById(id);
  }

  bindUi() {
    this.el('btnNocClose')?.addEventListener('click', () => this.close());
    this.el('btnNocFullscreen')?.addEventListener('click', () => this.toggleFullscreen());
    this.el('btnNocRefresh')?.addEventListener('click', () => this.fetchAndRender());

    this.el('nocIntervalSelect')?.addEventListener('change', (e) => {
      this.intervalSec = Math.max(5, parseInt(e.target.value, 10) || 5);
      this.countdownSec = this.intervalSec;
      this.restartTimers();
    });

    this.el('nocRangeSelect')?.addEventListener('change', (e) => {
      this.range = e.target.value || '24h';
      this.fetchAndRender();
    });

    this.el('nocRotateToggle')?.addEventListener('change', (e) => {
      this.autoRotate = Boolean(e.target.checked);
      this.restartRotateTimer();
    });

    document.querySelectorAll('#nocFocusTabs .tab-btn[data-nfocus]').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.setFocusView(btn.getAttribute('data-nfocus') || 'all');
      });
    });
  }

  open(enterFullscreen = false) {
    const overlay = this.el('nocOverlay');
    if (!overlay) return;
    this.active = true;
    overlay.classList.remove('hidden');
    if (!this.topoCanvas && this.el('nocTopoCanvas')) {
      this.topoCanvas = new LanTopologyCanvas(this.el('nocTopoCanvas'));
    }
    this.setFocusView(this.focusView);
    this.countdownSec = this.intervalSec;
    this.updateClock();
    this.fetchAndRender();
    this.restartTimers();
    this.restartRotateTimer();

    if (enterFullscreen && document.documentElement.requestFullscreen && !document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    }
  }

  close() {
    this.active = false;
    this.el('nocOverlay')?.classList.add('hidden');
    clearInterval(this.refreshTimer);
    clearInterval(this.clockTimer);
    clearInterval(this.rotateTimer);
    this.refreshTimer = null;
    this.clockTimer = null;
    this.rotateTimer = null;
    if (document.fullscreenElement && document.exitFullscreen) {
      document.exitFullscreen().catch(() => {});
    }
    if (this.onClose) this.onClose();
  }

  toggleFullscreen() {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen?.().catch(() => {});
    } else {
      document.exitFullscreen?.().catch(() => {});
    }
  }

  setFocusView(view) {
    this.focusView = view;
    document.querySelectorAll('#nocFocusTabs .tab-btn[data-nfocus]').forEach((b) => {
      b.classList.toggle('active', b.getAttribute('data-nfocus') === view);
    });
    const grid = this.el('nocMainGrid');
    const topoWrap = this.el('nocTopoStage');
    if (grid && topoWrap) {
      grid.classList.toggle('hidden', view === 'topology');
      topoWrap.classList.toggle('hidden', view !== 'topology');
    }
    if (this.lastData) {
      this.renderFocusHighlights();
      if (view === 'topology') {
        this.fetchAndRenderTopology();
      } else {
        this.drawTrafficChart(this.lastData);
      }
    }
  }

  renderFocusHighlights() {
    const panels = ['nocCardTraffic', 'nocCardQuality', 'nocCardInterfaces', 'nocCardSecurity', 'nocCardServices', 'nocCardTopApps'];
    for (const pid of panels) {
      const card = this.el(pid);
      if (!card) continue;
      card.classList.remove('noc-card-dim');
      if (this.focusView === 'quality' && pid !== 'nocCardQuality' && pid !== 'nocCardInterfaces' && pid !== 'nocCardServices') {
        card.classList.add('noc-card-dim');
      }
    }
  }

  restartTimers() {
    clearInterval(this.refreshTimer);
    clearInterval(this.clockTimer);
    this.clockTimer = setInterval(() => {
      if (!this.active) return;
      this.updateClock();
      this.countdownSec -= 1;
      if (this.countdownSec <= 0) {
        this.countdownSec = this.intervalSec;
        this.fetchAndRender();
      }
      const cd = this.el('nocCountdown');
      if (cd) cd.textContent = `Auto ${this.countdownSec}s`;
    }, 1000);
  }

  restartRotateTimer() {
    clearInterval(this.rotateTimer);
    if (!this.autoRotate || !this.active) return;
    const views = ['all', 'quality', 'topology'];
    this.rotateTimer = setInterval(() => {
      if (!this.active || !this.autoRotate) return;
      const idx = (views.indexOf(this.focusView) + 1) % views.length;
      this.setFocusView(views[idx]);
    }, 15000);
  }

  updateClock() {
    const clk = this.el('nocClock');
    if (clk) {
      clk.textContent = new Date().toLocaleTimeString('pt-BR', { hour12: false });
    }
  }

  async fetchAndRender() {
    if (!this.active) return;
    try {
      const resp = await this.apiFetch(`/api/noc/overview?range=${encodeURIComponent(this.range)}`);
      if (!resp.ok) return;
      const data = await resp.json();
      this.lastData = data;
      this.renderOverview(data);
      if (this.focusView === 'topology') {
        this.fetchAndRenderTopology();
      }
    } catch {}
  }

  async fetchAndRenderTopology() {
    if (!this.active || !this.topoCanvas) return;
    try {
      const resp = await this.apiFetch('/api/topology/lan');
      if (!resp.ok) return;
      const topo = await resp.json();
      this.topoCanvas.setData(topo, 'infra_or_active', '');
      this.topoCanvas.fitView();
    } catch {}
  }

  renderOverview(d) {
    const snap = d.snapshot || {};
    const qual = d.quality || {};
    const ifaces = d.interfaces || {};
    const disc = d.discovery || {};
    const intel = d.intelligence || {};
    const svcs = Array.isArray(d.services) ? d.services : [];
    const ana = d.analytics || {};
    const stor = d.storage || {};

    const diag = qual.diagnosis || {};
    const qHealth = diag.overallHealth || 'unknown';
    const rLevel = intel.overallRiskLevel || 'informative';
    const rScore = Number(intel.overallRiskScore || 0);
    const ifSum = ifaces.summary || {};

    const hdrMeta = this.el('nocHeaderBadges');
    if (hdrMeta) {
      hdrMeta.innerHTML = `
        <span class="state-pill">v${escHtml(d.version || '1.11.0')}</span>
        <span class="state-pill ${qHealth === 'critical' ? 'closed' : qHealth === 'degraded' ? 'syn' : 'new'}">QUALIDADE: ${escHtml(qHealth.toUpperCase())}</span>
        <span class="risk-pill ${escHtml(rLevel)}">RISCO ${rScore} · ${escHtml(rLevel.toUpperCase())}</span>
        <span class="state-pill">WAN: ${escHtml(ifSum.primaryInterface || '—')} (${escHtml(ifSum.primaryGateway || '—')})</span>
      `;
    }

    const nic = snap.nic || {};
    const stats = snap.stats || {};
    const targets = qual.targets || [];
    const okTargets = targets.filter((t) => t.status === 'ok').length;
    const worstLoss = targets.reduce((m, t) => Math.max(m, Number(t.metrics?.packetLossPct || 0)), 0);
    const avgP50 = targets.length
      ? targets.reduce((s, t) => s + Number(t.metrics?.p50Ms || t.metrics?.currentLatencyMs || 0), 0) / targets.length
      : 0;

    const svcsUp = svcs.filter((s) => s.status === 'up').length;
    const svcsDown = svcs.filter((s) => s.status === 'down').length;
    const dSum = disc.summary || {};

    this.el('nocKpiStrip').innerHTML = `
      <div class="noc-kpi"><span>THROUGHPUT RX / TX</span><strong>${escHtml(fmtBps(nic.rxBytesPerSec || 0))} / ${escHtml(fmtBps(nic.txBytesPerSec || 0))}</strong><small>Total ${escHtml(this.range)}: ${escHtml(fmtBytes(ana.totals?.totalBytes || 0))}</small></div>
      <div class="noc-kpi"><span>CONEXÕES ATIVAS</span><strong>${Number(stats.publicConnections || 0)} Pub · ${Number(stats.lanConnections || 0)} LAN</strong><small>Bind/UDP: ${Number(stats.listeningSockets || 0)} · Processos: ${Number((snap.processes || []).length)}</small></div>
      <div class="noc-kpi"><span>QUALIDADE REDE</span><strong>${avgP50.toFixed(1)} ms · ${worstLoss.toFixed(1)}% perda</strong><small>${okTargets}/${targets.length} alvos saudáveis</small></div>
      <div class="noc-kpi"><span>SERVIÇOS ÂNCORA</span><strong>${svcsUp}/${svcs.length} UP</strong><small>${svcsDown > 0 ? svcsDown + ' indisponível(is)' : 'Todos operacionais'}</small></div>
      <div class="noc-kpi"><span>DISPOSITIVOS LAN</span><strong>${Number(dSum.onlineCount || 0)} / ${Number(dSum.totalDevices || 0)} Online</strong><small>Gateways: ${Number(dSum.gatewaysCount || 0)} · Fabricantes: ${Number(dSum.vendorsCount || 0)}</small></div>
      <div class="noc-kpi"><span>INTELLIGENCE (ZERO IA)</span><strong>Risco ${rScore} (${escHtml(rLevel.toUpperCase())})</strong><small>${Number(intel.unacknowledgedCount || 0)} alertas pendentes · SQLite ${escHtml(fmtBytes(stor.sizeBytes || 0))}</small></div>
    `;

    this.drawTrafficChart(d);

    const topProcs = (ana.topProcesses || []).slice(0, 5);
    const maxBytes = topProcs.reduce((m, p) => Math.max(m, Number(p.totalBytes || 0)), 1);
    const topCountries = (ana.topCountries || []).slice(0, 5);
    this.el('nocTopAppsBody').innerHTML = `
      <div class="noc-sub-hdr">Top 5 Aplicações (${escHtml(this.range)})</div>
      ${topProcs.length === 0 ? '<div class="sec-row-meta">Aguardando rollups históricos...</div>' : topProcs.map((p) => {
        const pct = Math.max(4, Math.round((Number(p.totalBytes || 0) / maxBytes) * 100));
        return `<div class="noc-bar-row"><div><strong>${escHtml(p.processName)}</strong><span>${escHtml(fmtBytes(p.totalBytes || 0))}</span></div><div class="noc-bar-track"><div class="noc-bar-fill" style="width:${pct}%"></div></div></div>`;
      }).join('')}
      <div class="noc-sub-hdr" style="margin-top:8px">Top 5 Países (${escHtml(this.range)})</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${topCountries.map((c) => `<span class="state-pill">${escHtml(c.countryCode || '?')} · ${escHtml(fmtBytes(c.totalBytes || 0))}</span>`).join('') || '<span class="sec-row-meta">—</span>'}
      </div>
    `;

    this.el('nocQualityBody').innerHTML = targets.slice(0, 6).map((t) => {
      const m = t.metrics || {};
      const stCls = t.status === 'ok' ? 'new' : t.status === 'down' ? 'closed' : 'syn';
      return `<div class="sec-row"><div><strong>${escHtml(t.name)}</strong> <span class="sec-row-meta">${escHtml(t.host)}</span></div><div><span class="sec-row-meta">${Number(m.currentLatencyMs || 0).toFixed(1)}ms · P95 ${Number(m.p95Ms || 0).toFixed(1)}ms · J ${Number(m.jitterMs || 0).toFixed(1)}ms · Loss ${Number(m.packetLossPct || 0).toFixed(1)}%</span> <span class="state-pill ${stCls}">${escHtml((t.status || '').toUpperCase())}</span></div></div>`;
    }).join('') || '<div class="sec-row-meta">Sem sondagens registradas.</div>';

    const ifList = ifaces.interfaces || [];
    this.el('nocInterfacesBody').innerHTML = ifList.slice(0, 5).map((ifc) => {
      const up = ifc.operStatus === 'up';
      return `<div class="sec-row"><div><strong>${escHtml(ifc.name)}</strong> <span class="state-pill">${escHtml(ifc.type || '')}</span> ${ifc.isDefaultRoute ? '<span class="state-pill new">PRIMÁRIA</span>' : ''}</div><div class="sec-row-meta">↓ ${escHtml(fmtBps(ifc.rxBps || 0))} · ↑ ${escHtml(fmtBps(ifc.txBps || 0))} · <span class="state-pill ${up ? 'new' : 'closed'}">${escHtml((ifc.operStatus || '').toUpperCase())}</span></div></div>`;
    }).join('') || '<div class="sec-row-meta">Nenhuma interface detectada.</div>';

    const findings = diag.findings || [];
    const svcsHtml = svcs.slice(0, 8).map((s) => {
      const cls = s.status === 'up' ? 'new' : s.status === 'down' ? 'closed' : 'syn';
      return `<span class="state-pill ${cls}" title="${escHtml(s.host)}">${escHtml(s.name)} ${Number(s.latencyMs || 0).toFixed(0)}ms</span>`;
    }).join('');
    const findHtml = findings.slice(0, 3).map((f) =>
      `<div class="diag-card ${f.severity === 'critical' ? 'critical' : f.severity === 'warn' ? 'warn' : 'ok'}"><strong>${escHtml(f.title)}</strong><div class="sec-row-meta">${escHtml((f.observedFacts || [])[0] || '')}</div></div>`
    ).join('');
    this.el('nocServicesBody').innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px">${svcsHtml}</div>${findHtml}`;

    const alerts = (intel.alerts || []).slice(0, 6);
    this.el('nocSecurityBody').innerHTML = alerts.length === 0
      ? '<div class="sec-row-meta">Nenhum alerta comportamental recente.</div>'
      : alerts.map((a) => `
        <div class="sec-row">
          <div style="min-width:0;flex:1">
            <span class="risk-pill ${escHtml(a.riskLevel)}">${escHtml(a.riskLevel)} ${Number(a.riskScore)}</span>
            <strong>${escHtml(a.ruleName)}</strong>
            <span class="sec-row-meta">${escHtml(a.processName || 'Host')} · ${escHtml(a.destination || '—')}</span>
            <div class="sec-row-meta">${escHtml(a.whatHappened)}</div>
          </div>
          <span class="sec-row-meta">${new Date(a.tsMs).toLocaleTimeString('pt-BR')}</span>
        </div>
      `).join('');

    this.renderFocusHighlights();
  }

  drawTrafficChart(d) {
    const canvas = this.el('nocTrafficCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = 'rgba(2, 6, 23, 0.72)';
    ctx.fillRect(0, 0, w, h);

    const series = d.analytics?.dailyTraffic || [];
    if (series.length === 0) {
      ctx.fillStyle = '#94a3b8';
      ctx.font = '12px monospace';
      ctx.fillText('Aguardando dados históricos RX/TX no SQLite WAL...', 18, h / 2);
      return;
    }

    const maxV = Math.max(1, ...series.map((pt) => Math.max(Number(pt.rxBytes || 0), Number(pt.txBytes || 0))));
    const padL = 12;
    const padR = 12;
    const padT = 18;
    const padB = 22;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;
    const step = plotW / Math.max(1, series.length);

    ctx.strokeStyle = 'rgba(148, 163, 184, 0.14)';
    ctx.lineWidth = 1;
    for (let g = 0; g <= 3; g += 1) {
      const y = padT + (plotH * g) / 3;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
    }

    series.forEach((pt, idx) => {
      const rxH = (Number(pt.rxBytes || 0) / maxV) * plotH;
      const txH = (Number(pt.txBytes || 0) / maxV) * plotH;
      const x = padL + idx * step + 2;
      const bw = Math.max(4, step * 0.36);
      ctx.fillStyle = 'rgba(34, 211, 238, 0.82)';
      ctx.fillRect(x, padT + plotH - rxH, bw, rxH);
      ctx.fillStyle = 'rgba(52, 211, 153, 0.82)';
      ctx.fillRect(x + bw + 2, padT + plotH - txH, bw, txH);

      if (series.length <= 14 || idx % Math.ceil(series.length / 7) === 0) {
        const lbl = new Date(pt.bucketMs || Date.now()).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px monospace';
        ctx.fillText(lbl, x, h - 6);
      }
    });

    ctx.fillStyle = '#7dd3fc';
    ctx.font = '11px monospace';
    ctx.fillText(`Pico RX/TX janela: ${fmtBytes(maxV)}`, padL + 4, 13);
  }
}
