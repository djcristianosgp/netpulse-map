import { decodeTopoJson } from './topo.js';
import { PlanetMapCanvas } from './map-canvas.js';

const $ = (id) => document.getElementById(id);

function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytesPerSec(bps) {
  if (!bps || bps < 1) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let idx = 0;
  let val = bps;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val >= 100 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

function formatAge(ms) {
  const sec = Math.floor((ms || 0) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${sec % 60}s`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

function stateBadgeClass(c) {
  if (c.scope !== 'public') return 'lan';
  if (c.life === 'closed') return 'closed';
  if (c.life === 'new') return 'new';
  if (c.state === 'SYN_SENT' || c.state === 'SYN_RCVD') return 'syn';
  return '';
}

const state = {
  paused: false,
  snapshot: null,
  initialVersion: null,
  viewMode: 'local',    // 'local' | 'global'
  tab: 'conns',         // 'conns' | 'procs' | 'countries'
  globalTab: 'services',// 'services' | 'continents'
  filter: 'all',        // 'all' | 'public' | 'lan' | 'established' | 'new'
  search: '',
  selectedCountry: null,
  selectedProcess: null,
  selectedConnKey: null,
  selectedNodeKey: null,
  selectedServiceId: null,
  rxHistory: new Array(60).fill(0),
  txHistory: new Array(60).fill(0),
};

let ws = null;
let reconnectTimer = null;

const mapCanvas = new PlanetMapCanvas($('planetCanvas'), {
  onCursorCoords(ll) {
    if (!ll) {
      $('cursorCoords').textContent = 'FORA DO PLANETA';
      return;
    }
    const [lon, lat] = ll;
    const latStr = `${Math.abs(lat).toFixed(2)}°${lat >= 0 ? 'N' : 'S'}`;
    const lonStr = `${Math.abs(lon).toFixed(2)}°${lon >= 0 ? 'E' : 'W'}`;
    $('cursorCoords').textContent = `LAT ${latStr} · LON ${lonStr}`;
  },
  onZoomChange(zoom) {
    $('zoomLevel').textContent = `${Math.round(zoom * 100)}%`;
  },
  onHover({ x, y, node, service, country, countryCount }) {
    const tt = $('mapTooltip');
    if (service) {
      const rtt =
        service.status === 'down'
          ? `OFFLINE (${service.err || 'falha'})`
          : service.checksTotal > 0
          ? `${service.latencyMs.toFixed(1)} ms (média ${service.avgLatencyMs.toFixed(1)} ms)`
          : 'Medindo...';
      const extra =
        service.category === 'continent'
          ? ` · ${mapCanvas.continentTraffic.get(service.continent) || 0} conexões suas`
          : ` · Uptime ${service.uptimePct}%`;
      tt.innerHTML = `
        <div class="tt-title">${escHtml(service.name)}</div>
        <div class="tt-sub">${escHtml(service.host)}:${service.port}</div>
        <div class="tt-sub">${escHtml(rtt)}${escHtml(extra)}</div>
      `;
      positionTooltip(tt, x, y);
      tt.classList.remove('hidden');
      return;
    }
    if (node) {
      const procs = Array.from(node.processes).slice(0, 4).join(', ');
      const place = [node.city, node.country].filter(Boolean).join(', ');
      tt.innerHTML = `
        <div class="tt-title">${escHtml(place || 'Local Desconhecido')} (${escHtml(node.cc)})</div>
        <div class="tt-sub">${node.conns.length} conex${node.conns.length === 1 ? 'ão' : 'ões'} · ${escHtml(procs)}</div>
        ${node.isp ? `<div class="tt-sub">${escHtml(node.isp)}</div>` : ''}
      `;
      positionTooltip(tt, x, y);
      tt.classList.remove('hidden');
      return;
    }
    if (country) {
      tt.innerHTML = `
        <div class="tt-title">${escHtml(country.name)}</div>
        <div class="tt-sub">${countryCount > 0 ? `${countryCount} conexões ativas` : 'Sem conexões ativas'}</div>
      `;
      positionTooltip(tt, x, y);
      tt.classList.remove('hidden');
      return;
    }
    tt.classList.add('hidden');
  },
  onSelectNode(node) {
    state.selectedNodeKey = node.key;
    state.selectedConnKey = node.conns[0]?.k || null;
    state.selectedCountry = null;
    openNodeInspector(node);
    renderPanel();
  },
  onSelectService(svc) {
    state.selectedServiceId = svc.id;
    state.selectedCountry = null;
    openServiceInspector(svc);
    renderPanel();
  },
  onSelectCountry(countryName) {
    state.selectedCountry = countryName;
    state.selectedNodeKey = null;
    if (!countryName) {
      closeInspector();
    } else {
      openCountryInspector(countryName);
    }
    applyAndRender();
  },
  onClearSelection() {
    state.selectedNodeKey = null;
    state.selectedConnKey = null;
    state.selectedCountry = null;
    closeInspector();
    applyAndRender();
  },
});

function positionTooltip(el, x, y) {
  const pad = 14;
  let left = x + pad;
  let top = y + pad;
  if (left + 290 > window.innerWidth) left = x - 290;
  if (top + 90 > window.innerHeight) top = y - 90;
  el.style.left = `${Math.max(8, left)}px`;
  el.style.top = `${Math.max(8, top)}px`;
}

function drawSparkline() {
  const c = $('sparklineCanvas');
  const ctx = c.getContext('2d');
  const w = c.width;
  const h = c.height;
  ctx.clearRect(0, 0, w, h);

  let maxVal = 1024; // minimum 1 KB/s scale
  for (let i = 0; i < 60; i++) {
    if (state.rxHistory[i] > maxVal) maxVal = state.rxHistory[i];
    if (state.txHistory[i] > maxVal) maxVal = state.txHistory[i];
  }

  const drawSeries = (arr, stroke, fill) => {
    ctx.beginPath();
    for (let i = 0; i < arr.length; i++) {
      const x = (i / (arr.length - 1)) * w;
      const y = h - 2 - (arr[i] / maxVal) * (h - 6);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
  };

  drawSeries(state.rxHistory, '#22d3ee', 'rgba(34, 211, 238, 0.14)');
  drawSeries(state.txHistory, '#10b981', 'rgba(16, 185, 129, 0.12)');
}

function getFilteredConnections() {
  const snap = state.snapshot;
  if (!snap) return [];

  const q = state.search.trim().toLowerCase();
  const geo = snap.geo || {};
  const dns = snap.dns || {};

  return snap.conns.filter((c) => {
    if (state.filter === 'public' && c.scope !== 'public') return false;
    if (state.filter === 'lan' && c.scope === 'public') return false;
    if (state.filter === 'established' && c.state !== 'ESTABLISHED') return false;
    if (state.filter === 'new' && c.life !== 'new') return false;

    if (state.selectedProcess && c.proc !== state.selectedProcess) return false;

    const g = geo[c.rip];
    if (state.selectedCountry) {
      if (!g || (g.country || '').toLowerCase() !== state.selectedCountry.toLowerCase()) {
        return false;
      }
    }

    if (q) {
      const host = dns[c.rip] || '';
      const hay = [
        c.proc,
        c.rip,
        c.lip,
        String(c.rport),
        String(c.lport),
        c.state,
        host,
        g?.country || '',
        g?.cc || '',
        g?.city || '',
        g?.isp || '',
        g?.asn || '',
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function updateKpisAndBanner(filteredConns) {
  const snap = state.snapshot;
  if (!snap) return;

  const geo = snap.geo || {};
  const countries = new Set();
  const procs = new Set();
  for (const c of snap.conns) {
    procs.add(c.proc);
    if (c.scope === 'public' && geo[c.rip]?.country) {
      countries.add(geo[c.rip].country);
    }
  }

  $('kpiPublic').textContent = snap.stats?.public ?? 0;
  $('kpiLan').textContent = snap.stats?.lan ?? 0;
  $('kpiCountries').textContent = countries.size;
  $('kpiProcesses').textContent = procs.size;
  $('kpiListening').textContent = snap.stats?.listening ?? 0;

  $('rxRate').textContent = formatBytesPerSec(snap.nic?.rxBps || 0);
  $('txRate').textContent = formatBytesPerSec(snap.nic?.txBps || 0);
  if (snap.version) {
    $('appVersionBadge').textContent = `v${snap.version}`;
  }

  const pollMs = ((snap.pollUs || 0) / 1000).toFixed(2);
  if (!state.paused) {
    const mmdbTag = snap.mmdb ? ' · MMDB' : '';
    const modeTag = snap.elevated ? ' · Admin' : '';
    $('engineStatus').textContent = `Ao vivo · ${pollMs} ms/poll · ${snap.stats?.geoCached || 0} GeoIP${mmdbTag}${modeTag}`;
  }

  const banner = $('activeFiltersBanner');
  const activeTags = [];
  if (state.selectedCountry) activeTags.push(`País: ${state.selectedCountry}`);
  if (state.selectedProcess) activeTags.push(`App: ${state.selectedProcess}`);

  if (activeTags.length > 0) {
    banner.innerHTML = `<span>Filtro: <strong>${escHtml(activeTags.join(' · '))}</strong> (${filteredConns.length})</span><button id="clearActiveFiltersBtn">Limpar</button>`;
    banner.classList.remove('hidden');
    $('clearActiveFiltersBtn').onclick = () => {
      state.selectedCountry = null;
      state.selectedProcess = null;
      mapCanvas.selectedCountryName = null;
      applyAndRender();
    };
  } else {
    banner.classList.add('hidden');
  }
}

function renderPanel(filteredConns = getFilteredConnections()) {
  const container = $('panelList');
  const snap = state.snapshot;
  if (!snap) {
    container.innerHTML = '<div class="list-item"><div class="item-sub">Aguardando telemetria...</div></div>';
    return;
  }

  if (state.viewMode === 'global') {
    renderGlobalPanel(container, snap);
    return;
  }

  const prevScroll = container.scrollTop;
  const geo = snap.geo || {};
  const dns = snap.dns || {};

  if (state.tab === 'conns') {
    const visible = filteredConns.slice(0, 250);
    if (visible.length === 0) {
      container.innerHTML = '<div class="list-item"><div class="item-sub">Nenhuma conexão corresponde aos filtros atuais.</div></div>';
      return;
    }

    container.innerHTML = visible
      .map((c) => {
        const g = geo[c.rip];
        const host = dns[c.rip];
        const destLabel = host ? `${host} (${c.rip})` : c.rip;
        const geoLabel =
          c.scope === 'public'
            ? g
              ? `${g.city ? g.city + ', ' : ''}${g.country} · ${g.isp || g.org || ''}`
              : 'Resolvendo GeoIP...'
            : c.scope === 'loopback'
            ? 'Loopback Local'
            : 'Rede Local (LAN)';
        const sel = state.selectedConnKey === c.k ? 'selected' : '';
        return `
          <div class="list-item ${sel}" data-conn-key="${escHtml(c.k)}">
            <div class="item-top">
              <span class="item-proc">${escHtml(c.proc)} <span style="color:var(--text-muted);font-weight:400">#${c.pid}</span></span>
              <span class="state-pill ${stateBadgeClass(c)}">${escHtml(c.state)}</span>
            </div>
            <div class="item-sub">
              <span class="mono-cut">${escHtml(destLabel)}:${c.rport}</span>
              <span>:${c.lport} · ${formatAge(c.ageMs)}</span>
            </div>
            <div class="item-geo">${escHtml(geoLabel)}</div>
          </div>
        `;
      })
      .join('');

    container.querySelectorAll('[data-conn-key]').forEach((el) => {
      el.addEventListener('click', () => {
        const key = el.getAttribute('data-conn-key');
        const conn = snap.conns.find((x) => x.k === key);
        if (!conn) return;
        state.selectedConnKey = key;
        openConnectionInspector(conn);
        const g = geo[conn.rip];
        if (g) {
          mapCanvas.selectedNodeKey = `${g.lat.toFixed(2)},${g.lon.toFixed(2)}`;
          mapCanvas.flyTo(g.lon, g.lat, 2.5);
        }
        renderPanel(filteredConns);
      });
    });
  } else if (state.tab === 'bw') {
    const procs = (snap.procs || []).filter((p) => {
      const q = state.search.trim().toLowerCase();
      return !q || p.proc.toLowerCase().includes(q) || String(p.pid).includes(q);
    });
    const maxAct = Math.max(1024, ...procs.map((p) => p.actBps || 0));
    const isExact = snap.bwMode === 'exact_estats';

    const bannerHtml = `
      <div class="bw-banner">
        <span>${isExact ? 'Modo: <strong>Banda Exata (EStats)</strong>' : 'Modo: <strong>I/O por Processo</strong>'}</span>
        ${isExact ? '' : '<button class="ctrl-btn" id="btnElevateMode" style="height:24px;font-size:10.5px;padding:0 8px">Ativar Exato (Admin)</button>'}
      </div>
    `;

    container.innerHTML =
      bannerHtml +
      procs
        .map((p) => {
          const pct = Math.min(100, Math.round(((p.actBps || 0) / maxAct) * 100));
          const sel = state.selectedProcess === p.proc ? 'selected' : '';
          const rateTxt = isExact
            ? `↓${formatBytesPerSec(p.rxBps)} ↑${formatBytesPerSec(p.txBps)}`
            : formatBytesPerSec(p.actBps);
          return `
            <div class="list-item ${sel}" data-proc="${escHtml(p.proc)}">
              <div class="item-top">
                <span class="item-proc">${escHtml(p.proc)} <span style="color:var(--text-muted);font-weight:400">#${p.pid}</span></span>
                <span class="state-pill">${escHtml(rateTxt)}</span>
              </div>
              <div class="item-sub">
                <span>${p.conns} conex. (${p.pub} públicas)</span>
                <span>${pct}% rel.</span>
              </div>
              <div class="bw-bar-track"><div class="bw-bar-fill" style="width:${pct}%"></div></div>
            </div>
          `;
        })
        .join('');

    const elevBtn = $('btnElevateMode');
    if (elevBtn) {
      elevBtn.onclick = async () => {
        if (!confirm('Reiniciar NetPulse 2D como Administrador para habilitar leitura exata de bytes/s por socket (TcpConnectionEstatsData)?')) return;
        try {
          await fetch('/api/elevate', { method: 'POST' });
        } catch {}
      };
    }

    container.querySelectorAll('[data-proc]').forEach((el) => {
      el.addEventListener('click', () => {
        const proc = el.getAttribute('data-proc');
        state.selectedProcess = state.selectedProcess === proc ? null : proc;
        state.tab = 'conns';
        syncTabButtons();
        applyAndRender();
      });
    });
  } else if (state.tab === 'history') {
    renderHistoryPanel(container);
    return;
  } else if (state.tab === 'countries') {
    const groups = new Map();
    for (const c of filteredConns) {
      if (c.scope !== 'public') continue;
      const g = geo[c.rip];
      if (!g || !g.country) continue;
      let grp = groups.get(g.country);
      if (!grp) {
        grp = { country: g.country, cc: g.cc, count: 0, ips: new Set(), lat: g.lat, lon: g.lon };
        groups.set(g.country, grp);
      }
      grp.count++;
      grp.ips.add(c.rip);
    }
    const sorted = Array.from(groups.values()).sort((a, b) => b.count - a.count);
    container.innerHTML =
      sorted.length === 0
        ? '<div class="list-item"><div class="item-sub">Nenhum país resolvido ainda.</div></div>'
        : sorted
            .map((g) => {
              const sel = state.selectedCountry === g.country ? 'selected' : '';
              return `
                <div class="list-item ${sel}" data-country="${escHtml(g.country)}" data-lat="${g.lat}" data-lon="${g.lon}">
                  <div class="item-top">
                    <span class="item-proc">${escHtml(g.country)} (${escHtml(g.cc)})</span>
                    <span class="state-pill">${g.count}</span>
                  </div>
                  <div class="item-sub">
                    <span>${g.ips.size} IPs únicos</span>
                    <span>${g.lat.toFixed(1)}°, ${g.lon.toFixed(1)}°</span>
                  </div>
                </div>
              `;
            })
            .join('');

    container.querySelectorAll('[data-country]').forEach((el) => {
      el.addEventListener('click', () => {
        const country = el.getAttribute('data-country');
        const lat = parseFloat(el.getAttribute('data-lat'));
        const lon = parseFloat(el.getAttribute('data-lon'));
        state.selectedCountry = state.selectedCountry === country ? null : country;
        mapCanvas.selectedCountryName = state.selectedCountry;
        if (state.selectedCountry && !Number.isNaN(lat) && !Number.isNaN(lon)) {
          mapCanvas.flyTo(lon, lat, 2.2);
          openCountryInspector(country);
        }
        applyAndRender();
      });
    });
  }

  container.scrollTop = prevScroll;
}

function serviceStatusMeta(st) {
  if (st === 'up') return { label: 'ONLINE', cls: 'new' };
  if (st === 'degraded') return { label: 'LENTO', cls: 'syn' };
  if (st === 'down') return { label: 'OFFLINE', cls: 'closed' };
  return { label: 'TESTANDO', cls: '' };
}

function renderGlobalPanel(container, snap) {
  const prevScroll = container.scrollTop;
  const services = snap.services || [];
  const q = state.search.trim().toLowerCase();

  const matches = services.filter((s) => {
    if (state.globalTab === 'continents' && s.category !== 'continent') return false;
    if (state.globalTab === 'services' && s.category === 'continent') return false;
    if (!q) return true;
    return [s.name, s.host, s.continent, s.region, s.ip, s.status].join(' ').toLowerCase().includes(q);
  });

  if (matches.length === 0) {
    container.innerHTML = '<div class="list-item"><div class="item-sub">Nenhum serviço ou continente encontrado.</div></div>';
    return;
  }

  container.innerHTML = matches
    .map((s) => {
      const meta = serviceStatusMeta(s.status);
      const rtt =
        s.status === 'down'
          ? s.err || 'Falha'
          : s.checksTotal > 0
          ? `${s.latencyMs.toFixed(1)} ms`
          : '...';
      const localConns =
        s.category === 'continent' ? mapCanvas.continentTraffic.get(s.continent) || 0 : null;
      const sel = state.selectedServiceId === s.id ? 'selected' : '';
      return `
        <div class="list-item ${sel}" data-svc-id="${escHtml(s.id)}">
          <div class="item-top">
            <span class="item-proc">${escHtml(s.name)}</span>
            <div>
              <span class="state-pill ${meta.cls}">${meta.label} · ${escHtml(rtt)}</span>
              ${s.custom ? `<button class="svc-del-btn" data-del-svc="${escHtml(s.id)}" title="Remover">✕</button>` : ''}
            </div>
          </div>
          <div class="item-sub">
            <span class="mono-cut">${escHtml(s.host)}:${s.port}${s.ip ? ' · ' + escHtml(s.ip) : ''}</span>
            <span>${s.uptimePct}% up</span>
          </div>
          <div class="item-geo">
            ${
              localConns !== null
                ? `Suas conexões neste continente: ${localConns} · Média: ${s.avgLatencyMs.toFixed(1)} ms`
                : `${escHtml(s.region)} (${escHtml(s.continent)}) · Média: ${s.avgLatencyMs.toFixed(1)} ms`
            }
          </div>
        </div>
      `;
    })
    .join('');

  container.querySelectorAll('[data-svc-id]').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (e.target && e.target.hasAttribute('data-del-svc')) return;
      const id = el.getAttribute('data-svc-id');
      const svc = services.find((x) => x.id === id);
      if (!svc) return;
      state.selectedServiceId = id;
      mapCanvas.selectedServiceId = id;
      mapCanvas.flyTo(svc.lon, svc.lat, 2.2);
      openServiceInspector(svc);
      renderPanel();
    });
  });

  container.querySelectorAll('[data-del-svc]').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-del-svc');
      try {
        await fetch('/api/services/remove', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id }),
        });
        const resp = await fetch('/api/services');
        if (resp.ok && state.snapshot) {
          state.snapshot.services = await resp.json();
          applyAndRender();
        }
      } catch {}
    });
  });

  container.scrollTop = prevScroll;
}

let lastHistoryFetchMs = 0;

async function renderHistoryPanel(container) {
  const now = Date.now();
  if (now - lastHistoryFetchMs < 2000 && container.dataset.hasHistory === '1') return;
  lastHistoryFetchMs = now;

  try {
    const resp = await fetch('/api/history/events');
    if (!resp.ok) return;
    const data = await resp.json();
    const events = data.events || [];
    const alertsOn = !!data.alertsEnabled;

    const headerHtml = `
      <div class="bw-banner">
        <span>Notificações na Bandeja</span>
        <button class="ctrl-btn ${alertsOn ? 'active' : ''}" id="btnToggleTrayAlerts" style="height:24px;font-size:10.5px;padding:0 8px">
          ${alertsOn ? 'Ativadas' : 'Silenciadas'}
        </button>
      </div>
    `;

    const listHtml =
      events.length === 0
        ? '<div class="list-item"><div class="item-sub">Nenhum alerta ou evento registrado ainda.</div></div>'
        : events
            .map((e) => {
              const cls = e.sev === 'critical' ? 'closed' : e.sev === 'warn' ? 'syn' : 'new';
              const dt = new Date(e.ts).toLocaleTimeString('pt-BR');
              return `
                <div class="list-item">
                  <div class="item-top">
                    <span class="item-proc">${escHtml(e.title)}</span>
                    <span class="state-pill ${cls}">${escHtml(dt)}</span>
                  </div>
                  <div class="item-geo">${escHtml(e.detail)}</div>
                </div>
              `;
            })
            .join('');

    container.innerHTML = headerHtml + listHtml;
    container.dataset.hasHistory = '1';

    const tbtn = $('btnToggleTrayAlerts');
    if (tbtn) {
      tbtn.onclick = async () => {
        await fetch('/api/alerts/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: !alertsOn }),
        });
        lastHistoryFetchMs = 0;
        renderHistoryPanel(container);
      };
    }
  } catch {}
}

function drawServiceSparkline(canvas, points) {
  if (!canvas || !points || points.length < 2) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const maxMs = Math.max(50, ...points.map((p) => p.ms || 0));
  ctx.beginPath();
  for (let i = 0; i < points.length; i++) {
    const x = (i / (points.length - 1)) * (w - 8) + 4;
    const y = h - 6 - ((points[i].ms || 0) / maxMs) * (h - 12);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = '#22d3ee';
  ctx.lineWidth = 1.8;
  ctx.stroke();

  for (let i = 0; i < points.length; i++) {
    if (points[i].status === 'down') {
      const x = (i / (points.length - 1)) * (w - 8) + 4;
      ctx.fillStyle = '#f43f5e';
      ctx.fillRect(x - 1.5, 4, 3, h - 8);
    }
  }
}

let tracePollTimer = null;

async function startVisualTraceroute(targetIp, hostDiv) {
  if (tracePollTimer) {
    clearInterval(tracePollTimer);
    tracePollTimer = null;
  }
  hostDiv.innerHTML = `<div class="item-sub">Rastreando saltos ICMP para ${escHtml(targetIp)}...</div>`;
  try {
    await fetch('/api/trace/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: targetIp }),
    });
  } catch {
    hostDiv.innerHTML = `<div class="item-sub">Erro ao iniciar traceroute.</div>`;
    return;
  }

  const poll = async () => {
    try {
      const resp = await fetch('/api/trace/status');
      if (!resp.ok) return;
      const tr = await resp.json();
      const hops = tr.hops || [];

      const geoHops = [];
      for (const h of hops) {
        if (h.geo && typeof h.geo.lat === 'number' && typeof h.geo.lon === 'number') {
          geoHops.push({
            ttl: h.ttl,
            ip: h.ip,
            rttMs: h.rttMs,
            lat: h.geo.lat,
            lon: h.geo.lon,
            label: h.geo.city || h.geo.country || h.ip,
          });
        }
      }
      mapCanvas.setTraceRoute(tr.targetIp, geoHops);

      hostDiv.innerHTML = `
        <div class="insp-section-title" style="display:flex;justify-content:space-between;align-items:center">
          <span>Rota ICMP (${tr.running ? 'rastreando...' : 'concluído'})</span>
          <button class="svc-del-btn" id="btnClearTrace">Limpar</button>
        </div>
        <div>
          ${hops
            .map((h) => {
              const place = h.geo ? `${h.geo.city ? h.geo.city + ', ' : ''}${h.geo.cc}` : h.host || '';
              return `
                <div class="hop-row">
                  <span class="hop-ttl">#${h.ttl}</span>
                  <div>
                    <div>${h.timedOut ? '* * *' : escHtml(h.ip)}</div>
                    ${place ? `<div class="hop-geo">${escHtml(place)}</div>` : ''}
                  </div>
                  <span class="hop-rtt">${h.timedOut ? '—' : h.rttMs.toFixed(0) + ' ms'}</span>
                </div>`;
            })
            .join('')}
        </div>
      `;
      const clr = $('btnClearTrace');
      if (clr) {
        clr.onclick = () => {
          mapCanvas.clearTraceRoute();
          hostDiv.innerHTML = '';
        };
      }

      if (!tr.running && tracePollTimer) {
        clearInterval(tracePollTimer);
        tracePollTimer = null;
      }
    } catch {}
  };

  poll();
  tracePollTimer = setInterval(poll, 450);
}

function openServiceInspector(s) {
  const meta = serviceStatusMeta(s.status);
  const localConns =
    s.category === 'continent' ? mapCanvas.continentTraffic.get(s.continent) || 0 : null;

  document.body.classList.add('right-open');
  $('inspectorPanel').classList.remove('hidden');
  $('inspEyebrow').textContent =
    s.category === 'continent' ? `HUB CONTINENTAL · ${s.continent}` : `SERVIÇO MONITORADO · ${s.continent}`;
  $('inspTitle').textContent = s.name;

  $('inspBody').innerHTML = `
    <div class="kv-grid">
      <div class="kv-k">Status</div><div class="kv-v">${meta.label}</div>
      <div class="kv-k">Endpoint</div><div class="kv-v">${escHtml(s.host)}:${s.port}</div>
      <div class="kv-k">IP Resolvido</div><div class="kv-v">${escHtml(s.ip || '—')}</div>
      <div class="kv-k">Latência Atual</div><div class="kv-v">${s.checksTotal > 0 && s.status !== 'down' ? s.latencyMs.toFixed(1) + ' ms' : escHtml(s.err || '—')}</div>
      <div class="kv-k">Média RTT</div><div class="kv-v">${s.avgLatencyMs.toFixed(1)} ms</div>
      <div class="kv-k">Disponibilidade</div><div class="kv-v">${s.uptimePct}% (${s.checksTotal} testes)</div>
      <div class="kv-k">Localidade</div><div class="kv-v">${escHtml(s.region)} (${s.lat.toFixed(2)}, ${s.lon.toFixed(2)})</div>
      ${localConns !== null ? `<div class="kv-k">Suas Conexões</div><div class="kv-v">${localConns} ativas neste continente</div>` : ''}
    </div>
    <div class="insp-section-title">Histórico de Latência (RTT)</div>
    <canvas id="svcSparkCanvas" class="svc-spark" width="308" height="56"></canvas>
    ${s.ip ? `<div class="insp-actions"><button class="action-btn" id="btnTraceSvc">🧭 Rastrear Rota</button></div><div id="inspTraceBox"></div>` : ''}
  `;

  fetch('/api/history/service', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: s.id }),
  })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (d && d.points) drawServiceSparkline($('svcSparkCanvas'), d.points);
    })
    .catch(() => {});

  const traceBtn = $('btnTraceSvc');
  if (traceBtn && s.ip) {
    traceBtn.onclick = () => startVisualTraceroute(s.ip, $('inspTraceBox'));
  }
}

function openConnectionInspector(c) {
  const snap = state.snapshot;
  const g = snap?.geo?.[c.rip];
  const host = snap?.dns?.[c.rip];

  document.body.classList.add('right-open');
  $('inspectorPanel').classList.remove('hidden');
  $('inspEyebrow').textContent = `${c.protocol} IPv${c.v} · ${c.state}`;
  $('inspTitle').textContent = c.proc;

  const hasBw = (c.rxBps || 0) > 0 || (c.txBps || 0) > 0;

  $('inspBody').innerHTML = `
    <div class="kv-grid">
      <div class="kv-k">Processo</div><div class="kv-v">${escHtml(c.proc)} (PID ${c.pid})</div>
      <div class="kv-k">Executável</div><div class="kv-v">${escHtml(c.path || 'Sistema / Protegido')}</div>
      <div class="kv-k">Local</div><div class="kv-v">${escHtml(c.lip)}:${c.lport}</div>
      <div class="kv-k">Remoto</div><div class="kv-v">${escHtml(c.rip)}:${c.rport}</div>
      <div class="kv-k">Hostname (PTR)</div><div class="kv-v">${escHtml(host || '—')}</div>
      <div class="kv-k">Escopo</div><div class="kv-v">${escHtml(c.scope.toUpperCase())}</div>
      <div class="kv-k">Duração</div><div class="kv-v">${formatAge(c.ageMs)}</div>
      ${hasBw ? `<div class="kv-k">Tráfego</div><div class="kv-v">↓ ${formatBytesPerSec(c.rxBps)} · ↑ ${formatBytesPerSec(c.txBps)}</div>` : ''}
    </div>
    <div class="insp-actions">
      ${c.scope === 'public' ? '<button class="action-btn" id="btnTraceConn">🧭 Rastrear Rota</button>' : ''}
      ${c.scope === 'public' ? '<button class="action-btn danger" id="btnBlockIp">🛡 Bloquear IP</button>' : ''}
      ${c.pid > 4 ? '<button class="action-btn danger" id="btnKillProc">⏹ Encerrar PID</button>' : ''}
    </div>
    <div id="actionFeedback" class="item-geo hidden"></div>
    <div id="inspTraceBox"></div>
    ${
      g
        ? `
      <div class="insp-section-title">Geolocalização & Rede</div>
      <div class="kv-grid">
        <div class="kv-k">Localidade</div><div class="kv-v">${escHtml([g.city, g.region, g.country].filter(Boolean).join(', '))} (${escHtml(g.cc)})</div>
        <div class="kv-k">Coordenadas</div><div class="kv-v">${g.lat.toFixed(4)}, ${g.lon.toFixed(4)}</div>
        <div class="kv-k">ISP</div><div class="kv-v">${escHtml(g.isp || '—')}</div>
        <div class="kv-k">Organização</div><div class="kv-v">${escHtml(g.org || '—')}</div>
        <div class="kv-k">ASN</div><div class="kv-v">${escHtml(g.asn || '—')}</div>
      </div>`
        : ''
    }
  `;

  if ($('btnTraceConn')) {
    $('btnTraceConn').onclick = () => startVisualTraceroute(c.rip, $('inspTraceBox'));
  }
  if ($('btnBlockIp')) {
    $('btnBlockIp').onclick = async () => {
      if (!confirm(`Criar regra de bloqueio de saída no Firewall do Windows para ${c.rip}?`)) return;
      const fb = $('actionFeedback');
      fb.classList.remove('hidden');
      fb.textContent = 'Aplicando regra no Firewall...';
      try {
        const r = await fetch('/api/action/block-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: c.rip }),
        });
        const j = await r.json();
        fb.textContent = j.ok ? `IP ${c.rip} bloqueado no Firewall.` : `Erro: ${j.error}`;
      } catch {
        fb.textContent = 'Falha ao comunicar com o motor.';
      }
    };
  }
  if ($('btnKillProc')) {
    $('btnKillProc').onclick = async () => {
      if (!confirm(`Encerrar o processo ${c.proc} (PID ${c.pid})?`)) return;
      const fb = $('actionFeedback');
      fb.classList.remove('hidden');
      try {
        const r = await fetch('/api/action/kill-process', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pid: c.pid, proc: c.proc }),
        });
        const j = await r.json();
        fb.textContent = j.ok ? `Processo ${c.proc} (#${c.pid}) encerrado.` : `Erro: ${j.error}`;
      } catch {
        fb.textContent = 'Falha ao encerrar processo.';
      }
    };
  }
}

function openNodeInspector(node) {
  const snap = state.snapshot;
  const dns = snap?.dns || {};

  document.body.classList.add('right-open');
  $('inspectorPanel').classList.remove('hidden');
  $('inspEyebrow').textContent = `NÓ GEOGRÁFICO · ${node.conns.length} CONEXÕES`;
  $('inspTitle').textContent = [node.city, node.country].filter(Boolean).join(', ') || node.country;

  const connsHtml = node.conns
    .slice(0, 40)
    .map((c) => {
      const host = dns[c.rip];
      return `
        <div class="list-item" data-insp-conn="${escHtml(c.k)}">
          <div class="item-top">
            <span class="item-proc">${escHtml(c.proc)} (#${c.pid})</span>
            <span class="state-pill ${stateBadgeClass(c)}">${escHtml(c.state)}</span>
          </div>
          <div class="item-sub">
            <span class="mono-cut">${escHtml(host ? `${host} · ${c.rip}` : c.rip)}:${c.rport}</span>
            <span>:${c.lport}</span>
          </div>
        </div>
      `;
    })
    .join('');

  const firstIp = node.conns[0]?.rip;

  $('inspBody').innerHTML = `
    <div class="kv-grid">
      <div class="kv-k">País / Região</div><div class="kv-v">${escHtml([node.region, node.country].filter(Boolean).join(', '))} (${escHtml(node.cc)})</div>
      <div class="kv-k">Coordenadas</div><div class="kv-v">${node.lat.toFixed(4)}, ${node.lon.toFixed(4)}</div>
      <div class="kv-k">ISP / Org</div><div class="kv-v">${escHtml(node.isp || node.org || '—')}</div>
      <div class="kv-k">ASN</div><div class="kv-v">${escHtml(node.asn || '—')}</div>
    </div>
    ${firstIp ? `<div class="insp-actions"><button class="action-btn" id="btnTraceNode">🧭 Rastrear Rota (${escHtml(firstIp)})</button></div><div id="inspTraceBox"></div>` : ''}
    <div class="insp-section-title">Sockets neste Nó</div>
    <div>${connsHtml}</div>
  `;

  if ($('btnTraceNode') && firstIp) {
    $('btnTraceNode').onclick = () => startVisualTraceroute(firstIp, $('inspTraceBox'));
  }

  $('inspBody')
    .querySelectorAll('[data-insp-conn]')
    .forEach((el) => {
      el.addEventListener('click', () => {
        const k = el.getAttribute('data-insp-conn');
        const c = snap?.conns.find((x) => x.k === k);
        if (c) openConnectionInspector(c);
      });
    });
}

function openCountryInspector(countryName) {
  const snap = state.snapshot;
  if (!snap) return;
  const geo = snap.geo || {};
  const matching = snap.conns.filter(
    (c) => geo[c.rip]?.country?.toLowerCase() === countryName.toLowerCase()
  );

  document.body.classList.add('right-open');
  $('inspectorPanel').classList.remove('hidden');
  $('inspEyebrow').textContent = 'FILTRO POR PAÍS';
  $('inspTitle').textContent = countryName;

  const procs = new Set(matching.map((c) => c.proc));
  const ips = new Set(matching.map((c) => c.rip));

  $('inspBody').innerHTML = `
    <div class="kv-grid">
      <div class="kv-k">Conexões</div><div class="kv-v">${matching.length}</div>
      <div class="kv-k">IPs Únicos</div><div class="kv-v">${ips.size}</div>
      <div class="kv-k">Aplicações</div><div class="kv-v">${procs.size}</div>
    </div>
    <div class="insp-section-title">Top Conexões em ${escHtml(countryName)}</div>
    <div>
      ${matching
        .slice(0, 30)
        .map(
          (c) => `
          <div class="list-item" data-country-conn="${escHtml(c.k)}">
            <div class="item-top">
              <span class="item-proc">${escHtml(c.proc)}</span>
              <span class="state-pill ${stateBadgeClass(c)}">${escHtml(c.state)}</span>
            </div>
            <div class="item-sub">
              <span class="mono-cut">${escHtml(c.rip)}:${c.rport}</span>
              <span>${escHtml(geo[c.rip]?.city || '')}</span>
            </div>
          </div>`
        )
        .join('')}
    </div>
  `;

  $('inspBody')
    .querySelectorAll('[data-country-conn]')
    .forEach((el) => {
      el.addEventListener('click', () => {
        const k = el.getAttribute('data-country-conn');
        const c = snap.conns.find((x) => x.k === k);
        if (c) openConnectionInspector(c);
      });
    });
}

function closeInspector() {
  document.body.classList.remove('right-open');
  $('inspectorPanel').classList.add('hidden');
}

function applyAndRender() {
  if (!state.snapshot) return;
  const filtered = getFilteredConnections();
  updateKpisAndBanner(filtered);
  mapCanvas.updateTelemetry({
    host: state.snapshot.host,
    geo: state.snapshot.geo || {},
    filteredConns: filtered,
    allConns: state.snapshot.conns || [],
    services: state.snapshot.services || [],
  });
  renderPanel(filtered);
}

function syncTabButtons() {
  document.querySelectorAll('.tab-btn[data-tab]').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === state.tab);
  });
}

function connectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    $('connDot').className = state.paused ? 'brand-pulse paused' : 'brand-pulse online';
    const interval = $('intervalSelect').value;
    ws.send(`interval:${interval}`);
  };

  ws.onmessage = (ev) => {
    if (state.paused) return;
    try {
      const data = JSON.parse(ev.data);
      if (!state.initialVersion && data.version) {
        state.initialVersion = data.version;
      } else if (state.initialVersion && data.version && data.version !== state.initialVersion) {
        window.location.reload();
        return;
      }
      state.snapshot = data;
      state.rxHistory.push(data.nic?.rxBps || 0);
      state.rxHistory.shift();
      state.txHistory.push(data.nic?.txBps || 0);
      state.txHistory.shift();
      drawSparkline();
      applyAndRender();
    } catch {
      // ignore malformed packet
    }
  };

  ws.onclose = () => {
    $('connDot').className = 'brand-pulse offline';
    $('engineStatus').textContent = 'Desconectado — reconectando...';
    reconnectTimer = setTimeout(connectWebSocket, 1200);
  };

  ws.onerror = () => {
    ws.close();
  };
}

async function init() {
  // Load bundled offline Natural Earth 110m world vector map
  try {
    const resp = await fetch('/assets/countries-110m.json');
    const topo = await resp.json();
    const features = decodeTopoJson(topo, 'countries');
    mapCanvas.setFeatures(features);
    mapCanvas.start();
  } catch (err) {
    $('engineStatus').textContent = `Erro ao carregar mapa: ${err.message}`;
  }

  // UI Event Bindings
  $('projectionSelect').addEventListener('change', (e) => {
    mapCanvas.setProjection(e.target.value);
  });

  $('btnTerminator').addEventListener('click', (e) => {
    mapCanvas.showTerminator = !mapCanvas.showTerminator;
    e.currentTarget.classList.toggle('active', mapCanvas.showTerminator);
  });

  $('btnArcs').addEventListener('click', (e) => {
    mapCanvas.showArcs = !mapCanvas.showArcs;
    e.currentTarget.classList.toggle('active', mapCanvas.showArcs);
  });

  $('btnLan').addEventListener('click', (e) => {
    mapCanvas.showLan = !mapCanvas.showLan;
    e.currentTarget.classList.toggle('active', mapCanvas.showLan);
    applyAndRender();
  });

  $('btnLabels').addEventListener('click', (e) => {
    mapCanvas.showLabels = !mapCanvas.showLabels;
    e.currentTarget.classList.toggle('active', mapCanvas.showLabels);
  });

  $('intervalSelect').addEventListener('change', (e) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(`interval:${e.target.value}`);
    }
  });

  const togglePause = () => {
    state.paused = !state.paused;
    const btn = $('btnPause');
    btn.textContent = state.paused ? 'Retomar' : 'Pausar';
    btn.classList.toggle('paused', state.paused);
    $('connDot').className = state.paused ? 'brand-pulse paused' : 'brand-pulse online';
    if (state.paused) {
      $('engineStatus').textContent = 'Stream pausado (inspecionando)';
    }
  };
  $('btnPause').addEventListener('click', togglePause);

  $('btnReset').addEventListener('click', () => mapCanvas.fitPlanet());
  $('btnZoomFit').addEventListener('click', () => mapCanvas.fitPlanet());
  $('btnZoomIn').addEventListener('click', () => mapCanvas.zoomBy(1.35));
  $('btnZoomOut').addEventListener('click', () => mapCanvas.zoomBy(1 / 1.35));

  $('toggleLeftBtn').addEventListener('click', () => {
    const open = document.body.classList.toggle('left-open');
    $('toggleLeftBtn').textContent = open ? '◀' : '▶';
    mapCanvas.fitPlanet();
  });

  $('closeInspectorBtn').addEventListener('click', () => {
    state.selectedNodeKey = null;
    state.selectedConnKey = null;
    closeInspector();
  });

  document.querySelectorAll('.tab-btn[data-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.tab = btn.getAttribute('data-tab');
      syncTabButtons();
      renderPanel();
    });
  });

  document.querySelectorAll('.tab-btn[data-gtab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.globalTab = btn.getAttribute('data-gtab');
      document.querySelectorAll('.tab-btn[data-gtab]').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-gtab') === state.globalTab);
      });
      renderPanel();
    });
  });

  document.querySelectorAll('.view-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.getAttribute('data-view');
      state.viewMode = mode;
      document.querySelectorAll('.view-btn').forEach((b) => b.classList.toggle('active', b === btn));
      const isGlobal = mode === 'global';
      $('localTabs').classList.toggle('hidden', isGlobal);
      $('localFilterChips').classList.toggle('hidden', isGlobal);
      $('globalTabs').classList.toggle('hidden', !isGlobal);
      $('globalActions').classList.toggle('hidden', !isGlobal);
      if (!isGlobal) $('addServiceForm').classList.add('hidden');
      closeInspector();
      mapCanvas.setViewMode(mode);
      applyAndRender();
    });
  });

  $('btnProbeServices').addEventListener('click', async () => {
    try {
      await fetch('/api/services/probe', { method: 'POST' });
      setTimeout(async () => {
        const resp = await fetch('/api/services');
        if (resp.ok && state.snapshot) {
          state.snapshot.services = await resp.json();
          applyAndRender();
        }
      }, 900);
    } catch {}
  });

  $('btnToggleAddService').addEventListener('click', () => {
    $('addServiceForm').classList.toggle('hidden');
  });

  const CONTINENT_COORDS = {
    SA: [-23.5505, -46.6333],
    NA: [39.0438, -77.4874],
    EU: [50.1109, 8.6821],
    AF: [-33.9249, 18.4241],
    AS: [35.6762, 139.6503],
    OC: [-33.8688, 151.2093],
    GLOBAL: [20.0, 0.0],
  };

  $('addServiceForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const cont = $('svcContinent').value;
    const [lat, lon] = CONTINENT_COORDS[cont] || [0, 0];
    const payload = {
      name: $('svcName').value.trim(),
      host: $('svcHost').value.trim(),
      port: parseInt($('svcPort').value, 10) || 443,
      continent: cont,
      lat,
      lon,
    };
    try {
      const resp = await fetch('/api/services/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (resp.ok) {
        $('svcName').value = '';
        $('svcHost').value = '';
        $('addServiceForm').classList.add('hidden');
        if (state.snapshot) {
          state.snapshot.services = await resp.json();
          applyAndRender();
        }
      }
    } catch {}
  });

  document.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      state.filter = chip.getAttribute('data-filter');
      document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', c === chip));
      applyAndRender();
    });
  });

  $('searchInput').addEventListener('input', (e) => {
    state.search = e.target.value;
    applyAndRender();
  });

  // Keyboard shortcuts
  window.addEventListener('keydown', (e) => {
    const inInput = document.activeElement === $('searchInput');
    if (e.key === 'Escape') {
      if (inInput) {
        $('searchInput').blur();
      } else {
        closeInspector();
        state.selectedNodeKey = null;
        state.selectedConnKey = null;
        state.selectedCountry = null;
        mapCanvas.selectedNodeKey = null;
        mapCanvas.selectedCountryName = null;
        mapCanvas.clearTraceRoute();
        applyAndRender();
      }
      return;
    }
    if (inInput) return;

    if (e.code === 'Space') {
      e.preventDefault();
      togglePause();
    } else if (e.key === 'r' || e.key === 'R') {
      mapCanvas.fitPlanet();
    } else if (e.key === 'f' || e.key === 'F') {
      e.preventDefault();
      if (!document.body.classList.contains('left-open')) {
        document.body.classList.add('left-open');
        $('toggleLeftBtn').textContent = '◀';
      }
      $('searchInput').focus();
    }
  });

  connectWebSocket();
  initUpdateMonitor();
}

let updatePollTimer = null;

function renderUpdateStatus(u) {
  if (!u) return;
  if (u.currentVersion) {
    $('appVersionBadge').textContent = `v${u.currentVersion}`;
  }

  const pill = $('updatePill');
  const txt = $('updatePillText');
  const btn = $('btnApplyUpdate');
  const notes = $('updateNotesLink');

  if (u.releaseUrl) {
    notes.href = u.releaseUrl;
    notes.classList.remove('hidden');
  } else {
    notes.classList.add('hidden');
  }

  if (u.state === 'available') {
    pill.classList.remove('hidden');
    txt.textContent = `Nova versão v${u.latestVersion}`;
    btn.textContent = 'Atualizar';
    btn.disabled = false;
    btn.classList.remove('hidden');
  } else if (u.state === 'downloading') {
    pill.classList.remove('hidden');
    txt.textContent = `Baixando v${u.latestVersion} (${u.progressPct || 0}%)...`;
    btn.classList.add('hidden');
  } else if (u.state === 'verifying') {
    pill.classList.remove('hidden');
    txt.textContent = 'Verificando SHA-256...';
    btn.classList.add('hidden');
  } else if (u.state === 'installing') {
    pill.classList.remove('hidden');
    txt.textContent = 'Instalando & reiniciando...';
    btn.classList.add('hidden');
  } else if (u.state === 'checking') {
    $('btnCheckUpdate').title = 'Verificando atualizacoes...';
  } else if (u.state === 'up_to_date') {
    pill.classList.add('hidden');
    $('btnCheckUpdate').title = `Atualizado (v${u.currentVersion})`;
  } else if (u.state === 'error') {
    $('btnCheckUpdate').title = `Erro ao verificar atualização: ${u.error || 'falha de rede'}`;
    if (u.latestVersion && u.downloadUrl) {
      pill.classList.remove('hidden');
      txt.textContent = u.error || 'Erro ao atualizar';
      btn.textContent = 'Tentar de novo';
      btn.disabled = false;
      btn.classList.remove('hidden');
    }
  }
}

async function pollUpdateStatus() {
  try {
    const resp = await fetch('/api/update/status');
    if (!resp.ok) return;
    const u = await resp.json();
    renderUpdateStatus(u);

    const active = ['checking', 'downloading', 'verifying', 'installing'].includes(u.state);
    if (active && !updatePollTimer) {
      updatePollTimer = setInterval(pollUpdateStatus, 450);
    } else if (!active && updatePollTimer) {
      clearInterval(updatePollTimer);
      updatePollTimer = null;
    }
  } catch {
    // ignore transient offline state during restart
  }
}

function initUpdateMonitor() {
  $('btnCheckUpdate').addEventListener('click', async () => {
    try {
      await fetch('/api/update/check', { method: 'POST' });
      pollUpdateStatus();
    } catch {}
  });

  $('btnApplyUpdate').addEventListener('click', async () => {
    $('btnApplyUpdate').disabled = true;
    try {
      await fetch('/api/update/apply', { method: 'POST' });
      pollUpdateStatus();
    } catch {}
  });

  setTimeout(pollUpdateStatus, 3200);
  setInterval(pollUpdateStatus, 30000);
}

init();
