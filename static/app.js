import { decodeTopoJson } from './topo.js';
import { PlanetMapCanvas } from './map-canvas.js';
import { LanTopologyCanvas } from './lan-topo.js';
import { NocDashboardController } from './noc-dashboard.js';

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
  analytics: {
    tab: 'overview',
    range: '7d',
    connOffset: 0,
    connLimit: 30,
    connTotal: 0,
  },
  quality: {
    range: '1h',
    selectedTargetId: null,
    timer: null,
  },
  trace: {
    tab: 'history',
    runs: [],
  },
  interfaces: {
    range: '1h',
    filter: 'all',
    selectedId: null,
    timer: null,
  },
  discovery: {
    filter: 'all',
    search: '',
    timer: null,
  },
  lanTopo: {
    data: null,
    timer: null,
  },
  intelligence: {
    tab: 'alerts',
    level: '',
    unackOnly: false,
    timer: null,
  },
  auth: {
    authenticated: false,
    role: 'none',
    actor: '',
    csrfToken: '',
    remoteAccess: false,
    tlsEnabled: false,
    bootstrapFileAvailable: false,
  },
};

function hasRole(required) {
  const rank = { none: -1, viewer: 0, operator: 1, administrator: 2 };
  return (rank[state.auth.role] ?? -1) >= (rank[required] ?? 99);
}

async function apiFetch(url, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = new Headers(opts.headers || {});
  if (method !== 'GET' && method !== 'HEAD' && state.auth.csrfToken) {
    headers.set('X-CSRF-Token', state.auth.csrfToken);
  }
  const resp = await fetch(url, { ...opts, method, headers, credentials: 'same-origin' });
  if (resp.status === 401 && !url.startsWith('/api/auth/')) {
    state.auth.authenticated = false;
    state.auth.role = 'none';
    updateAuthUi();
    showAuthModal();
  }
  return resp;
}

function updateAuthUi() {
  const badge = $('authRoleBadge');
  if (badge) {
    const labelMap = { administrator: 'Admin', operator: 'Operator', viewer: 'Viewer', none: 'Login' };
    badge.textContent = labelMap[state.auth.role] || 'Login';
  }
  const isOp = hasRole('operator');
  const isAdmin = hasRole('administrator');
  if ($('btnToggleAddService')) $('btnToggleAddService').classList.toggle('hidden', !isOp);
  if ($('btnProbeServices')) $('btnProbeServices').disabled = !isOp;
  if ($('btnApplyUpdate')) $('btnApplyUpdate').disabled = !isAdmin;
  if ($('btnSettings')) $('btnSettings').disabled = !state.auth.authenticated;
}

function showAuthModal(errText = '') {
  const modal = $('authModal');
  if (!modal) return;
  $('authBootstrapHint').classList.toggle('hidden', !state.auth.bootstrapFileAvailable);
  const fb = $('authFeedback');
  if (errText) {
    fb.textContent = errText;
    fb.classList.remove('hidden');
  } else {
    fb.classList.add('hidden');
  }
  modal.classList.remove('hidden');
  setTimeout(() => $('authTokenInput')?.focus(), 50);
}

function hideAuthModal() {
  $('authModal')?.classList.add('hidden');
}

async function ensureAuthenticated() {
  const params = new URLSearchParams(window.location.search);
  const boot = params.get('boot');
  if (boot) {
    try {
      const resp = await fetch('/api/auth/exchange', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ nonce: boot }),
      });
      if (resp.ok) {
        const d = await resp.json();
        state.auth.authenticated = true;
        state.auth.role = d.role || 'administrator';
        state.auth.actor = d.actor || 'local-desktop';
        state.auth.csrfToken = d.csrfToken || '';
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
        updateAuthUi();
        return true;
      }
    } catch {}
  }

  try {
    const resp = await fetch('/api/auth/session', { credentials: 'same-origin' });
    if (resp.ok) {
      const s = await resp.json();
      state.auth = { ...state.auth, ...s };
      updateAuthUi();
      if (s.authenticated) return true;
    }
  } catch {}

  updateAuthUi();
  showAuthModal();
  return false;
}

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
        ${isExact || !hasRole('administrator') ? '' : '<button class="ctrl-btn" id="btnElevateMode" style="height:24px;font-size:10.5px;padding:0 8px">Ativar Exato (Admin)</button>'}
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
          await apiFetch('/api/elevate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirm: true }),
          });
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
        await apiFetch('/api/services/remove', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id }),
        });
        const resp = await apiFetch('/api/services');
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
    const resp = await apiFetch('/api/history/events');
    if (!resp.ok) return;
    const data = await resp.json();
    const events = data.events || [];
    const alertsOn = !!data.alertsEnabled;

    const headerHtml = `
      <div class="bw-banner">
        <span>Notificações na Bandeja</span>
        <div style="display:flex;gap:5px">
          <button class="ctrl-btn" id="btnAlertCats" style="height:24px;font-size:10.5px;padding:0 8px">⚙ Categorias</button>
          <button class="ctrl-btn ${alertsOn ? 'active' : ''}" id="btnToggleTrayAlerts" style="height:24px;font-size:10.5px;padding:0 8px">
            ${alertsOn ? 'Ativadas' : 'Silenciadas'}
          </button>
        </div>
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

    const cbtn = $('btnAlertCats');
    if (cbtn) cbtn.onclick = openSettingsModal;

    const tbtn = $('btnToggleTrayAlerts');
    if (tbtn) {
      tbtn.onclick = async () => {
        await apiFetch('/api/alerts/toggle', {
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
    const r = await apiFetch('/api/trace/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: targetIp }),
    });
    if (!r.ok) {
      hostDiv.innerHTML = `<div class="item-sub">Sem permissão ou erro ao iniciar traceroute.</div>`;
      return;
    }
  } catch {
    hostDiv.innerHTML = `<div class="item-sub">Erro ao iniciar traceroute.</div>`;
    return;
  }

  const poll = async () => {
    try {
      const resp = await apiFetch('/api/trace/status');
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
        <div class="insp-section-title" style="display:flex;justify-content:space-between;align-items:center;gap:4px">
          <span>Rota ICMP (${tr.running ? 'rastreando...' : 'concluído'})${tr.changedFromPrev ? ' · <strong style="color:#fbbf24">ALTERADA</strong>' : ''}</span>
          <div style="display:flex;gap:4px">
            <button class="svc-del-btn" id="btnTraceHistOpen">Histórico</button>
            <button class="svc-del-btn" id="btnClearTrace">Limpar</button>
          </div>
        </div>
        <div>
          ${hops
            .map((h) => {
              const geoTxt = h.geo ? `${h.geo.city ? h.geo.city + ', ' : ''}${h.geo.cc}${h.geo.asn ? ' · ' + h.geo.asn : ''}` : '';
              const place = [h.host, geoTxt].filter(Boolean).join(' · ');
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
      const thBtn = $('btnTraceHistOpen');
      if (thBtn) {
        thBtn.onclick = () => openTraceModal(tr.targetIp);
      }
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
    ${s.ip && hasRole('operator') ? `<div class="insp-actions"><button class="action-btn" id="btnTraceSvc">🧭 Rastrear Rota</button></div><div id="inspTraceBox"></div>` : ''}
  `;

  apiFetch('/api/history/service', {
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
      ${c.scope === 'public' && hasRole('operator') ? '<button class="action-btn" id="btnTraceConn">🧭 Rastrear Rota</button>' : ''}
      ${c.scope === 'public' && hasRole('administrator') ? '<button class="action-btn danger" id="btnBlockIp">🛡 Bloquear IP</button>' : ''}
      ${c.pid > 4 && hasRole('administrator') ? '<button class="action-btn danger" id="btnKillProc">⏹ Encerrar PID</button>' : ''}
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
        const r = await apiFetch('/api/action/block-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: c.rip, confirm: true }),
        });
        const j = await r.json();
        fb.textContent = j.ok ? `IP ${c.rip} bloqueado no Firewall.` : `Erro: ${j.message || j.error}`;
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
        const r = await apiFetch('/api/action/kill-process', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pid: c.pid, proc: c.proc, confirm: true }),
        });
        const j = await r.json();
        fb.textContent = j.ok ? `Processo ${c.proc} (#${c.pid}) encerrado.` : `Erro: ${j.message || j.error}`;
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
    ${firstIp && hasRole('operator') ? `<div class="insp-actions"><button class="action-btn" id="btnTraceNode">🧭 Rastrear Rota (${escHtml(firstIp)})</button></div><div id="inspTraceBox"></div>` : ''}
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

async function connectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (!state.auth.authenticated) return;

  let wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`;
  try {
    const tr = await apiFetch('/api/auth/ws-ticket', { method: 'POST' });
    if (tr.ok) {
      const td = await tr.json();
      if (td.ticket) wsUrl += `?ticket=${encodeURIComponent(td.ticket)}`;
    } else if (tr.status === 401) {
      return;
    }
  } catch {}

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    $('connDot').className = state.paused ? 'brand-pulse paused' : 'brand-pulse online';
    if (hasRole('operator')) {
      const interval = $('intervalSelect').value;
      ws.send(`interval:${interval}`);
    }
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

  $('btnAnimations').addEventListener('click', (e) => {
    mapCanvas.showAnimations = !mapCanvas.showAnimations;
    e.currentTarget.classList.toggle('active', mapCanvas.showAnimations);
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

  $('btnReset').addEventListener('click', () => mapCanvas.fitPlanet(true));
  $('btnZoomFit').addEventListener('click', () => mapCanvas.fitPlanet(true));
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
      switchViewMode(btn.getAttribute('data-view'));
    });
  });

  $('btnSettings').addEventListener('click', openSettingsModal);
  $('btnCloseSettings').addEventListener('click', closeSettingsModal);
  $('btnCancelSettings').addEventListener('click', closeSettingsModal);
  $('settingsModal').addEventListener('click', (e) => {
    if (e.target === $('settingsModal')) closeSettingsModal();
  });

  const catIds = [
    'cfgNotifyServiceDown',
    'cfgNotifyServiceDegraded',
    'cfgNotifySensitivePort',
    'cfgNotifyNewCountry',
  ];

  $('cfgAlertsEnabled').addEventListener('change', syncNotifyCategoryDisabledState);

  $('btnEnableAllNotif').addEventListener('click', () => {
    $('cfgAlertsEnabled').checked = true;
    catIds.forEach((id) => { $(id).checked = true; });
    syncNotifyCategoryDisabledState();
  });

  $('btnDisableAllNotif').addEventListener('click', () => {
    $('cfgAlertsEnabled').checked = false;
    catIds.forEach((id) => { $(id).checked = false; });
    syncNotifyCategoryDisabledState();
  });

  $('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fb = $('settingsFeedback');
    fb.classList.remove('hidden');
    fb.textContent = 'Salvando configurações...';
    const retDays = Math.max(1, Math.min(365, parseInt($('cfgRetentionDays').value, 10) || 30));
    const maxDbMb = Math.max(32, Math.min(2048, parseInt($('cfgMaxDbSizeMb').value, 10) || 256));
    const payload = {
      alertsEnabled: $('cfgAlertsEnabled').checked,
      notifyServiceDown: $('cfgNotifyServiceDown').checked,
      notifyServiceDegraded: $('cfgNotifyServiceDegraded').checked,
      notifySensitivePort: $('cfgNotifySensitivePort').checked,
      notifyNewCountry: $('cfgNotifyNewCountry').checked,
      autoStart: $('cfgAutoStart').checked,
      minimizeToTray: $('cfgMinimizeToTray').checked,
      defaultView: $('cfgDefaultView').value,
      retentionDays: retDays,
      maxDbSizeMb: maxDbMb,
    };
    try {
      const resp = await apiFetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) {
        fb.textContent = `Erro: ${data.message || data.error || 'falha ao salvar'}`;
        return;
      }
      fb.textContent = 'Configurações salvas!';
      lastHistoryFetchMs = 0;
      setTimeout(() => closeSettingsModal(), 450);
    } catch {
      fb.textContent = 'Erro de comunicação com o motor local.';
    }
  });

  $('btnMinimizeTray').addEventListener('click', async () => {
    try {
      await apiFetch('/api/window/minimize-tray', { method: 'POST' });
    } catch {}
  });

  $('btnProbeServices').addEventListener('click', async () => {
    try {
      await apiFetch('/api/services/probe', { method: 'POST' });
      setTimeout(async () => {
        const resp = await apiFetch('/api/services');
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
      const resp = await apiFetch('/api/services/add', {
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
    const activeTag = document.activeElement?.tagName;
    const inInput = activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT';
    if (e.key === 'Escape') {
      if ($('nocOverlay') && !$('nocOverlay').classList.contains('hidden')) {
        nocController?.close();
      } else if ($('notificationsModal') && !$('notificationsModal').classList.contains('hidden')) {
        closeNotificationsModal();
      } else if ($('moduleDockModal') && !$('moduleDockModal').classList.contains('hidden')) {
        closeModuleDock();
      } else if (!$('intelligenceModal').classList.contains('hidden')) {
        closeIntelligenceModal();
      } else if (!$('topologyModal').classList.contains('hidden')) {
        closeTopologyModal();
      } else if (!$('discoveryModal').classList.contains('hidden')) {
        closeDiscoveryModal();
      } else if (!$('interfacesModal').classList.contains('hidden')) {
        closeInterfacesModal();
      } else if (!$('traceModal').classList.contains('hidden')) {
        closeTraceModal();
      } else if (!$('qualityModal').classList.contains('hidden')) {
        closeQualityModal();
      } else if (!$('analyticsModal').classList.contains('hidden')) {
        closeAnalyticsModal();
      } else if (!$('securityModal').classList.contains('hidden')) {
        closeSecurityModal();
      } else if (!$('settingsModal').classList.contains('hidden')) {
        closeSettingsModal();
      } else if (inInput) {
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
    } else if (e.key === 'm' || e.key === 'M') {
      e.preventDefault();
      if ($('moduleDockModal')?.classList.contains('hidden')) openModuleDock();
      else closeModuleDock();
    } else if (e.key === 'n' || e.key === 'N') {
      e.preventDefault();
      if ($('nocOverlay')?.classList.contains('hidden')) nocController?.open(false);
      else nocController?.close();
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

  $('btnSecurity').addEventListener('click', () => {
    if (!state.auth.authenticated) {
      showAuthModal();
    } else {
      openSecurityModal();
    }
  });
  $('btnCloseSecurity').addEventListener('click', closeSecurityModal);
  $('securityModal').addEventListener('click', (e) => {
    if (e.target === $('securityModal')) closeSecurityModal();
  });
  $('btnRefreshAudit').addEventListener('click', loadSecurityModalData);

  $('cfgRetentionPreset').addEventListener('change', () => {
    const val = $('cfgRetentionPreset').value;
    if (val !== 'custom') {
      $('cfgRetentionDays').value = val;
    }
  });
  $('cfgRetentionDays').addEventListener('input', () => {
    const d = String(parseInt($('cfgRetentionDays').value, 10) || '');
    $('cfgRetentionPreset').value = ['1', '7', '30', '90'].includes(d) ? d : 'custom';
  });

  $('btnAnalytics').addEventListener('click', openAnalyticsModal);
  $('btnCloseAnalytics').addEventListener('click', closeAnalyticsModal);
  $('analyticsModal').addEventListener('click', (e) => {
    if (e.target === $('analyticsModal')) closeAnalyticsModal();
  });
  $('anaRangeSelect').addEventListener('change', () => {
    state.analytics.range = $('anaRangeSelect').value;
    loadActiveAnalyticsTab();
  });
  document.querySelectorAll('#anaTabs .tab-btn[data-atab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.analytics.tab = btn.getAttribute('data-atab');
      document.querySelectorAll('#anaTabs .tab-btn[data-atab]').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-atab') === state.analytics.tab);
      });
      loadActiveAnalyticsTab();
    });
  });
  $('btnHistConnApply').addEventListener('click', () => {
    state.analytics.connOffset = 0;
    loadAnalyticsConnections();
  });
  $('histConnSearch').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      state.analytics.connOffset = 0;
      loadAnalyticsConnections();
    }
  });
  $('btnHistPrev').addEventListener('click', () => {
    state.analytics.connOffset = Math.max(0, state.analytics.connOffset - state.analytics.connLimit);
    loadAnalyticsConnections();
  });
  $('btnHistNext').addEventListener('click', () => {
    if (state.analytics.connOffset + state.analytics.connLimit < state.analytics.connTotal) {
      state.analytics.connOffset += state.analytics.connLimit;
      loadAnalyticsConnections();
    }
  });
  $('btnHistProcApply').addEventListener('click', loadAnalyticsProcesses);
  $('histProcFilter').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadAnalyticsProcesses();
    }
  });

  $('btnQuality').addEventListener('click', openQualityModal);
  $('btnCloseQuality').addEventListener('click', closeQualityModal);
  $('qualityModal').addEventListener('click', (e) => {
    if (e.target === $('qualityModal')) closeQualityModal();
  });
  $('qualRangeSelect').addEventListener('change', () => {
    state.quality.range = $('qualRangeSelect').value;
    loadQualityHistory();
  });
  $('btnQualityProbe').addEventListener('click', async () => {
    await apiFetch('/api/quality/probe', { method: 'POST' });
    setTimeout(loadQualityStatus, 650);
  });
  $('btnQualityRediscover').addEventListener('click', async () => {
    const resp = await apiFetch('/api/quality/rediscover', { method: 'POST' });
    if (resp.ok) {
      await loadQualityStatus();
    }
  });
  $('qualAddTargetForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fb = $('qualFormFeedback');
    fb.classList.remove('hidden');
    fb.textContent = 'Adicionando destino...';
    const payload = {
      name: $('qTargetName').value.trim(),
      host: $('qTargetHost').value.trim(),
      probeMode: $('qTargetMode').value,
      port: parseInt($('qTargetPort').value, 10) || 0,
      intervalSec: Math.max(5, Math.min(300, parseInt($('qTargetInterval').value, 10) || 10)),
      category: 'custom',
    };
    try {
      const resp = await apiFetch('/api/quality/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        fb.textContent = `Erro: ${err.message || err.error || resp.status}`;
        return;
      }
      $('qTargetName').value = '';
      $('qTargetHost').value = '';
      fb.classList.add('hidden');
      await loadQualityStatus();
    } catch {
      fb.textContent = 'Falha ao comunicar com o motor local.';
    }
  });

  $('btnTraceModal').addEventListener('click', () => openTraceModal());
  $('btnCloseTraceModal').addEventListener('click', closeTraceModal);
  $('traceModal').addEventListener('click', (e) => {
    if (e.target === $('traceModal')) closeTraceModal();
  });
  document.querySelectorAll('#traceTabs .tab-btn[data-ttab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.trace.tab = btn.getAttribute('data-ttab');
      document.querySelectorAll('#traceTabs .tab-btn[data-ttab]').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-ttab') === state.trace.tab);
      });
      loadActiveTraceTab();
    });
  });
  $('btnTraceFilterApply').addEventListener('click', loadTraceHistory);
  $('traceFilterIp').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadTraceHistory();
    }
  });
  $('btnTraceRunTarget').addEventListener('click', async () => {
    const ip = $('traceFilterIp').value.trim();
    if (!ip) return;
    const resp = await apiFetch('/api/trace/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    if (resp.ok) {
      $('traceRunsList').innerHTML = `<div class="sec-row"><span class="sec-row-meta">Traceroute iniciado para ${escHtml(ip)}... aguarde alguns segundos e clique em Filtrar.</span></div>`;
      setTimeout(loadTraceHistory, 3500);
    }
  });
  $('btnComputeTraceDiff').addEventListener('click', computeSelectedTraceDiff);
  $('traceMonitorForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const targetIp = $('tmIpInput').value.trim();
    const label = $('tmLabelInput').value.trim();
    const intervalSec = Math.max(30, Math.min(3600, parseInt($('tmIntervalInput').value, 10) || 300));
    const resp = await apiFetch('/api/trace/monitors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetIp, label, intervalSec, enabled: true }),
    });
    if (resp.ok) {
      $('tmIpInput').value = '';
      $('tmLabelInput').value = '';
      loadTraceMonitors();
    }
  });

  $('btnInterfaces').addEventListener('click', openInterfacesModal);
  $('btnCloseInterfaces').addEventListener('click', closeInterfacesModal);
  $('interfacesModal').addEventListener('click', (e) => {
    if (e.target === $('interfacesModal')) closeInterfacesModal();
  });
  $('ifaceRangeSelect').addEventListener('change', () => {
    state.interfaces.range = $('ifaceRangeSelect').value;
    loadInterfaceHistory();
  });
  $('ifaceFilterSelect').addEventListener('change', () => {
    state.interfaces.filter = $('ifaceFilterSelect').value;
    loadInterfacesData();
  });
  $('btnIfaceRefresh').addEventListener('click', async () => {
    if (hasRole('operator')) {
      await apiFetch('/api/interfaces/refresh', { method: 'POST' });
    }
    await loadInterfacesData();
  });

  $('btnDiscovery').addEventListener('click', openDiscoveryModal);
  $('btnCloseDiscovery').addEventListener('click', closeDiscoveryModal);
  $('discoveryModal').addEventListener('click', (e) => {
    if (e.target === $('discoveryModal')) closeDiscoveryModal();
  });
  $('discSearchInput').addEventListener('input', () => {
    state.discovery.search = $('discSearchInput').value.trim().toLowerCase();
    loadDiscoveryDevices();
  });
  $('discFilterSelect').addEventListener('change', () => {
    state.discovery.filter = $('discFilterSelect').value;
    loadDiscoveryDevices();
  });
  $('btnDiscoveryRefresh').addEventListener('click', loadDiscoveryDevices);
  $('btnDiscoveryScan').addEventListener('click', async () => {
    $('btnDiscoveryScan').disabled = true;
    $('btnDiscoveryScan').textContent = '⏳ Varrendo LAN...';
    await apiFetch('/api/discovery/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    setTimeout(loadDiscoveryDevices, 900);
  });

  $('btnLanTopo').addEventListener('click', openTopologyModal);
  $('btnCloseTopoModal').addEventListener('click', closeTopologyModal);
  $('topologyModal').addEventListener('click', (e) => {
    if (e.target === $('topologyModal')) closeTopologyModal();
  });
  $('btnTopoRefresh').addEventListener('click', loadLanTopology);

  $('btnIntelligence').addEventListener('click', openIntelligenceModal);
  $('btnCloseIntelligence').addEventListener('click', closeIntelligenceModal);
  $('intelligenceModal').addEventListener('click', (e) => {
    if (e.target === $('intelligenceModal')) closeIntelligenceModal();
  });
  $('btnIntelRefresh').addEventListener('click', loadIntelligenceOverview);
  document.querySelectorAll('#intelTabs .tab-btn[data-itab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.intelligence.tab = btn.getAttribute('data-itab');
      switchIntelligenceTab();
    });
  });
  $('intelLevelFilter').addEventListener('change', () => {
    state.intelligence.level = $('intelLevelFilter').value;
    loadIntelligenceOverview();
  });
  $('intelUnackOnly').addEventListener('change', () => {
    state.intelligence.unackOnly = $('intelUnackOnly').checked;
    loadIntelligenceOverview();
  });
  $('intelRuleForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      name: $('ruleNameInput').value.trim(),
      kind: $('ruleKindInput').value,
      enabled: true,
      riskWeight: parseInt($('ruleWeightInput').value, 10) || 40,
      thresholdNum: parseFloat($('ruleThresholdInput').value) || 0,
      matchCountry: $('ruleCountryInput').value.trim().toUpperCase(),
      matchPort: parseInt($('rulePortInput').value, 10) || 0,
      matchProcess: $('ruleProcessInput').value.trim(),
      description: 'Regra configurada pelo operador/administrador via UI',
    };
    const resp = await apiFetch('/api/intelligence/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      $('ruleNameInput').value = '';
      renderIntelligenceData(await resp.json());
    } else {
      alert('Falha ao salvar regra (verifique permissões Administrator e campos).');
    }
  });
  $('secListForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      listKind: $('listKindInput').value,
      targetType: $('listTypeInput').value,
      targetValue: $('listValueInput').value.trim(),
      reason: $('listReasonInput').value.trim(),
    };
    const resp = await apiFetch('/api/security/lists', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      $('listValueInput').value = '';
      $('listReasonInput').value = '';
      renderIntelligenceData(await resp.json());
    } else {
      const err = await resp.json().catch(() => ({}));
      alert(err.message || err.error || 'Falha ao adicionar entrada.');
    }
  });
  $('fwRuleForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const applyToOs = $('fwApplyOsInput').checked;
    const ruleName = $('fwNameInput').value.trim();
    if (!confirm(`Confirmar criação da regra de firewall "${ruleName}"${applyToOs ? ' com aplicação no Firewall do Sistema' : ' (política registrada)'}?`)) {
      return;
    }
    const payload = {
      ruleName,
      direction: $('fwDirInput').value,
      action: $('fwActionInput').value,
      protocol: $('fwProtoInput').value,
      remoteIp: $('fwIpInput').value.trim(),
      remotePort: parseInt($('fwPortInput').value, 10) || 0,
      programPath: $('fwProgramInput').value.trim(),
      applyToOs,
      confirm: true,
    };
    const resp = await apiFetch('/api/security/firewall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      $('fwNameInput').value = '';
      $('fwIpInput').value = '';
      $('fwPortInput').value = '';
      $('fwProgramInput').value = '';
      renderIntelligenceData(await resp.json());
    } else {
      const err = await resp.json().catch(() => ({}));
      alert(err.message || err.error || 'Falha ao criar regra de firewall.');
    }
  });
  $('btnTopoResetView').addEventListener('click', () => lanTopoCanvas.fitView());
  $('topoFilterSelect').addEventListener('change', applyTopologyView);
  $('topoSearchInput').addEventListener('input', applyTopologyView);

  nocController = new NocDashboardController({ apiFetch });
  $('btnModules').addEventListener('click', openModuleDock);
  $('btnCloseModuleDock').addEventListener('click', closeModuleDock);
  $('moduleDockModal').addEventListener('click', (e) => {
    if (e.target === $('moduleDockModal')) closeModuleDock();
  });
  $('btnDockOpenNoc').addEventListener('click', () => {
    closeModuleDock();
    nocController.open(true);
  });
  $('btnNoc').addEventListener('click', () => nocController.open(false));

  $('btnNotifications').addEventListener('click', openNotificationsModal);
  $('btnCloseNotifications').addEventListener('click', closeNotificationsModal);
  $('notificationsModal').addEventListener('click', (e) => {
    if (e.target === $('notificationsModal')) closeNotificationsModal();
  });
  $('btnNotifRefresh').addEventListener('click', loadNotificationsTab);
  document.querySelectorAll('#notifTabs .tab-btn[data-ntab]').forEach((b) => {
    b.addEventListener('click', () => {
      state.notifTab = b.getAttribute('data-ntab');
      switchNotificationsTab();
    });
  });
  $('notifChannelForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      name: $('ncNameInput').value.trim(),
      kind: $('ncKindInput').value,
      enabled: true,
      endpointUrl: $('ncUrlInput').value.trim(),
      secretOrToken: $('ncSecretInput').value.trim(),
      chatId: $('ncChatIdInput').value.trim(),
      minSeverity: $('ncMinSevInput').value,
      cooldownSec: parseInt($('ncCooldownInput').value, 10) || 60,
    };
    const resp = await apiFetch('/api/notifications/channels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      $('ncNameInput').value = '';
      $('ncUrlInput').value = '';
      $('ncSecretInput').value = '';
      $('ncChatIdInput').value = '';
      renderNotificationChannels(await resp.json());
    } else {
      const err = await resp.json().catch(() => ({}));
      alert(err.message || err.error || 'Falha ao salvar canal (requer Administrator + URL HTTPS).');
    }
  });
  $('btnCopyPromSnippet').addEventListener('click', () => {
    const yaml = `scrape_configs:\n  - job_name: 'netpulse'\n    metrics_path: '/metrics'\n    authorization:\n      credentials: 'SEU_TOKEN_VIEWER_OU_ADMIN'\n    static_configs:\n      - targets: ['${window.location.host}']`;
    navigator.clipboard?.writeText(yaml).catch(() => {});
    alert('Configuração Prometheus copiada para a área de transferência!');
  });

  $('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = $('authTokenInput').value.trim();
    const fb = $('authFeedback');
    fb.classList.add('hidden');
    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ token }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        fb.textContent = data.message || data.error || 'Token inválido.';
        fb.classList.remove('hidden');
        return;
      }
      state.auth.authenticated = true;
      state.auth.role = data.role;
      state.auth.actor = data.actor;
      state.auth.csrfToken = data.csrfToken || '';
      $('authTokenInput').value = '';
      hideAuthModal();
      updateAuthUi();
      await loadInitialSettings();
      connectWebSocket();
      pollUpdateStatus();
      const qs = new URLSearchParams(window.location.search);
      if (qs.get('noc') === '1' || window.location.hash === '#noc') {
        nocController?.open(false);
      }
    } catch {
      fb.textContent = 'Falha ao autenticar no motor local.';
      fb.classList.remove('hidden');
    }
  });

  $('btnLogoutSession').addEventListener('click', async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    if (ws) ws.close();
    state.auth.authenticated = false;
    state.auth.role = 'none';
    state.auth.csrfToken = '';
    closeSecurityModal();
    updateAuthUi();
    showAuthModal('Sessão encerrada.');
  });

  $('btnRevokeAllSessions').addEventListener('click', async () => {
    if (!confirm('Revogar TODAS as sessões ativas em todos os navegadores?')) return;
    try {
      const r = await apiFetch('/api/auth/tokens/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allSessions: true }),
      });
      if (r.ok) {
        if (ws) ws.close();
        state.auth.authenticated = false;
        state.auth.role = 'none';
        state.auth.csrfToken = '';
        closeSecurityModal();
        updateAuthUi();
        showAuthModal('Todas as sessões foram revogadas.');
      }
    } catch {}
  });

  $('createTokenForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const label = $('tokLabelInput').value.trim();
    const role = $('tokRoleSelect').value;
    try {
      const resp = await apiFetch('/api/auth/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, role }),
      });
      const data = await resp.json();
      if (resp.ok && data.token) {
        $('tokLabelInput').value = '';
        const banner = $('newTokenBanner');
        banner.innerHTML = `<span>Token (${escHtml(data.role)}): <code>${escHtml(data.token)}</code></span><button type="button" id="btnDismissNewTok">OK</button>`;
        banner.classList.remove('hidden');
        $('btnDismissNewTok').onclick = () => banner.classList.add('hidden');
        await loadSecurityModalData();
      }
    } catch {}
  });

  const authed = await ensureAuthenticated();
  if (authed) {
    await loadInitialSettings();
    connectWebSocket();
    const qs = new URLSearchParams(window.location.search);
    if (qs.get('noc') === '1' || window.location.hash === '#noc') {
      nocController?.open(false);
    }
  }
  initUpdateMonitor();
}

let nocController = null;

function openModuleDock() {
  renderModuleDock();
  $('moduleDockModal').classList.remove('hidden');
}

function closeModuleDock() {
  $('moduleDockModal').classList.add('hidden');
}

function renderModuleDock() {
  const s = state.snapshot?.stats || {};
  const svcs = state.snapshot?.services || [];
  const upSvcs = svcs.filter((x) => x.status === 'up').length;
  const openLeftAndTab = (tabName) => {
    closeModuleDock();
    switchViewMode('local');
    if (!document.body.classList.contains('left-open')) {
      document.body.classList.add('left-open');
      $('toggleLeftBtn').textContent = '◀';
      mapCanvas.fitPlanet();
    }
    state.tab = tabName;
    syncTabButtons();
    renderPanel();
  };

  const modules = [
    {
      id: 'global-map',
      icon: '🌍',
      title: '1. Mapa Global 2D',
      badge: `${Number(s.publicConnections || 0)} fluxos`,
      desc: 'Arcos geodésicos em tempo real, projeções e terminador Dia/Noite.',
      action: () => { closeModuleDock(); switchViewMode('local'); mapCanvas.fitPlanet(true); },
    },
    {
      id: 'connections',
      icon: '🔌',
      title: '2. Conexões Ativas',
      badge: `${Number(s.totalConnections || 0)} sockets`,
      desc: 'Inspeção instantânea TCP/UDP, PID, estado e filtro por escopo.',
      action: () => openLeftAndTab('conns'),
    },
    {
      id: 'processes',
      icon: '📈',
      title: '3. Consumo & Processos',
      badge: `${Number((state.snapshot?.processes || []).length)} apps`,
      desc: 'Aplicações que consomem internet e evolução RX/TX ao vivo.',
      action: () => openLeftAndTab('bw'),
    },
    {
      id: 'countries',
      icon: '🏳️',
      title: '4. Países & GeoIP',
      badge: `${Number(s.countries || 0)} países`,
      desc: 'Destinos internacionais, cidades, provedores e ASNs offline/online.',
      action: () => openLeftAndTab('countries'),
    },
    {
      id: 'services',
      icon: '🌐',
      title: '5. Serviços & Sonda TCP',
      badge: `${upSvcs}/${svcs.length} UP`,
      desc: 'Monitoramento contínuo de âncoras continentais e endpoints custom.',
      action: () => { closeModuleDock(); switchViewMode('global'); },
    },
    {
      id: 'quality',
      icon: '📶',
      title: '6. Qualidade de Rede',
      badge: 'P50–P99 · Jitter',
      desc: 'Latência contínua, jitter, packet loss, DNS RFC-1035 e diagnóstico.',
      action: () => { closeModuleDock(); openQualityModal(); },
    },
    {
      id: 'traceroute',
      icon: '🧭',
      title: '7. Rotas & Traceroute',
      badge: 'Route Diff',
      desc: 'Salto a salto com GeoIP/ASN, monitoramento agendado e diff TTL.',
      action: () => { closeModuleDock(); openTraceModal(); },
    },
    {
      id: 'interfaces',
      icon: '🔗',
      title: '8. Multi-WAN & Interfaces',
      badge: 'Links & Gateways',
      desc: 'Inventário Ethernet/Wi-Fi/VPN/Virtual, RX/TX e transições failover.',
      action: () => { closeModuleDock(); openInterfacesModal(); },
    },
    {
      id: 'discovery',
      icon: '🛰',
      title: '9. Descoberta LAN',
      badge: 'ARP · OUI',
      desc: 'Hosts na rede local, fabricantes IEEE OUI, MAC LAA e portas.',
      action: () => { closeModuleDock(); openDiscoveryModal(); },
    },
    {
      id: 'topology',
      icon: '🕸',
      title: '10. Topologia LAN',
      badge: 'Grafo Evidências',
      desc: 'Visualização hierárquica Host → NIC → Gateway/DNS → Dispositivos.',
      action: () => { closeModuleDock(); openTopologyModal(); },
    },
    {
      id: 'intelligence',
      icon: '🧠',
      title: '11. Intelligence & Firewall',
      badge: 'Zero IA · Regras',
      desc: 'Detecção comportamental determinística, allow/blocklist e firewall.',
      action: () => { closeModuleDock(); openIntelligenceModal(); },
    },
    {
      id: 'analytics',
      icon: '📊',
      title: '12. Histórico & Analytics',
      badge: 'SQLite WAL',
      desc: 'Top 10 apps/destinos/países, séries RX/TX e retenção configurável.',
      action: () => { closeModuleDock(); openAnalyticsModal(); },
    },
    {
      id: 'notifications',
      icon: '🔔',
      title: 'Notificações, Prometheus & API v1',
      badge: 'OpenAPI 3.0',
      desc: 'Canais Webhook HMAC/Discord/Telegram, /metrics e especificação API v1.',
      action: () => { closeModuleDock(); openNotificationsModal(); },
    },
  ];

  const grid = $('moduleDockGrid');
  grid.innerHTML = modules.map((m) => `
    <button type="button" class="module-card" data-mod="${escHtml(m.id)}">
      <div class="module-card-top">
        <span>${m.icon} ${escHtml(m.title)}</span>
        <span class="state-pill">${escHtml(m.badge)}</span>
      </div>
      <div class="module-card-desc">${escHtml(m.desc)}</div>
    </button>
  `).join('');

  grid.querySelectorAll('.module-card').forEach((btn) => {
    const id = btn.getAttribute('data-mod');
    const mod = modules.find((x) => x.id === id);
    if (mod) btn.addEventListener('click', mod.action);
  });
}

function switchViewMode(mode) {
  if (mode !== 'local' && mode !== 'global') return;
  state.viewMode = mode;
  document.querySelectorAll('.view-btn').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-view') === mode);
  });
  const isGlobal = mode === 'global';
  $('localTabs').classList.toggle('hidden', isGlobal);
  $('localFilterChips').classList.toggle('hidden', isGlobal);
  $('globalTabs').classList.toggle('hidden', !isGlobal);
  $('globalActions').classList.toggle('hidden', !isGlobal);
  if (!isGlobal) $('addServiceForm').classList.add('hidden');
  closeInspector();
  mapCanvas.setViewMode(mode);
  applyAndRender();
}

async function loadInitialSettings() {
  try {
    const resp = await apiFetch('/api/settings');
    if (!resp.ok) return;
    const cfg = await resp.json();
    if (cfg.defaultView === 'global' || cfg.defaultView === 'local') {
      switchViewMode(cfg.defaultView);
    }
  } catch {}
}

function syncNotifyCategoryDisabledState() {
  const masterOn = $('cfgAlertsEnabled').checked;
  const wrap = $('cfgNotifyCategories');
  wrap.classList.toggle('disabled', !masterOn);
  wrap.querySelectorAll('input[type="checkbox"]').forEach((chk) => {
    chk.disabled = !masterOn;
  });
}

async function openSettingsModal() {
  $('settingsFeedback').classList.add('hidden');
  $('settingsModal').classList.remove('hidden');
  try {
    const resp = await apiFetch('/api/settings');
    if (!resp.ok) return;
    const cfg = await resp.json();
    $('cfgAlertsEnabled').checked = !!cfg.alertsEnabled;
    $('cfgNotifyServiceDown').checked = cfg.notifyServiceDown !== false;
    $('cfgNotifyServiceDegraded').checked = cfg.notifyServiceDegraded !== false;
    $('cfgNotifySensitivePort').checked = cfg.notifySensitivePort !== false;
    $('cfgNotifyNewCountry').checked = cfg.notifyNewCountry !== false;
    syncNotifyCategoryDisabledState();
    $('cfgAutoStart').checked = !!cfg.autoStart;
    $('cfgMinimizeToTray').checked = !!cfg.minimizeToTray;
    $('cfgDefaultView').value = cfg.defaultView === 'global' ? 'global' : 'local';
    const retDays = Number(cfg.retentionDays) || 30;
    $('cfgRetentionDays').value = retDays;
    $('cfgRetentionPreset').value = ['1', '7', '30', '90'].includes(String(retDays)) ? String(retDays) : 'custom';
    $('cfgMaxDbSizeMb').value = Number(cfg.maxDbSizeMb) || 256;
  } catch {}
}

function closeSettingsModal() {
  $('settingsModal').classList.add('hidden');
}

async function openSecurityModal() {
  $('securityModal').classList.remove('hidden');
  $('newTokenBanner').classList.add('hidden');
  $('secSessionSummary').textContent = `Ator: ${state.auth.actor || 'local'} · Nível: ${state.auth.role} · ${state.auth.tlsEnabled ? 'TLS ativo' : 'HTTP local'}`;
  $('secTokensSection').classList.toggle('hidden', !hasRole('administrator'));
  $('btnRevokeAllSessions').classList.toggle('hidden', !hasRole('administrator'));
  await loadSecurityModalData();
}

function closeSecurityModal() {
  $('securityModal').classList.add('hidden');
}

async function loadSecurityModalData() {
  const isAdmin = hasRole('administrator');
  if (isAdmin) {
    try {
      const tr = await apiFetch('/api/auth/tokens');
      if (tr.ok) {
        const td = await tr.json();
        const tokens = td.tokens || [];
        $('secTokensList').innerHTML =
          tokens.length === 0
            ? '<div class="sec-row"><span class="sec-row-meta">Nenhum token cadastrado.</span></div>'
            : tokens
                .map(
                  (t) => `
                <div class="sec-row">
                  <div>
                    <div><strong>${escHtml(t.label)}</strong> <span class="state-pill">${escHtml(t.role)}</span></div>
                    <div class="sec-row-meta">${escHtml(t.id)} · ${escHtml(t.prefix)}... ${t.revoked ? '· REVOGADO' : ''}</div>
                  </div>
                  ${!t.revoked ? `<button type="button" class="svc-del-btn" data-revoke-tok="${escHtml(t.id)}">Revogar</button>` : ''}
                </div>`
                )
                .join('');
        $('secTokensList')
          .querySelectorAll('[data-revoke-tok]')
          .forEach((btn) => {
            btn.onclick = async () => {
              const id = btn.getAttribute('data-revoke-tok');
              if (!confirm(`Revogar token ${id}?`)) return;
              await apiFetch('/api/auth/tokens/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id }),
              });
              loadSecurityModalData();
            };
          });
      }
    } catch {}
  }

  try {
    const br = await apiFetch('/api/security/blocks');
    if (br.ok) {
      const bd = await br.json();
      const blocks = bd.blocks || [];
      $('secBlocksList').innerHTML =
        blocks.length === 0
          ? '<div class="sec-row"><span class="sec-row-meta">Nenhum IP bloqueado pelo NetPulse.</span></div>'
          : blocks
              .map(
                (b) => `
              <div class="sec-row">
                <div>
                  <div><strong>${escHtml(b.ip)}</strong></div>
                  <div class="sec-row-meta">Por ${escHtml(b.actor)} · ${new Date(b.blockedAt).toLocaleString('pt-BR')}</div>
                </div>
                ${isAdmin ? `<button type="button" class="mini-pill-btn" data-unblock-ip="${escHtml(b.ip)}">Reverter</button>` : ''}
              </div>`
              )
              .join('');
      $('secBlocksList')
        .querySelectorAll('[data-unblock-ip]')
        .forEach((btn) => {
          btn.onclick = async () => {
            const ip = btn.getAttribute('data-unblock-ip');
            if (!confirm(`Remover regra de bloqueio de firewall para ${ip}?`)) return;
            await apiFetch('/api/action/unblock-ip', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ip, confirm: true }),
            });
            loadSecurityModalData();
          };
        });
    }
  } catch {}

  try {
    const ar = await apiFetch('/api/security/audit');
    if (ar.ok) {
      const ad = await ar.json();
      const entries = ad.entries || [];
      $('secAuditList').innerHTML =
        entries.length === 0
          ? '<div class="sec-row"><span class="sec-row-meta">Sem eventos de auditoria ainda.</span></div>'
          : entries
              .slice(0, 60)
              .map((e) => {
                const cls = e.outcome === 'denied' || e.outcome === 'failed' ? 'closed' : 'new';
                return `
                <div class="sec-row">
                  <div style="min-width:0">
                    <div><strong>${escHtml(e.action)}</strong> → ${escHtml(e.target)}</div>
                    <div class="sec-row-meta">${escHtml(e.actor)} (${escHtml(e.role)}) · ${escHtml(e.sourceIp)} · ${new Date(e.ts).toLocaleTimeString('pt-BR')} · ${escHtml(e.detail)}</div>
                  </div>
                  <span class="state-pill ${cls}">${escHtml(e.outcome)}</span>
                </div>`;
              })
              .join('');
    }
  } catch {}
}

function formatTotalBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let val = n / 1024;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val >= 100 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

function openAnalyticsModal() {
  $('analyticsModal').classList.remove('hidden');
  loadActiveAnalyticsTab();
}

function closeAnalyticsModal() {
  $('analyticsModal').classList.add('hidden');
}

function syncAnalyticsViews() {
  const tab = state.analytics.tab;
  $('anaViewOverview').classList.toggle('hidden', tab !== 'overview');
  $('anaViewConnections').classList.toggle('hidden', tab !== 'connections');
  $('anaViewProcesses').classList.toggle('hidden', tab !== 'processes');
  $('anaViewStorage').classList.toggle('hidden', tab !== 'storage');
}

async function loadActiveAnalyticsTab() {
  syncAnalyticsViews();
  const tab = state.analytics.tab;
  if (tab === 'overview') await loadAnalyticsOverview();
  else if (tab === 'connections') await loadAnalyticsConnections();
  else if (tab === 'processes') await loadAnalyticsProcesses();
  else if (tab === 'storage') await loadAnalyticsStorage();
}

function renderDailyTrafficChart(series) {
  const canvas = $('anaDailyChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  if (!series || series.length === 0) {
    ctx.fillStyle = 'rgba(148, 163, 184, 0.7)';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Ainda sem amostras diárias acumuladas neste período.', w / 2, h / 2);
    return;
  }

  let maxVal = 1;
  for (const pt of series) {
    maxVal = Math.max(maxVal, Number(pt.rxBytes) || 0, Number(pt.txBytes) || 0);
  }
  const padL = 12;
  const padR = 12;
  const padT = 14;
  const padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const groupW = plotW / series.length;
  const barW = Math.max(4, Math.min(22, (groupW - 8) / 2));

  series.forEach((pt, idx) => {
    const cx = padL + idx * groupW + groupW / 2;
    const rxH = Math.round(((Number(pt.rxBytes) || 0) / maxVal) * plotH);
    const txH = Math.round(((Number(pt.txBytes) || 0) / maxVal) * plotH);

    ctx.fillStyle = '#38bdf8';
    ctx.fillRect(cx - barW - 1, padT + plotH - rxH, barW, Math.max(2, rxH));

    ctx.fillStyle = '#34d399';
    ctx.fillRect(cx + 1, padT + plotH - txH, barW, Math.max(2, txH));

    const label = new Date(pt.dayMs).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
    ctx.fillStyle = 'rgba(148, 163, 184, 0.8)';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(label, cx, h - 6);
  });
}

async function loadAnalyticsOverview() {
  try {
    const resp = await apiFetch(`/api/history/analytics?range=${encodeURIComponent(state.analytics.range)}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const s = d.summary || {};

    $('anaSummaryGrid').innerHTML = `
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Download (RX)</div><div class="ana-kpi-val" style="color:var(--accent-rx)">${formatTotalBytes(s.rxBytes)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Upload (TX)</div><div class="ana-kpi-val" style="color:var(--accent-tx)">${formatTotalBytes(s.txBytes)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Conexões Registradas</div><div class="ana-kpi-val">${Number(s.totalConnections || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Duração Média</div><div class="ana-kpi-val">${formatAge(s.avgDurationMs || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Apps / Destinos / Países</div><div class="ana-kpi-val">${Number(s.uniqueProcesses || 0)} / ${Number(s.uniqueDestinations || 0)} / ${Number(s.uniqueCountries || 0)}</div></div>
    `;

    renderDailyTrafficChart(d.dailySeries || []);

    const procs = d.topProcesses || [];
    $('anaTopProcs').innerHTML = procs.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Sem dados no período.</span></div>'
      : procs.map((p, i) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>#${i + 1} ${escHtml(p.process)}</strong></div>
            <div class="sec-row-meta">${Number(p.connections || 0)} conns · ↓ ${formatTotalBytes(p.rxBytes)} · ↑ ${formatTotalBytes(p.txBytes)}</div>
          </div>
        </div>`).join('');

    const dests = d.topDestinations || [];
    $('anaTopDests').innerHTML = dests.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Sem destinos públicos no período.</span></div>'
      : dests.map((x, i) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>#${i + 1} ${escHtml(x.dns || x.remoteIp)}</strong></div>
            <div class="sec-row-meta">${escHtml(x.remoteIp)} · ${escHtml(x.country || '—')} · ${Number(x.connections || 0)}x · ↓ ${formatTotalBytes(x.rxBytes)}</div>
          </div>
        </div>`).join('');

    const countries = d.topCountries || [];
    $('anaTopCountries').innerHTML = countries.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Sem países registrados no período.</span></div>'
      : countries.map((c, i) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>#${i + 1} ${escHtml(c.country || c.cc)}</strong> (${escHtml(c.cc)})</div>
            <div class="sec-row-meta">${Number(c.connections || 0)} conns · ${Number(c.uniqueIps || 0)} IPs · ↓ ${formatTotalBytes(c.rxBytes)}</div>
          </div>
        </div>`).join('');
  } catch {}
}

async function loadAnalyticsConnections() {
  const q = new URLSearchParams();
  q.set('limit', String(state.analytics.connLimit));
  q.set('offset', String(state.analytics.connOffset));
  const search = $('histConnSearch').value.trim();
  const scope = $('histConnScope').value;
  const proto = $('histConnProto').value;
  if (search) q.set('search', search);
  if (scope) q.set('scope', scope);
  if (proto) q.set('protocol', proto);

  try {
    const resp = await apiFetch(`/api/history/connections?${q.toString()}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const items = d.items || [];
    state.analytics.connTotal = Number(d.total || 0);

    $('histConnList').innerHTML = items.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma conexão encontrada para os filtros aplicados.</span></div>'
      : items.map((c) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>${escHtml(c.process)}</strong> <span class="sec-row-meta">(PID ${Number(c.pid || 0)} · ${escHtml(c.protocol)} · ${escHtml(c.scope)})</span> → ${escHtml(c.dns || c.remoteIp)}:${Number(c.remotePort || 0)}</div>
            <div class="sec-row-meta">${escHtml(c.localIp)}:${Number(c.localPort || 0)} · ${escHtml(c.country || 'Local')} · ${new Date(c.startedAt).toLocaleString('pt-BR')} · Duração ${formatAge(c.durationMs || 0)} · ↓ ${formatTotalBytes(c.rxBytes)} / ↑ ${formatTotalBytes(c.txBytes)}</div>
          </div>
          <span class="state-pill">${escHtml(c.state)}</span>
        </div>`).join('');

    const start = state.analytics.connTotal === 0 ? 0 : state.analytics.connOffset + 1;
    const end = Math.min(state.analytics.connTotal, state.analytics.connOffset + items.length);
    $('histConnPageInfo').textContent = `${start}–${end} de ${state.analytics.connTotal} registros`;
  } catch {}
}

async function loadAnalyticsProcesses() {
  const filter = $('histProcFilter').value.trim();
  const q = new URLSearchParams({ range: state.analytics.range, limit: '60' });
  if (filter) q.set('process', filter);
  try {
    const resp = await apiFetch(`/api/history/processes?${q.toString()}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const items = d.items || [];
    $('histProcList').innerHTML = items.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma aplicação registrada neste período.</span></div>'
      : items.map((p) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>${escHtml(p.process)}</strong></div>
            <div class="sec-row-meta">${escHtml(p.exePath || 'Caminho indisponível')} · ${Number(p.connections || 0)} conns · ${Number(p.uniqueDestinations || 0)} IPs · ${Number(p.countriesCount || 0)} países · Média ${formatAge(p.avgDurationMs || 0)}</div>
          </div>
          <div style="text-align:right;font-size:11px;white-space:nowrap">
            <div style="color:var(--accent-rx)">↓ ${formatTotalBytes(p.rxBytes)}</div>
            <div style="color:var(--accent-tx)">↑ ${formatTotalBytes(p.txBytes)}</div>
          </div>
        </div>`).join('');
  } catch {}
}

async function loadAnalyticsStorage() {
  try {
    const resp = await apiFetch('/api/history/storage');
    if (!resp.ok) return;
    const st = await resp.json();
    const t = st.tables || {};
    const sizeMb = ((Number(st.sizeBytes) || 0) / (1024 * 1024)).toFixed(2);
    $('histStorageCard').innerHTML = `
      <div class="ana-kpi-grid" style="margin-bottom:12px">
        <div class="ana-kpi-card"><div class="ana-kpi-lbl">Motor SQLite</div><div class="ana-kpi-val">${escHtml(st.sqliteVersion)} (${escHtml(st.journalMode)})</div></div>
        <div class="ana-kpi-card"><div class="ana-kpi-lbl">Integridade</div><div class="ana-kpi-val">${st.integrityOk ? 'OK (quick_check)' : 'ATENÇÃO'}</div></div>
        <div class="ana-kpi-card"><div class="ana-kpi-lbl">Tamanho em Disco</div><div class="ana-kpi-val">${sizeMb} / ${Number(st.maxDbSizeMb || 256)} MB</div></div>
        <div class="ana-kpi-card"><div class="ana-kpi-lbl">Retenção Configurada</div><div class="ana-kpi-val">${Number(st.retentionDays || 30)} dias (v${Number(st.schemaVersion || 1)})</div></div>
      </div>
      <div class="sec-list" style="margin-bottom:12px">
        <div class="sec-row"><span>Histórico de Conexões</span><strong>${Number(t.connectionHistory || 0)}</strong></div>
        <div class="sec-row"><span>Amostras NIC (agregadas)</span><strong>${Number(t.nicSamples || 0)}</strong></div>
        <div class="sec-row"><span>Rollups Tráfego / Processo</span><strong>${Number(t.trafficRollups || 0)}</strong></div>
        <div class="sec-row"><span>Métricas de Serviços</span><strong>${Number(t.serviceMetrics || 0)}</strong></div>
        <div class="sec-row"><span>Eventos e Alertas</span><strong>${Number(t.events || 0)}</strong></div>
      </div>
      <div class="bw-banner" style="margin-bottom:0">
        <span>Limpeza manual aplica política de retenção e compacta o banco (WAL checkpoint + incremental vacuum).</span>
        ${hasRole('administrator')
          ? '<button type="button" class="ctrl-btn danger" id="btnPruneHistory">Executar Limpeza Agora</button>'
          : '<span class="sec-row-meta">Requer perfil Administrator</span>'}
      </div>
      <div id="histPruneFeedback" class="item-geo hidden" style="margin-top:8px"></div>
    `;
    const btn = $('btnPruneHistory');
    if (btn) {
      btn.onclick = async () => {
        if (!window.confirm('Aplicar política de retenção e compactar o histórico SQLite agora?')) return;
        const fb = $('histPruneFeedback');
        fb.classList.remove('hidden');
        fb.textContent = 'Compactando histórico...';
        try {
          const pr = await apiFetch('/api/history/prune', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirm: true }),
          });
          if (pr.ok) {
            await loadAnalyticsStorage();
          } else {
            const err = await pr.json().catch(() => ({}));
            fb.textContent = `Falha: ${err.message || err.error || pr.status}`;
          }
        } catch {
          fb.textContent = 'Erro de comunicação ao compactar banco.';
        }
      };
    }
  } catch {}
}

function openQualityModal() {
  $('qualityModal').classList.remove('hidden');
  loadQualityStatus();
  if (state.quality.timer) clearInterval(state.quality.timer);
  state.quality.timer = setInterval(() => {
    if (!$('qualityModal').classList.contains('hidden')) {
      loadQualityStatus();
    }
  }, 5000);
}

function closeQualityModal() {
  $('qualityModal').classList.add('hidden');
  if (state.quality.timer) {
    clearInterval(state.quality.timer);
    state.quality.timer = null;
  }
}

function renderQualityChart(series) {
  const canvas = $('qualHistoryChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  if (!series || series.length === 0) {
    ctx.fillStyle = 'rgba(148, 163, 184, 0.72)';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Aguardando amostras históricas para este destino e janela.', w / 2, h / 2);
    return;
  }

  let maxMs = 10;
  for (const pt of series) {
    maxMs = Math.max(maxMs, Number(pt.p95Ms) || 0, Number(pt.avgMs) || 0);
  }
  maxMs *= 1.15;

  const padL = 42;
  const padR = 14;
  const padT = 14;
  const padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.16)';
  ctx.lineWidth = 1;
  for (let g = 0; g <= 3; g++) {
    const y = padT + (plotH * g) / 3;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();
    const lblVal = maxMs * (1 - g / 3);
    ctx.fillStyle = 'rgba(148, 163, 184, 0.78)';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(`${lblVal.toFixed(0)}ms`, padL - 5, y + 3);
  }

  const xOf = (idx) => (series.length === 1 ? padL + plotW / 2 : padL + (idx / (series.length - 1)) * plotW);
  const yOf = (val) => padT + plotH - Math.min(1, Math.max(0, (Number(val) || 0) / maxMs)) * plotH;

  // P95 amber line
  ctx.strokeStyle = '#fbbf24';
  ctx.lineWidth = 1.6;
  ctx.beginPath();
  series.forEach((pt, idx) => {
    const x = xOf(idx);
    const y = yOf(pt.p95Ms);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Avg cyan line
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  series.forEach((pt, idx) => {
    const x = xOf(idx);
    const y = yOf(pt.avgMs);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Loss markers
  series.forEach((pt, idx) => {
    if ((Number(pt.lossPct) || 0) > 0) {
      ctx.fillStyle = '#f87171';
      ctx.beginPath();
      ctx.arc(xOf(idx), padT + plotH - 4, 3.2, 0, Math.PI * 2);
      ctx.fill();
    }
  });

  // Start & end time labels
  ctx.fillStyle = 'rgba(148, 163, 184, 0.78)';
  ctx.font = '10px monospace';
  ctx.textAlign = 'left';
  ctx.fillText(new Date(series[0].ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }), padL, h - 6);
  ctx.textAlign = 'right';
  ctx.fillText(new Date(series[series.length - 1].ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }), padL + plotW, h - 6);
}

async function loadQualityHistory() {
  const tid = state.quality.selectedTargetId;
  if (!tid) {
    renderQualityChart([]);
    return;
  }
  try {
    const resp = await apiFetch(`/api/quality/history?targetId=${encodeURIComponent(tid)}&range=${encodeURIComponent(state.quality.range)}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const s = d.summary || {};
    $('qualChartStats').textContent = `${Number(s.samples || 0)} amostras · P50 ${Number(s.p50Ms || 0).toFixed(1)}ms · P95 ${Number(s.p95Ms || 0).toFixed(1)}ms · Perda ${Number(s.lossPct || 0).toFixed(1)}%`;
    renderQualityChart(d.series || []);
  } catch {}
}

async function loadQualityStatus() {
  try {
    const resp = await apiFetch('/api/quality/status');
    if (!resp.ok) return;
    const d = await resp.json();
    const infra = d.infra || {};
    const gwText = (infra.gateways && infra.gateways.length) ? infra.gateways.join(', ') : 'não detectado';
    const dnsText = (infra.dnsServers && infra.dnsServers.length) ? infra.dnsServers.join(', ') : 'não detectado';
    $('qualInfraBar').innerHTML = `<span>Gateway Local: <strong>${escHtml(gwText)}</strong> · DNS do Provedor/Sistema: <strong>${escHtml(dnsText)}</strong></span><span class="sec-row-meta">Atualização contínua (5s)</span>`;

    const diag = d.diagnosis || {};
    const health = diag.overallHealth || 'unknown';
    const badge = $('qualOverallBadge');
    badge.textContent = health.toUpperCase();
    badge.className = `state-pill ${health === 'critical' ? 'closed' : health === 'degraded' ? 'syn' : 'new'}`;

    const findings = diag.findings || [];
    $('qualDiagnosisList').innerHTML = findings.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Coletando primeiras amostras...</span></div>'
      : findings.map((f) => `
        <div class="diag-card ${escHtml(f.severity || 'info')}">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <strong>${escHtml(f.title)}</strong>
            <span class="state-pill ${f.severity === 'critical' ? 'closed' : f.severity === 'warn' ? 'syn' : 'new'}">${escHtml(f.code)}</span>
          </div>
          ${(f.observedFacts || []).length ? `<div class="sec-row-meta"><strong>Fatos observados:</strong> ${(f.observedFacts || []).map(escHtml).join(' | ')}</div>` : ''}
          ${(f.hypotheses || []).length ? `<div class="sec-row-meta" style="color:#cbd5e1"><strong>Diagnóstico:</strong> ${(f.hypotheses || []).map(escHtml).join(' ')}</div>` : ''}
        </div>`).join('');

    const targets = d.targets || [];
    if (!state.quality.selectedTargetId || !targets.some((t) => t.id === state.quality.selectedTargetId)) {
      state.quality.selectedTargetId = targets.length ? targets[0].id : null;
    }

    const canEdit = hasRole('operator');
    $('qualAddTargetForm').classList.toggle('hidden', !canEdit);
    $('btnQualityProbe').disabled = !canEdit;
    $('btnQualityRediscover').disabled = !canEdit;

    $('qualTargetsList').innerHTML = targets.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhum alvo configurado.</span></div>'
      : targets.map((t) => {
        const m = t.metrics || {};
        const sel = t.id === state.quality.selectedTargetId;
        const pillCls = t.status === 'down' ? 'closed' : t.status === 'degraded' ? 'syn' : t.status === 'ok' ? 'new' : '';
        return `
          <div class="sec-row qual-row ${sel ? 'selected' : ''}" data-qid="${escHtml(t.id)}">
            <div style="min-width:0;flex:1">
              <div><strong>${escHtml(t.name)}</strong> <span class="sec-row-meta">${escHtml(t.host)}${t.port ? ':' + Number(t.port) : ''} · ${escHtml(t.methodUsed || t.probeMode)} (${Number(t.intervalSec)}s) ${t.enabled ? '' : '· PAUSADO'}</span></div>
              <div class="sec-row-meta">Atual ${Number(m.currentMs || 0).toFixed(1)}ms · Mín ${Number(m.minMs || 0).toFixed(1)} · Méd ${Number(m.avgMs || 0).toFixed(1)} · Máx ${Number(m.maxMs || 0).toFixed(1)} | P50 ${Number(m.p50Ms || 0).toFixed(1)} · P90 ${Number(m.p90Ms || 0).toFixed(1)} · P95 ${Number(m.p95Ms || 0).toFixed(1)} · P99 ${Number(m.p99Ms || 0).toFixed(1)} | Jitter ${Number(m.jitterMs || 0).toFixed(1)}ms · Perda ${Number(m.lossPct || 0).toFixed(1)}% · Disp ${Number(m.availabilityPct || 0).toFixed(1)}% · DNS ${Number(m.avgDnsMs || 0).toFixed(1)}ms</div>
            </div>
            <div style="display:flex;align-items:center;gap:5px;flex-shrink:0">
              <span class="state-pill ${pillCls}">${escHtml(t.status)}</span>
              ${canEdit ? `<button type="button" class="mini-pill-btn q-toggle" data-id="${escHtml(t.id)}" data-en="${t.enabled ? '1' : '0'}">${t.enabled ? 'Pausar' : 'Ativar'}</button>` : ''}
              ${canEdit && !t.isAuto ? `<button type="button" class="mini-pill-btn q-del" data-id="${escHtml(t.id)}">✕</button>` : ''}
            </div>
          </div>`;
      }).join('');

    document.querySelectorAll('.qual-row[data-qid]').forEach((row) => {
      row.onclick = (e) => {
        if (e.target.closest('button')) return;
        state.quality.selectedTargetId = row.getAttribute('data-qid');
        const tObj = targets.find((x) => x.id === state.quality.selectedTargetId);
        if (tObj) $('qualChartTitle').textContent = `Série Histórica — ${tObj.name} (${tObj.host})`;
        document.querySelectorAll('.qual-row').forEach((r) => r.classList.toggle('selected', r === row));
        loadQualityHistory();
      };
    });

    document.querySelectorAll('.q-toggle').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        const nextEn = btn.getAttribute('data-en') !== '1';
        const tObj = targets.find((x) => x.id === id);
        await apiFetch('/api/quality/targets/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id,
            name: tObj ? tObj.name : '',
            port: tObj ? tObj.port : 0,
            probeMode: tObj ? tObj.probeMode : 'icmp',
            intervalSec: tObj ? tObj.intervalSec : 10,
            enabled: nextEn,
          }),
        });
        loadQualityStatus();
      };
    });

    document.querySelectorAll('.q-del').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        if (!window.confirm('Remover este destino monitorado e seu histórico?')) return;
        await apiFetch('/api/quality/targets/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id, confirm: true }),
        });
        loadQualityStatus();
      };
    });

    const curTarget = targets.find((x) => x.id === state.quality.selectedTargetId);
    if (curTarget) {
      $('qualChartTitle').textContent = `Série Histórica — ${curTarget.name} (${curTarget.host})`;
    }
    await loadQualityHistory();
  } catch {}
}

function openTraceModal(filterIp = '') {
  if (filterIp) $('traceFilterIp').value = filterIp;
  $('traceModal').classList.remove('hidden');
  loadActiveTraceTab();
}

function closeTraceModal() {
  $('traceModal').classList.add('hidden');
}

function loadActiveTraceTab() {
  const tab = state.trace.tab;
  $('traceViewHistory').classList.toggle('hidden', tab !== 'history');
  $('traceViewMonitors').classList.toggle('hidden', tab !== 'monitors');
  const canEdit = hasRole('operator');
  $('btnTraceRunTarget').disabled = !canEdit;
  $('traceMonitorForm').classList.toggle('hidden', !canEdit);
  if (tab === 'history') loadTraceHistory();
  else loadTraceMonitors();
}

async function loadTraceHistory() {
  const ip = $('traceFilterIp').value.trim();
  const q = new URLSearchParams({ limit: '40' });
  if (ip) q.set('targetIp', ip);
  try {
    const resp = await apiFetch(`/api/trace/history?${q.toString()}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const runs = d.runs || [];
    state.trace.runs = runs;

    $('traceRunsList').innerHTML = runs.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma execução de traceroute salva ainda.</span></div>'
      : runs.map((r) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>#${r.id} · ${escHtml(r.targetLabel || r.targetIp)}</strong> <span class="sec-row-meta">${escHtml(r.targetIp)} · ${escHtml(r.triggerKind)} · ${new Date(r.startedAt).toLocaleString('pt-BR')}</span></div>
            <div class="sec-row-meta">${r.hopCount} saltos · RTT final ${Number(r.totalRttMs || 0).toFixed(1)}ms · hash ${escHtml(r.pathHash || '—')} · ${r.reached ? 'Destino alcançado' : 'Incompleto'}</div>
          </div>
          ${r.changedFromPrev ? '<span class="state-pill syn">ROTA ALTERADA</span>' : '<span class="state-pill new">ESTÁVEL</span>'}
        </div>`).join('');

    const optHtml = runs.map((r) => `<option value="${r.id}">#${r.id} · ${escHtml(r.targetIp)} (${new Date(r.startedAt).toLocaleTimeString('pt-BR')})</option>`).join('');
    $('traceDiffRunA').innerHTML = optHtml;
    $('traceDiffRunB').innerHTML = optHtml;
    if (runs.length >= 2) {
      $('traceDiffRunB').value = String(runs[0].id); // newest
      $('traceDiffRunA').value = String(runs[1].id); // previous baseline
      await computeSelectedTraceDiff();
    } else {
      $('traceDiffOutput').innerHTML = '<div class="sec-row"><span class="sec-row-meta">São necessárias pelo menos 2 execuções do mesmo destino para calcular o Route Diff.</span></div>';
    }
  } catch {}
}

async function computeSelectedTraceDiff() {
  const runA = $('traceDiffRunA').value;
  const runB = $('traceDiffRunB').value;
  if (!runA || !runB) return;
  try {
    const resp = await apiFetch(`/api/trace/diff?runA=${encodeURIComponent(runA)}&runB=${encodeURIComponent(runB)}`);
    if (!resp.ok) return;
    const d = await resp.json();
    if (d.error) {
      $('traceDiffOutput').innerHTML = `<div class="sec-row"><span class="sec-row-meta">${escHtml(d.message || d.error)}</span></div>`;
      return;
    }
    const header = `
      <div class="bw-banner" style="margin-bottom:6px">
        <span><strong>${d.pathChanged ? '⚠ Caminho alterado' : '✓ Caminho idêntico'}</strong> · ${d.changedHopsCount} saltos diferentes · Δ RTT total: ${Number(d.totalRttDeltaMs || 0) >= 0 ? '+' : ''}${Number(d.totalRttDeltaMs || 0).toFixed(1)} ms</span>
        <span class="sec-row-meta">#${d.runAId} (${d.hopCountA} saltos) → #${d.runBId} (${d.hopCountB} saltos)</span>
      </div>`;
    const rows = (d.diffs || []).map((h) => {
      const cls = (h.kind === 'changed' || h.kind === 'removed') ? 'closed' : (h.kind === 'added' || h.kind === 'timeout_change') ? 'syn' : 'new';
      const deltaStr = `${Number(h.deltaRttMs || 0) >= 0 ? '+' : ''}${Number(h.deltaRttMs || 0).toFixed(1)}ms`;
      return `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>TTL #${h.ttl}</strong> · ${escHtml(h.ipA || '—')} (${Number(h.rttMsA || 0).toFixed(1)}ms) → ${escHtml(h.ipB || '—')} (${Number(h.rttMsB || 0).toFixed(1)}ms)</div>
            <div class="sec-row-meta">Δ RTT ${deltaStr}${(h.asnA || h.asnB) ? ` · ASN: ${escHtml(h.asnA || '—')} → ${escHtml(h.asnB || '—')}` : ''}</div>
          </div>
          <span class="state-pill ${cls}">${escHtml(h.kind)}</span>
        </div>`;
    }).join('');
    $('traceDiffOutput').innerHTML = header + rows;
  } catch {}
}

async function loadTraceMonitors() {
  const canEdit = hasRole('operator');
  try {
    const resp = await apiFetch('/api/trace/monitors');
    if (!resp.ok) return;
    const d = await resp.json();
    const list = d.monitors || [];
    $('traceMonitorsList').innerHTML = list.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhum destino com monitoramento periódico de rota configurado.</span></div>'
      : list.map((m) => `
        <div class="sec-row">
          <div style="min-width:0">
            <div><strong>${escHtml(m.label || m.targetIp)}</strong> <span class="sec-row-meta">${escHtml(m.targetIp)} · a cada ${Number(m.intervalSec)}s</span></div>
            <div class="sec-row-meta">${m.lastRunMs ? 'Última execução: ' + new Date(m.lastRunMs).toLocaleString('pt-BR') : 'Aguardando primeira execução'} · ${m.enabled ? 'Ativo' : 'Pausado'}</div>
          </div>
          <div style="display:flex;gap:6px">
            ${canEdit ? `<button type="button" class="mini-pill-btn tm-toggle" data-ip="${escHtml(m.targetIp)}" data-lbl="${escHtml(m.label)}" data-iv="${Number(m.intervalSec)}" data-en="${m.enabled ? '1' : '0'}">${m.enabled ? 'Pausar' : 'Ativar'}</button>` : ''}
            ${canEdit ? `<button type="button" class="mini-pill-btn tm-del" data-ip="${escHtml(m.targetIp)}">✕</button>` : ''}
          </div>
        </div>`).join('');

    document.querySelectorAll('.tm-toggle').forEach((btn) => {
      btn.onclick = async () => {
        await apiFetch('/api/trace/monitors', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targetIp: btn.getAttribute('data-ip'),
            label: btn.getAttribute('data-lbl'),
            intervalSec: Number(btn.getAttribute('data-iv')) || 300,
            enabled: btn.getAttribute('data-en') !== '1',
          }),
        });
        loadTraceMonitors();
      };
    });

    document.querySelectorAll('.tm-del').forEach((btn) => {
      btn.onclick = async () => {
        const targetIp = btn.getAttribute('data-ip');
        if (!window.confirm(`Remover monitoramento periódico de ${targetIp}?`)) return;
        await apiFetch('/api/trace/monitors/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetIp, confirm: true }),
        });
        loadTraceMonitors();
      };
    });
  } catch {}
}

function formatLinkSpeed(bps) {
  const n = Number(bps) || 0;
  if (n <= 0) return '—';
  if (n >= 1e9) return `${(n / 1e9).toFixed(n % 1e9 === 0 ? 0 : 1)} Gbps`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(0)} Mbps`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)} Kbps`;
  return `${n} bps`;
}

function openInterfacesModal() {
  $('interfacesModal').classList.remove('hidden');
  loadInterfacesData();
  if (state.interfaces.timer) clearInterval(state.interfaces.timer);
  state.interfaces.timer = setInterval(() => {
    if (!$('interfacesModal').classList.contains('hidden')) {
      loadInterfacesData();
    }
  }, 3000);
}

function closeInterfacesModal() {
  $('interfacesModal').classList.add('hidden');
  if (state.interfaces.timer) {
    clearInterval(state.interfaces.timer);
    state.interfaces.timer = null;
  }
}

function renderInterfaceHistoryChart(series) {
  const canvas = $('ifaceHistoryChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  if (!series || series.length === 0) {
    ctx.fillStyle = 'rgba(148, 163, 184, 0.72)';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Coletando amostras históricas desta interface (amostragem a cada 10s).', w / 2, h / 2);
    return;
  }

  let maxBps = 1024;
  for (const pt of series) {
    maxBps = Math.max(maxBps, Number(pt.avgRxBps) || 0, Number(pt.avgTxBps) || 0);
  }
  maxBps *= 1.15;

  const padL = 56;
  const padR = 14;
  const padT = 14;
  const padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.16)';
  ctx.lineWidth = 1;
  for (let g = 0; g <= 3; g++) {
    const y = padT + (plotH * g) / 3;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();
    ctx.fillStyle = 'rgba(148, 163, 184, 0.78)';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(formatBytesPerSec(maxBps * (1 - g / 3)), padL - 5, y + 3);
  }

  const xOf = (idx) => (series.length === 1 ? padL + plotW / 2 : padL + (idx / (series.length - 1)) * plotW);
  const yOf = (val) => padT + plotH - Math.min(1, Math.max(0, (Number(val) || 0) / maxBps)) * plotH;

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  series.forEach((pt, idx) => {
    const x = xOf(idx);
    const y = yOf(pt.avgRxBps);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.strokeStyle = '#34d399';
  ctx.lineWidth = 1.8;
  ctx.beginPath();
  series.forEach((pt, idx) => {
    const x = xOf(idx);
    const y = yOf(pt.avgTxBps);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.fillStyle = 'rgba(148, 163, 184, 0.78)';
  ctx.font = '10px monospace';
  ctx.textAlign = 'left';
  ctx.fillText(new Date(series[0].ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }), padL, h - 6);
  ctx.textAlign = 'right';
  ctx.fillText(new Date(series[series.length - 1].ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }), padL + plotW, h - 6);
}

async function loadInterfaceHistory() {
  const ifId = state.interfaces.selectedId;
  if (!ifId) {
    renderInterfaceHistoryChart([]);
    return;
  }
  try {
    const resp = await apiFetch(`/api/interfaces/history?id=${encodeURIComponent(ifId)}&range=${encodeURIComponent(state.interfaces.range)}`);
    if (!resp.ok) return;
    const d = await resp.json();
    const s = d.series || [];
    const peakRx = s.reduce((a, p) => Math.max(a, Number(p.maxRxBps) || 0), 0);
    const peakTx = s.reduce((a, p) => Math.max(a, Number(p.maxTxBps) || 0), 0);
    $('ifaceChartStats').textContent = `${s.length} pontos · Pico ↓ ${formatBytesPerSec(peakRx)} · Pico ↑ ${formatBytesPerSec(peakTx)}`;
    renderInterfaceHistoryChart(s);
  } catch {}
}

async function loadInterfacesData() {
  try {
    const resp = await apiFetch('/api/interfaces');
    if (!resp.ok) return;
    const d = await resp.json();

    $('ifaceSummaryGrid').innerHTML = `
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">WAN Primária</div><div class="ana-kpi-val">${escHtml(d.primaryIfName || 'N/A')}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Gateway Padrão</div><div class="ana-kpi-val">${escHtml(d.primaryGateway || '—')}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">WANs Ativas / Total</div><div class="ana-kpi-val">${Number(d.activeWanCount || 0)} / ${Number(d.wanCount || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">RX / TX Agregado</div><div class="ana-kpi-val">↓ ${formatBytesPerSec(d.totalRxBps)} · ↑ ${formatBytesPerSec(d.totalTxBps)}</div></div>
    `;

    const all = d.interfaces || [];
    const filt = state.interfaces.filter;
    const items = all.filter((i) => {
      if (filt === 'wan') return i.isWanCandidate || i.type === 'ethernet' || i.type === 'wifi';
      if (filt === 'vpn') return i.type === 'vpn' || i.type === 'tunnel';
      if (filt === 'virtual') return i.type === 'virtual';
      if (filt === 'up') return i.operStatus === 'up';
      return true;
    });

    if (!state.interfaces.selectedId || !all.some((x) => x.id === state.interfaces.selectedId)) {
      state.interfaces.selectedId = d.primaryIfId || (items[0] ? items[0].id : null);
    }

    $('ifaceList').innerHTML = items.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma interface para este filtro.</span></div>'
      : items.map((ifc) => {
        const sel = ifc.id === state.interfaces.selectedId;
        const stCls = ifc.operStatus === 'up' ? 'new' : 'closed';
        const ips = [...(ifc.ipv4 || []), ...(ifc.ipv6 || [])].slice(0, 3).join(', ') || 'sem IP';
        const gw = (ifc.gateways && ifc.gateways.length) ? ifc.gateways.join(', ') : '—';
        const dns = (ifc.dnsServers && ifc.dnsServers.length) ? ifc.dnsServers.slice(0, 3).join(', ') : '—';
        return `
          <div class="sec-row qual-row ${sel ? 'selected' : ''}" data-ifid="${escHtml(ifc.id)}">
            <div style="min-width:0;flex:1">
              <div>
                <strong>${escHtml(ifc.name)}</strong>
                <span class="state-pill">${escHtml(String(ifc.type || '').toUpperCase())}</span>
                ${ifc.isDefaultRoute ? '<span class="state-pill syn">WAN PRIMÁRIA</span>' : ''}
                <span class="sec-row-meta">${escHtml(ifc.description)}</span>
              </div>
              <div class="sec-row-meta">IPs: ${escHtml(ips)} · GW: ${escHtml(gw)} · DNS: ${escHtml(dns)} · MAC: ${escHtml(ifc.mac || '—')} · Link: ${formatLinkSpeed(ifc.linkSpeedBps)} · MTU ${Number(ifc.mtu || 0)}</div>
              <div class="sec-row-meta">Taxa: ↓ ${formatBytesPerSec(ifc.rxBps)} (${Number(ifc.rxPps || 0).toFixed(0)} pps) · ↑ ${formatBytesPerSec(ifc.txBps)} (${Number(ifc.txPps || 0).toFixed(0)} pps) | Total ↓ ${formatTotalBytes(ifc.rxBytes)} / ↑ ${formatTotalBytes(ifc.txBytes)} | Erros ${Number(ifc.rxErrors || 0) + Number(ifc.txErrors || 0)} · Drops ${Number(ifc.rxDiscards || 0) + Number(ifc.txDiscards || 0)}</div>
            </div>
            <span class="state-pill ${stCls}">${escHtml(String(ifc.operStatus || 'unknown').toUpperCase())}</span>
          </div>`;
      }).join('');

    document.querySelectorAll('.qual-row[data-ifid]').forEach((row) => {
      row.onclick = () => {
        state.interfaces.selectedId = row.getAttribute('data-ifid');
        const obj = all.find((x) => x.id === state.interfaces.selectedId);
        if (obj) $('ifaceChartTitle').textContent = `Histórico — ${obj.name} (${obj.type})`;
        document.querySelectorAll('.qual-row[data-ifid]').forEach((r) => r.classList.toggle('selected', r === row));
        loadInterfaceHistory();
      };
    });

    const curObj = all.find((x) => x.id === state.interfaces.selectedId);
    if (curObj) $('ifaceChartTitle').textContent = `Histórico — ${curObj.name} (${curObj.type})`;
    await loadInterfaceHistory();
  } catch {}
}

function openDiscoveryModal() {
  $('discoveryModal').classList.remove('hidden');
  loadDiscoveryDevices();
  if (state.discovery.timer) clearInterval(state.discovery.timer);
  state.discovery.timer = setInterval(() => {
    if (!$('discoveryModal').classList.contains('hidden')) {
      loadDiscoveryDevices();
    }
  }, 4000);
}

function closeDiscoveryModal() {
  $('discoveryModal').classList.add('hidden');
  if (state.discovery.timer) {
    clearInterval(state.discovery.timer);
    state.discovery.timer = null;
  }
}

async function loadDiscoveryDevices() {
  try {
    const resp = await apiFetch('/api/discovery/devices');
    if (!resp.ok) return;
    const d = await resp.json();
    const s = d.summary || {};

    const canEdit = hasRole('operator');
    const scanBtn = $('btnDiscoveryScan');
    if (s.scanRunning) {
      scanBtn.disabled = true;
      scanBtn.textContent = '⏳ Varrendo LAN...';
    } else {
      scanBtn.disabled = !canEdit;
      scanBtn.textContent = '🔍 Varrer Sub-rede LAN';
    }

    const lastStr = s.lastScanMs ? new Date(s.lastScanMs).toLocaleTimeString('pt-BR') : 'Passivo (ARP)';
    const subs = (s.subnets && s.subnets.length) ? s.subnets.join(', ') : '—';
    $('discSummaryGrid').innerHTML = `
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Dispositivos Conhecidos</div><div class="ana-kpi-val">${Number(s.totalDevices || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Online / Offline</div><div class="ana-kpi-val">${Number(s.onlineCount || 0)} / ${Number(s.offlineCount || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Gateways / Fabricantes</div><div class="ana-kpi-val">${Number(s.gatewaysCount || 0)} / ${Number(s.vendorsCount || 0)}</div></div>
      <div class="ana-kpi-card"><div class="ana-kpi-lbl">Sub-redes &amp; Varredura</div><div class="ana-kpi-val" style="font-size:11.5px">${escHtml(subs)} (${escHtml(lastStr)})</div></div>
    `;

    const all = d.devices || [];
    const filt = state.discovery.filter;
    const q = state.discovery.search;
    const filtered = all.filter((dev) => {
      if (filt === 'online' && !dev.online) return false;
      if (filt === 'offline' && dev.online) return false;
      if (filt === 'infra' && !dev.isGateway && dev.deviceType !== 'Ativo de Rede') return false;
      if (q) {
        const hay = `${dev.ip} ${dev.mac} ${dev.vendor} ${dev.hostname} ${dev.deviceType} ${dev.customLabel} ${(dev.openPorts || []).join(',')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    $('discDevicesList').innerHTML = filtered.length === 0
      ? '<div class="sec-row"><span class="sec-row-meta">Nenhum dispositivo correspondente aos filtros.</span></div>'
      : filtered.map((dev) => {
        const title = dev.customLabel || dev.hostname || dev.ip;
        const ports = (dev.openPorts || []).length ? `Portas: ${dev.openPorts.join(', ')}` : 'Sem portas abertas detectadas';
        return `
          <div class="sec-row">
            <div style="min-width:0;flex:1">
              <div>
                <strong>${escHtml(title)}</strong>
                <span class="sec-row-meta">${escHtml(dev.ip)}</span>
                <span class="state-pill">${escHtml(dev.deviceType)}</span>
                ${dev.isLocalHost ? '<span class="state-pill new">ESTE HOST</span>' : ''}
                ${dev.isGateway ? '<span class="state-pill syn">GATEWAY</span>' : ''}
                ${dev.randomizedMac ? '<span class="state-pill">MAC PRIVADO</span>' : ''}
              </div>
              <div class="sec-row-meta">MAC: ${escHtml(dev.mac || '—')} · Fabricante: ${escHtml(dev.vendor || 'Desconhecido')} · Interface: ${escHtml(dev.interface || '—')}${dev.hostname ? ' · Hostname: ' + escHtml(dev.hostname) : ''}</div>
              <div class="sec-row-meta">${escHtml(ports)} · RTT ${Number(dev.latencyMs || 0).toFixed(1)}ms · Visto ${Number(dev.seenCount || 1)}x · Último: ${new Date(dev.lastSeen).toLocaleString('pt-BR')}</div>
            </div>
            <div style="display:flex;align-items:center;gap:5px;flex-shrink:0">
              <span class="state-pill ${dev.online ? 'new' : 'closed'}">${dev.online ? 'ONLINE' : 'OFFLINE'}</span>
              ${canEdit ? `<button type="button" class="mini-pill-btn d-lbl" data-key="${escHtml(dev.key)}" data-cur="${escHtml(dev.customLabel || '')}">✏</button>` : ''}
              ${canEdit && !dev.isLocalHost ? `<button type="button" class="mini-pill-btn d-del" data-key="${escHtml(dev.key)}">✕</button>` : ''}
            </div>
          </div>`;
      }).join('');

    document.querySelectorAll('.d-lbl').forEach((btn) => {
      btn.onclick = async () => {
        const key = btn.getAttribute('data-key');
        const cur = btn.getAttribute('data-cur') || '';
        const nextLbl = window.prompt('Nome/rótulo amigável para este dispositivo (vazio remove o rótulo):', cur);
        if (nextLbl === null) return;
        await apiFetch('/api/discovery/label', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deviceKey: key, label: nextLbl.trim() }),
        });
        loadDiscoveryDevices();
      };
    });

    document.querySelectorAll('.d-del').forEach((btn) => {
      btn.onclick = async () => {
        const key = btn.getAttribute('data-key');
        if (!window.confirm(`Remover dispositivo ${key} do inventário?`)) return;
        await apiFetch('/api/discovery/devices/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deviceKey: key, confirm: true }),
        });
        loadDiscoveryDevices();
      };
    });
  } catch {}
}

const lanTopoCanvas = new LanTopologyCanvas($('lanTopoCanvas'), (node, edges) => {
  renderTopologyInspector(node, edges);
});

function renderTopologyInspector(node, edges) {
  const box = $('topoInspector');
  if (!node) {
    box.innerHTML = '<div class="sec-row-meta">Clique em qualquer nó do grafo para inspecionar metadados e a evidência técnica de conectividade das arestas.</div>';
    return;
  }
  const edgeHtml = (!edges || edges.length === 0)
    ? '<div class="sec-row-meta">Sem arestas visíveis no filtro atual.</div>'
    : edges.map((e) => `
      <div class="sec-row" style="flex-direction:column;align-items:stretch;gap:2px">
        <div><strong>${escHtml(e.kind)}</strong> · ${escHtml(e.label || '')}${e.rttMs > 0 ? ` (${Number(e.rttMs).toFixed(1)} ms)` : ''}</div>
        <div class="sec-row-meta">${escHtml(e.evidence)}</div>
      </div>`).join('');

  box.innerHTML = `
    <div style="font-size:13px;font-weight:700;color:#f8fafc">${escHtml(node.label)}</div>
    <div class="sec-row-meta">${escHtml(node.deviceType || node.kind)} · Status: <strong>${escHtml(node.status)}</strong></div>
    <div class="sec-list" style="margin:6px 0">
      ${node.ip ? `<div class="sec-row"><span>IP</span><strong>${escHtml(node.ip)}</strong></div>` : ''}
      ${node.mac ? `<div class="sec-row"><span>MAC</span><strong>${escHtml(node.mac)}</strong></div>` : ''}
      ${node.vendor ? `<div class="sec-row"><span>Fabricante</span><strong>${escHtml(node.vendor)}</strong></div>` : ''}
      ${node.subnet ? `<div class="sec-row"><span>Sub-rede</span><strong>${escHtml(node.subnet)}</strong></div>` : ''}
      ${node.openPorts ? `<div class="sec-row"><span>Portas</span><strong>${escHtml(node.openPorts)}</strong></div>` : ''}
      ${node.latencyMs > 0 ? `<div class="sec-row"><span>Latência</span><strong>${Number(node.latencyMs).toFixed(1)} ms</strong></div>` : ''}
      ${node.activeConns > 0 ? `<div class="sec-row"><span>Sockets Ativos</span><strong>${Number(node.activeConns)}</strong></div>` : ''}
    </div>
    <div class="notify-cats-head" style="padding-top:4px"><span>Evidências de Conectividade (${(edges || []).length})</span></div>
    <div class="sec-list">${edgeHtml}</div>
  `;
}

function applyTopologyView() {
  if (!state.lanTopo.data) return;
  lanTopoCanvas.setData(
    state.lanTopo.data,
    $('topoFilterSelect').value,
    $('topoSearchInput').value
  );
}

function openTopologyModal() {
  $('topologyModal').classList.remove('hidden');
  lanTopoCanvas.startAnimation();
  loadLanTopology().then(() => lanTopoCanvas.fitView());
  if (state.lanTopo.timer) clearInterval(state.lanTopo.timer);
  state.lanTopo.timer = setInterval(() => {
    if (!$('topologyModal').classList.contains('hidden')) {
      loadLanTopology();
    }
  }, 5000);
}

function closeTopologyModal() {
  $('topologyModal').classList.add('hidden');
  lanTopoCanvas.stopAnimation();
  if (state.lanTopo.timer) {
    clearInterval(state.lanTopo.timer);
    state.lanTopo.timer = null;
  }
}

async function loadLanTopology() {
  try {
    const resp = await apiFetch('/api/topology/lan');
    if (!resp.ok) return;
    const d = await resp.json();
    state.lanTopo.data = d;
    const s = d.summary || {};
    $('topoSummaryBar').innerHTML = `<span>Nós: <strong>${Number(s.nodes || 0)}</strong> · Arestas: <strong>${Number(s.edges || 0)}</strong> · Dispositivos Online: <strong>${Number(s.onlineDevices || 0)}/${Number(s.totalDevices || 0)}</strong> · Sockets Ativos: <strong>${Number(s.activeSockets || 0)}</strong></span><span class="sec-row-meta">Arraste para mover · Roda do mouse para zoom</span>`;
    $('topoModelNote').textContent = d.modelNote || '';
    applyTopologyView();
  } catch {}
}

function openIntelligenceModal() {
  $('intelligenceModal').classList.remove('hidden');
  switchIntelligenceTab();
  loadIntelligenceOverview();
  if (state.intelligence.timer) clearInterval(state.intelligence.timer);
  state.intelligence.timer = setInterval(() => {
    if (!$('intelligenceModal').classList.contains('hidden')) {
      loadIntelligenceOverview();
    }
  }, 5000);
}

function closeIntelligenceModal() {
  $('intelligenceModal').classList.add('hidden');
  if (state.intelligence.timer) {
    clearInterval(state.intelligence.timer);
    state.intelligence.timer = null;
  }
}

function switchIntelligenceTab() {
  const t = state.intelligence.tab;
  document.querySelectorAll('#intelTabs .tab-btn[data-itab]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-itab') === t);
  });
  $('intelTabAlerts').classList.toggle('hidden', t !== 'alerts');
  $('intelTabRules').classList.toggle('hidden', t !== 'rules');
  $('intelTabLists').classList.toggle('hidden', t !== 'lists');
  $('intelTabFirewall').classList.toggle('hidden', t !== 'firewall');
}

async function loadIntelligenceOverview() {
  try {
    const qs = new URLSearchParams({ limit: '120' });
    if (state.intelligence.level) qs.set('level', state.intelligence.level);
    if (state.intelligence.unackOnly) qs.set('unackOnly', 'true');
    const resp = await apiFetch('/api/intelligence/overview?' + qs.toString());
    if (!resp.ok) return;
    renderIntelligenceData(await resp.json());
  } catch {}
}

function renderIntelligenceData(d) {
  const canOp = hasRole('operator');
  const canAdmin = hasRole('administrator');
  const level = d.overallRiskLevel || 'informative';
  const score = Number(d.overallRiskScore || 0);
  const badge = $('intelRiskHeaderBadge');
  if (badge) {
    badge.className = `risk-pill ${escHtml(level)}`;
    badge.textContent = `RISCO ${score} · ${level.toUpperCase()}`;
  }

  const sum = d.summary || {};
  $('intelSummaryGrid').innerHTML = `
    <div class="ana-kpi-card"><span>Motor</span><strong>Determinístico (Sem IA)</strong></div>
    <div class="ana-kpi-card"><span>Não Reconhecidos</span><strong>${Number(d.unacknowledgedCount || 0)}</strong></div>
    <div class="ana-kpi-card"><span>Críticos / Altos</span><strong>${Number(sum.critical || 0)} / ${Number(sum.high || 0)}</strong></div>
    <div class="ana-kpi-card"><span>Moderados / Baixos</span><strong>${Number(sum.moderate || 0)} / ${Number(sum.low || 0)}</strong></div>
    <div class="ana-kpi-card"><span>Processos Base EWMA</span><strong>${Number(d.trackedProcessBaselines || 0)}</strong></div>
  `;

  if ($('intelRuleForm')) $('intelRuleForm').querySelector('button[type="submit"]').disabled = !canAdmin;
  if ($('secListForm')) $('secListForm').querySelector('button[type="submit"]').disabled = !canOp;
  if ($('fwRuleForm')) $('fwRuleForm').querySelector('button[type="submit"]').disabled = !canAdmin;

  const alerts = d.alerts || [];
  $('intelAlertsList').innerHTML = alerts.length === 0
    ? '<div class="sec-row"><span class="sec-row-meta">Nenhum alerta comportamental registrado com os filtros atuais.</span></div>'
    : alerts.map((a) => {
      const evs = (a.evidences || []).map((e) => `• ${escHtml(e)}`).join(' &nbsp; ');
      const destIp = (a.destination || '').split(':')[0];
      return `
        <div class="diag-card ${a.riskLevel === 'critical' || a.riskLevel === 'high' ? 'critical' : a.riskLevel === 'moderate' ? 'warn' : 'ok'}">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
            <div>
              <span class="risk-pill ${escHtml(a.riskLevel)}">${escHtml(a.riskLevel)} (${Number(a.riskScore)})</span>
              <strong>${escHtml(a.ruleName)}</strong>
              <span class="sec-row-meta">${escHtml(a.processName || 'Host')}${a.pid ? ' #' + a.pid : ''} · ${escHtml(a.destination || '—')}</span>
            </div>
            <div style="display:flex;gap:5px;align-items:center">
              <span class="sec-row-meta">${new Date(a.tsMs).toLocaleString('pt-BR')}</span>
              ${!a.acknowledged && canOp ? `<button type="button" class="mini-pill-btn i-ack" data-id="${a.id}">✓ Reconhecer</button>` : `<span class="sec-row-meta">${a.acknowledged ? '✓ Reconhecido' : ''}</span>`}
              ${canOp && a.processName ? `<button type="button" class="mini-pill-btn i-allow" data-proc="${escHtml(a.processName)}">Allowlist Proc</button>` : ''}
              ${canOp && destIp && /^\d+\.\d+\.\d+\.\d+$/.test(destIp) ? `<button type="button" class="mini-pill-btn i-block" data-ip="${escHtml(destIp)}">Blocklist IP</button>` : ''}
            </div>
          </div>
          <div>${escHtml(a.whatHappened)}</div>
          <div class="sec-row-meta">${evs}</div>
          <div class="sec-row-meta">Motivo: ${escHtml(a.classificationReason)}</div>
        </div>`;
    }).join('');

  $('intelAlertsList').querySelectorAll('.i-ack').forEach((b) => {
    b.addEventListener('click', async () => {
      await apiFetch('/api/intelligence/ack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId: parseInt(b.getAttribute('data-id'), 10) }),
      });
      loadIntelligenceOverview();
    });
  });
  $('intelAlertsList').querySelectorAll('.i-allow').forEach((b) => {
    b.addEventListener('click', async () => {
      const proc = b.getAttribute('data-proc');
      await apiFetch('/api/security/lists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listKind: 'allowlist', targetType: 'process', targetValue: proc, reason: 'Permitido a partir do alerta UI' }),
      });
      loadIntelligenceOverview();
    });
  });
  $('intelAlertsList').querySelectorAll('.i-block').forEach((b) => {
    b.addEventListener('click', async () => {
      const ip = b.getAttribute('data-ip');
      if (!confirm(`Adicionar ${ip} à Blocklist de segurança?`)) return;
      await apiFetch('/api/security/lists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listKind: 'blocklist', targetType: 'ip', targetValue: ip, reason: 'Marcado como blocklist via alerta UI' }),
      });
      loadIntelligenceOverview();
    });
  });

  const rules = d.rules || [];
  $('intelRulesList').innerHTML = rules.map((r) => `
    <div class="sec-row">
      <div style="min-width:0;flex:1">
        <div>
          <strong>${escHtml(r.name)}</strong>
          <span class="state-pill">${escHtml(r.kind)}</span>
          <span class="risk-pill ${r.riskWeight >= 80 ? 'critical' : r.riskWeight >= 60 ? 'high' : r.riskWeight >= 40 ? 'moderate' : 'low'}">Peso ${Number(r.riskWeight)}</span>
          ${r.isBuiltin ? '<span class="state-pill">BUILTIN</span>' : '<span class="state-pill new">CUSTOM</span>'}
        </div>
        <div class="sec-row-meta">${escHtml(r.description || '')} · Limiar=${Number(r.thresholdNum || 0)}${r.matchCountry ? ' · País=' + escHtml(r.matchCountry) : ''}${r.matchPort ? ' · Porta=' + r.matchPort : ''}${r.matchProcess ? ' · Proc=' + escHtml(r.matchProcess) : ''}</div>
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <button type="button" class="mini-pill-btn i-rtog" data-id="${escHtml(r.id)}" ${!canAdmin ? 'disabled' : ''}>${r.enabled ? 'Ativa ✓' : 'Inativa'}</button>
        ${!r.isBuiltin && canAdmin ? `<button type="button" class="mini-pill-btn i-rdel" data-id="${escHtml(r.id)}">✕</button>` : ''}
      </div>
    </div>
  `).join('');

  $('intelRulesList').querySelectorAll('.i-rtog').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      const r = rules.find((x) => x.id === id);
      if (!r) return;
      const resp = await apiFetch('/api/intelligence/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...r, enabled: !r.enabled }),
      });
      if (resp.ok) renderIntelligenceData(await resp.json());
    });
  });
  $('intelRulesList').querySelectorAll('.i-rdel').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      if (!confirm('Remover regra personalizada?')) return;
      const resp = await apiFetch('/api/intelligence/rules/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, confirm: true }),
      });
      if (resp.ok) renderIntelligenceData(await resp.json());
    });
  });

  const lists = d.lists || [];
  $('secListsContainer').innerHTML = lists.length === 0
    ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma entrada configurada em Allowlist ou Blocklist.</span></div>'
    : lists.map((e) => `
      <div class="sec-row">
        <div>
          <span class="risk-pill ${e.listKind === 'blocklist' ? 'critical' : 'low'}">${escHtml(e.listKind)}</span>
          <span class="state-pill">${escHtml(e.targetType)}</span>
          <strong>${escHtml(e.targetValue)}</strong>
          <span class="sec-row-meta">${escHtml(e.reason || '')} · por ${escHtml(e.createdBy || '—')}</span>
        </div>
        ${canOp ? `<button type="button" class="mini-pill-btn i-ldel" data-id="${escHtml(e.id)}">✕ Remover</button>` : ''}
      </div>
    `).join('');

  $('secListsContainer').querySelectorAll('.i-ldel').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      if (!confirm('Remover item da lista de segurança?')) return;
      const resp = await apiFetch('/api/security/lists/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, confirm: true }),
      });
      if (resp.ok) renderIntelligenceData(await resp.json());
    });
  });

  const fws = d.firewallRules || [];
  $('fwRulesList').innerHTML = fws.length === 0
    ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma regra granular de firewall criada.</span></div>'
    : fws.map((fw) => `
      <div class="sec-row">
        <div>
          <span class="risk-pill ${fw.action === 'block' ? 'high' : 'low'}">${escHtml(fw.action)} ${escHtml(fw.direction)}</span>
          <strong>${escHtml(fw.ruleName)}</strong>
          <span class="state-pill">${escHtml(fw.protocol)}</span>
          ${fw.osApplied ? '<span class="state-pill new">OS APLICADA</span>' : '<span class="state-pill">POLÍTICA DB</span>'}
          <div class="sec-row-meta">${fw.remoteIp ? 'IP=' + escHtml(fw.remoteIp) + ' ' : ''}${fw.remotePort ? 'Porta=' + fw.remotePort + ' ' : ''}${fw.programPath ? 'Exe=' + escHtml(fw.programPath) : ''}</div>
        </div>
        ${canAdmin ? `<button type="button" class="mini-pill-btn i-fwdel" data-id="${escHtml(fw.id)}">↺ Reverter / Excluir</button>` : ''}
      </div>
    `).join('');

  $('fwRulesList').querySelectorAll('.i-fwdel').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      if (!confirm('Reverter/excluir regra de firewall?')) return;
      const resp = await apiFetch('/api/security/firewall/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, confirm: true }),
      });
      if (resp.ok) renderIntelligenceData(await resp.json());
      else {
        const err = await resp.json().catch(() => ({}));
        alert(err.message || err.error || 'Falha ao remover regra.');
      }
    });
  });
}

function openNotificationsModal() {
  state.notifTab = state.notifTab || 'channels';
  $('notificationsModal').classList.remove('hidden');
  switchNotificationsTab();
}

function closeNotificationsModal() {
  $('notificationsModal').classList.add('hidden');
}

function switchNotificationsTab() {
  const t = state.notifTab || 'channels';
  document.querySelectorAll('#notifTabs .tab-btn[data-ntab]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-ntab') === t);
  });
  $('notifTabChannels').classList.toggle('hidden', t !== 'channels');
  $('notifTabDeliveries').classList.toggle('hidden', t !== 'deliveries');
  $('notifTabApi').classList.toggle('hidden', t !== 'api');
  loadNotificationsTab();
}

async function loadNotificationsTab() {
  const t = state.notifTab || 'channels';
  const canAdmin = hasRole('administrator');
  if ($('notifChannelForm')) $('notifChannelForm').querySelector('button[type="submit"]').disabled = !canAdmin;
  if (t === 'channels') {
    const r = await apiFetch('/api/notifications/channels');
    if (r.ok) renderNotificationChannels(await r.json());
  } else if (t === 'deliveries') {
    const r = await apiFetch('/api/notifications/deliveries?limit=60');
    if (r.ok) {
      const d = await r.json();
      const items = d.deliveries || [];
      $('notifDeliveriesList').innerHTML = items.length === 0
        ? '<div class="sec-row"><span class="sec-row-meta">Nenhuma entrega registrada.</span></div>'
        : items.map((x) => `
          <div class="sec-row">
            <div>
              <span class="state-pill ${x.ok ? 'new' : 'closed'}">${x.ok ? 'HTTP ' + x.httpStatus : 'ERRO ' + x.httpStatus}</span>
              <strong>${escHtml(x.channelName)}</strong> · ${escHtml(x.title)}
              <div class="sec-row-meta">${escHtml(x.eventKind)} (${escHtml(x.severity)}) ${x.error ? '· ' + escHtml(x.error) : ''}</div>
            </div>
            <span class="sec-row-meta">${new Date(x.tsMs).toLocaleString('pt-BR')}</span>
          </div>
        `).join('');
    }
  } else if (t === 'api') {
    const [rProm, rOpen] = await Promise.all([
      apiFetch('/metrics'),
      apiFetch('/api/v1/openapi.json'),
    ]);
    if (rProm.ok) {
      $('promPreviewPre').textContent = await rProm.text();
    }
    if (rOpen.ok) {
      const spec = await rOpen.json();
      const entries = Object.entries(spec.paths || {});
      $('openApiPathsList').innerHTML = entries.map(([p, ops]) => {
        const meths = Object.entries(ops).map(([m, info]) =>
          `<span class="state-pill">${escHtml(m.toUpperCase())}</span> ${escHtml(info.summary || '')}`
        ).join(' ');
        return `<div class="sec-row"><div><code>${escHtml(p)}</code></div><div>${meths}</div></div>`;
      }).join('');
    }
  }
}

function renderNotificationChannels(d) {
  const canOp = hasRole('operator');
  const canAdmin = hasRole('administrator');
  const list = d.channels || [];
  $('notifChannelsList').innerHTML = list.length === 0
    ? '<div class="sec-row"><span class="sec-row-meta">Nenhum canal Webhook/Discord/Telegram configurado.</span></div>'
    : list.map((c) => `
      <div class="sec-row">
        <div style="min-width:0;flex:1">
          <div>
            <span class="state-pill">${escHtml(c.kind.toUpperCase())}</span>
            <strong>${escHtml(c.name)}</strong>
            <span class="state-pill ${c.enabled ? 'new' : 'closed'}">${c.enabled ? 'ATIVO' : 'PAUSADO'}</span>
            ${c.hasSecret ? `<span class="state-pill">Secret ${escHtml(c.secretPreview || '***')}</span>` : ''}
          </div>
          <div class="sec-row-meta">${escHtml(c.endpointUrl || (c.kind === 'telegram' ? 'Telegram API (' + c.chatId + ')' : '—'))} · Mín=${escHtml(c.minSeverity)} · Cooldown=${Number(c.cooldownSec)}s · Último=${escHtml(c.lastStatus || 'nunca')} ${c.lastError ? '(' + escHtml(c.lastError) + ')' : ''}</div>
        </div>
        <div style="display:flex;gap:5px;flex-shrink:0">
          ${canOp ? `<button type="button" class="mini-pill-btn n-test" data-id="${escHtml(c.id)}">▶ Testar</button>` : ''}
          ${canAdmin ? `<button type="button" class="mini-pill-btn n-del" data-id="${escHtml(c.id)}">✕</button>` : ''}
        </div>
      </div>
    `).join('');

  $('notifChannelsList').querySelectorAll('.n-test').forEach((b) => {
    b.addEventListener('click', async () => {
      b.disabled = true;
      const resp = await apiFetch('/api/notifications/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: b.getAttribute('data-id') }),
      });
      b.disabled = false;
      if (resp.ok) alert('Notificação de teste entregue com sucesso!');
      else {
        const err = await resp.json().catch(() => ({}));
        alert(`Falha no envio: ${err.message || err.error || resp.status}`);
      }
      loadNotificationsTab();
    });
  });

  $('notifChannelsList').querySelectorAll('.n-del').forEach((b) => {
    b.addEventListener('click', async () => {
      if (!confirm('Remover canal externo de notificação?')) return;
      const resp = await apiFetch('/api/notifications/channels/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: b.getAttribute('data-id'), confirm: true }),
      });
      if (resp.ok) renderNotificationChannels(await resp.json());
    });
  });
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
  if (!state.auth.authenticated) return;
  try {
    const resp = await apiFetch('/api/update/status');
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
      await apiFetch('/api/update/check', { method: 'POST' });
      pollUpdateStatus();
    } catch {}
  });

  $('btnApplyUpdate').addEventListener('click', async () => {
    if (!confirm('Baixar e instalar a nova versão do NetPulse? O aplicativo será reiniciado.')) return;
    $('btnApplyUpdate').disabled = true;
    try {
      await apiFetch('/api/update/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      pollUpdateStatus();
    } catch {}
  });

  setTimeout(pollUpdateStatus, 3200);
  setInterval(pollUpdateStatus, 30000);
}

init();
