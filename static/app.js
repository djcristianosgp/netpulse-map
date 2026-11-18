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
  analytics: {
    tab: 'overview',
    range: '7d',
    connOffset: 0,
    connLimit: 30,
    connTotal: 0,
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
    const inInput = document.activeElement === $('searchInput');
    if (e.key === 'Escape') {
      if (!$('analyticsModal').classList.contains('hidden')) {
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
  }
  initUpdateMonitor();
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
