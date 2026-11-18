# Changelog

Todas as mudanças relevantes do **NetPulse** serão documentadas neste arquivo.

## [2.0.0] - 2026-11-18 — Fase 10: NetPulse 2.0 Platform Release (Estabilização, Benchmarks, CI Multiplataforma & Empacotamento)

### Adicionado e Consolidado
- **Benchmarks & Estabilização (`tests/test_core.cpp`)**: nova suíte `testPlatformBenchmarksAndStabilization` validando orçamento de latência do `NetMonitor::poll`, geração/serialização de topologia LAN com 128 hosts e 50 sockets, estabilidade do motor EWMA/cooldown em rajadas de 20 ticks e throughput do OpenAPI 3.0.3.
- **CI Multiplataforma Windows + Linux (`.github/workflows/ci.yml`, `.github/workflows/release.yml`)**: job paralelo `linux-cmake-and-test` (`ubuntu-latest`, CMake + OpenSSL + `ctest`) somado ao job MSVC `windows-latest`, com verificação `node --check` em todos os 5 scripts JS (`topo.js`, `map-canvas.js`, `lan-topo.js`, `noc-dashboard.js`, `app.js`).
- **Empacotamento & Segurança (`packaging/build-installer.ps1`, `build.bat`, `CMakeLists.txt`, `Dockerfile`, `src/notifications/notification_engine.cpp`)**: versão unificada `2.0.0`, inclusão da documentação técnica completa no pacote portátil ZIP, verificação de hostname `SSL_set1_host` no transporte HTTPS Linux e atualização consolidada de `README.md`, `ARCHITECTURE.md`, `SECURITY.md` e `ROADMAP.md`.

## [1.12.0] - 2026-11-18 — Fase 9: API v1 Documentada, Prometheus & Notificações

### Adicionado
- **Notification Engine (`src/notifications/notification_engine.*`)**:
  - Despacho assíncrono em thread dedicada (`std::jthread`) conectado automaticamente a `HistoryStore` (eventos operacionais) e `IntelligenceEngine` (alertas comportamentais).
  - Suporte nativo a **Webhook HTTPS com assinatura HMAC-SHA256** (`X-NetPulse-Signature: sha256=...`, RFC 2104 sobre `AuthManager::sha256Hex`), **Discord Webhook** (embeds por severidade) e **Telegram Bot API** (`sendMessage`), com filtros por severidade mínima/categorias, cooldown configurável por canal, proteção SSRF/HTTPS (HTTP permitido apenas para loopback local) e mascaramento de segredos (`secretPreview`).
- **SQLite Migration v7 (`src/storage/sqlite_db.cpp`, `src/history_store.*`)**:
  - Tabelas `notification_channels` e `notification_deliveries` integradas à retenção e ao endpoint `/api/history/storage`.
- **Prometheus Exporter & OpenAPI 3.0.3 (`src/api/prometheus_openapi.*`, `src/api/api_router.*`, `src/ws_server.cpp`)**:
  - `GET /metrics` (`/api/metrics` / `/api/v1/metrics`, perfil `Viewer+`): exportação Prometheus `text/plain; version=0.0.4` cobrindo sockets ativos, NIC RX/TX, alvos Quality, interfaces Multi-WAN, Discovery LAN, serviços, risco Intelligence e entregas de notificação.
  - `GET /api/v1/openapi.json` (`Viewer+`): especificação completa OpenAPI 3.0.3 (36 endpoints) com esquemas `bearerAuth` e `cookieAuth`.
  - CRUD e teste de notificações (`/api/notifications/channels*`, `/api/notifications/test`, `/api/notifications/deliveries`) protegidos por RBAC/CSRF/`confirm: true`/AuditLog.
- **Web UI (`static/index.html`, `static/app.js`)**: botão `🔔 Notif / API`, atalho no dock de módulos e modal `#notificationsModal` com gestão de canais, histórico de entregas, cópia de `scrape_configs` Prometheus e visualizador de endpoints OpenAPI.
- **Testes (`tests/test_core.cpp`)**: `testNotificationsPrometheusAndOpenApi` (vetor RFC 4231 HMAC-SHA256, validação URL SSRF, cooldown, formatter Discord/Telegram, Migration v7 e preservação de segredo em edição) + cobertura HTTP `/metrics`, `/api/v1/openapi.json` e `/api/v1/notifications/channels`.

## [1.11.0] - 2026-11-18 — Fase 8: Dashboard Analytics & Modo NOC

### Adicionado
- **Endpoint Consolidado Somente Leitura (`src/api/api_router.cpp`)**: `GET /api/noc/overview` (`/api/v1/noc/overview`, perfil `Viewer+`) agrega em única chamada determinística telemetria em tempo real, Network Quality, Interfaces Multi-WAN, Discovery LAN, Intelligence Determinística, Serviços Âncora, Analytics (`24h`/`7d`/`30d`), Traceroute recente e estatísticas SQLite WAL.
- **Navegação Unificada em 12 Módulos (`static/index.html`, `static/styles.css`, `static/app.js`)**: botão `⊞ 12 Módulos` (atalho `M`) e modal `#moduleDockModal` com cards interativos e contadores ao vivo para acesso direto aos 12 módulos operacionais da plataforma.
- **Modo NOC / TV Fullscreen Somente Leitura (`static/noc-dashboard.js`, `#nocOverlay`)**: classe `NocDashboardController` (botão `📺 NOC`, atalho `N` ou query/hash `?noc=1` / `#noc`) sem qualquer controle de mutação, com relógio em tempo real, 6 KPIs de alto contraste, gráfico Canvas2D RX/TX, matriz multi-alvo/Multi-WAN, Top Aplicações/Países, diagnóstico & serviços, alertas comportamentais, Topologia LAN ao vivo embutida, Fullscreen API (`⛶ Tela Cheia`), cadência configurável (`5s`/`10s`/`30s`) e rotação automática opcional para TV (`15s`).
- **Testes (`tests/test_core.cpp`)**: validação HTTP/RBAC e parsing JSON estrito de `GET /api/v1/noc/overview?range=24h` em `testLiveSecurityHttpAndWsIntegration`.

## [1.10.0] - 2026-11-18 — Fase 7: Security Engine & Intelligence Determinística

### Adicionado
- **Intelligence Engine 100% Determinístico (`src/intelligence/intelligence_engine.*`, zero IA/LLM)**:
  - Avaliação contínua por tick de telemetria (`processTelemetry`) com baseline EWMA por processo e interface global.
  - Todos os 9 detectores comportamentais nativos (`high_connection_rate`, `unseen_country` com nota explícita de que país/geolocalização isolada não indica malícia, `unknown_destination`, `abnormal_traffic_volume`, `persistent_connection`, `traffic_pattern_shift`, `repeated_failed_connections`, `sensitive_port_usage`, `unusual_process_path`).
  - Regras configuráveis pelo usuário (`country_watch`, `bandwidth_threshold`, `connection_duration`, `sensitive_port_watch`, `new_external_process`, `connection_burst`) com ativação, edição de limiares/pesos e exclusão controlada de regras customizadas.
  - Índice de risco transparente em 5 níveis (`informative`, `low`, `moderate`, `high`, `critical`) com fórmula/peso, evidências técnicas, processo/PID/executável, destino e ações sugeridas.
- **Security Engine & Reversibilidade (`src/actions.*`, `src/history_store.*`)**:
  - Gestão persistente de Allowlist e Blocklist (`ip`, `process`, `port`).
  - Criação e reversão de regras granulares de firewall por IP remoto, porta TCP/UDP, direção (`in`/`out`), ação (`block`/`allow`) e executável (`applyOsFirewallRule` / `removeOsFirewallRule` via `netsh advfirewall` no Windows quando elevado + validação rígida de tokens/caminhos, exigindo `"confirm": true` e registro no `AuditLog`).
- **Migration v6 no SQLite (`src/storage/sqlite_db.cpp`)**:
  - Novas tabelas `security_rules`, `security_alerts` (com retenção automática), `security_lists` e `firewall_rules`.
- **API & Web UI (`src/api/api_router.*`, `static/index.html`, `static/styles.css`, `static/app.js`)**:
  - Endpoints `/api/intelligence/overview`, `/api/intelligence/ack`, `/api/intelligence/rules*`, `/api/security/lists*` e `/api/security/firewall*` com RBAC (`Viewer` / `Operator` / `Administrator`) e CSRF.
  - Botão `🧠 Intelligence` e modal `#intelligenceModal` com abas **Alertas & Risco**, **Regras**, **Allowlist / Blocklist** e **Firewall**.
- **Testes (`tests/test_core.cpp`)**:
  - Novo teste `testIntelligenceAndSecurityEngine`, verificação de `schemaVersion:6` e cobertura HTTP/RBAC/CSRF/`confirm:true` dos endpoints Fase 7 em `testLiveSecurityHttpAndWsIntegration`.

## [1.9.0] - 2026-11-18 — Fase 6: Mapa de Topologia LAN

### Adicionado
- Builder determinístico `buildLanTopology` / `serializeLanTopologyJson` (`src/discovery/topology_builder.*`) correlacionando interfaces de rede, gateways/rotas padrão, servidores DNS, dispositivos LAN via ARP/sub-rede, sondagens do Quality Engine e sessões socket TCP/UDP ativas com evidência técnica explícita por aresta (`local_nic`, `default_route`, `dns_config`, `arp_subnet`, `active_socket`).
- Getters thread-safe de snapshot em `InterfaceMonitor`, `DiscoveryEngine` e `NetworkQualityEngine`.
- Endpoint `GET /api/topology/lan` (`GET /api/v1/topology/lan`, perfil `Viewer+`).
- Módulo visual Canvas2D independente `static/lan-topo.js` (`LanTopologyCanvas`) com pan, zoom, layout em camadas hierárquicas + grid escalável para grandes redes `/24`, filtros (`Infra + Ativos`, `Todos Online`, `Todos`), destaque de busca e inspetor lateral de nós/evidências (`#topologyModal` / botão `🕸 Topologia`).
- Teste `testLanTopologyBuilder` + integração HTTP `/api/v1/topology/lan` em `tests/test_core.cpp`.

## [1.8.0] - 2026-11-18 — Fase 5: Discovery Engine

### Adicionado
- Módulo `DiscoveryEngine` (`src/discovery/discovery_engine.*`) com coleta passiva (`GetIpNetTable` no Windows; `/proc/net/arp` no Linux) e varredura ativa `/24` limitada com pool de 24 workers (`SendARP` L2 no Windows, TCP SYN no Linux, portas comuns `{80,443,22,445,53,3389,554,9100}` e rDNS `getnameinfo`).
- Tabela IEEE OUI offline embutida + detecção de MAC randomizado/LAA (`isLocallyAdministeredMac`, `lookupOuiVendor`) e classificação determinística de tipo (`inferDeviceType`: Roteador/Gateway, Estação Local, Impressora, Câmera/NVR, Máquina Virtual, Servidor/NAS, IoT, Estação, Dispositivo Móvel).
- Migration v5 no SQLite (`lan_devices`) com persistência de primeira/última visualização, contagem `seen_count`, rótulos personalizados (`custom_label`), retenção de offline não rotulados e evento `new_lan_device` em `HistoryStore`.
- Endpoints `GET /api/discovery/devices` (`Viewer+`), `POST /api/discovery/scan`, `POST /api/discovery/label` e `POST /api/discovery/devices/delete` / `DELETE /api/discovery/devices` (`Operator+` com `"confirm": true` + auditoria).
- Modal `#discoveryModal` (`🛰 Dispositivos`) na Web UI com KPIs LAN, filtros (`Online`/`Offline`/`Gateways`), edição de rótulo, remoção confirmada e disparo de varredura `/24`.
- Teste `testDiscoveryEngineAndOui` + integração HTTP/RBAC `/api/v1/discovery/*` em `tests/test_core.cpp`.

## [1.7.0] - 2026-11-18 — Fase 4: Multi-WAN e Interfaces de Rede

### Adicionado
- Módulo `InterfaceMonitor` (`src/network/interface_monitor.*`) com inventário completo Ethernet/Wi-Fi/VPN/Virtual/Tunnel/Loopback (`GetAdaptersAddresses` + `GetIfTable2` + `GetBestInterface` no Windows; `/proc/net/dev` + `getifaddrs` + `/proc/net/route` + `/sys/class/net` no Linux).
- Métricas individuais por interface (`rxBps`, `txBps`, `rxPps`, `txPps`, `rxBytes`, `txBytes`, `rxErrors`, `txErrors`, `rxDiscards`, `txDiscards`, link speed, MTU, MAC, IPv4/IPv6, gateways, DNS) e detecção de transições Multi-WAN (`wan_primary_changed`, `interface_down`, `interface_up`).
- Migration v4 no SQLite (`interface_samples`) com gravação em lote a cada 10s e consulta histórica (`15m`, `1h`, `24h`, `7d`) em `HistoryStore`.
- Endpoints `GET /api/interfaces`, `GET /api/interfaces/history` (`Viewer+`) e `POST /api/interfaces/refresh` (`Operator+`).
- Modal `#interfacesModal` (`🔌 Interfaces`) na Web UI com KPIs Multi-WAN, gráfico Canvas2D RX/TX por interface e filtros por tipo/estado.
- Teste `testMultiWanAndInterfaces` + integração HTTP/RBAC `/api/v1/interfaces*` em `tests/test_core.cpp`.

## [1.6.0] - 2026-11-18 — Fase 3: Traceroute Avançado

### Adicionado
- Migration v3 no SQLite (`src/storage/sqlite_db.cpp`): tabelas `trace_runs`, `trace_hops` (com rDNS, ASN e GeoIP) e `trace_monitors` integradas à retenção em `HistoryStore`.
- Fingerprinting determinístico de caminho (`computeTracePathHash`, FNV-1a 64-bit por TTL:IP), algoritmo de comparação lado a lado (`computeTraceRouteDiff` / `serializeTraceDiffJson`) e detecção automática de mudança de rota (`changedFromPrev` + evento `route_changed`) em `src/traceroute.*`.
- Agendador periódico desacoplado (`TracerouteService::schedulerLoop`) para alvos configuráveis (`30..3600s`) sem interferir no traceroute interativo.
- Endpoints em `ApiRouter`: `GET /api/trace/history`, `GET /api/trace/diff`, `GET/POST /api/trace/monitors` e `POST /api/trace/monitors/delete` / `DELETE /api/trace/monitors` (Operator+ com `"confirm": true` e auditoria).
- Modal `#traceModal` (`🧭 Rotas`) na Web UI com execuções salvas, seleção `A → B` de Route Diff por TTL e gerenciamento de monitores periódicos, além de exibição de ASN e atalho `Histórico` no inspetor lateral.
- Teste `testTracerouteHistoryAndRouteDiff` e integração HTTP/RBAC em `tests/test_core.cpp`.

## [1.5.0] - 2026-11-18 — Fase 2: Network Quality Engine

### Adicionado
- Módulo `NetworkQualityEngine` (`src/quality/network_quality_engine.*`) com descoberta automática de gateway local e DNS do provedor (`GetAdaptersAddresses` no Windows; `/proc/net/route` e `/etc/resolv.conf` no Linux) + alvos padrão (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `github.com`, `www.microsoft.com`) e destinos personalizados.
- Sondagem contínua sem invocação de shell (`icmp` via `IcmpSendEcho` no Windows ou `IPPROTO_ICMP` datagram com fallback TCP no Linux, `tcp` connect não-bloqueante e `dns_udp` RFC-1035 para medição real de resolução DNS).
- Cálculo determinístico de métricas (`computeQualityMetrics`): atual, mínimo, máximo, média, percentis `P50`, `P90`, `P95`, `P99`, jitter (diferença absoluta consecutiva), perda de pacotes `%`, disponibilidade `%`, tempo de DNS e contagem de transições (flaps).
- Diagnóstico determinístico (`diagnoseNetworkQuality`) diferenciando explicitamente **Fatos Observados** de **Hipóteses**, cobrindo: `gateway_unreachable`, `gateway_icmp_filtered`, `dns_unreachable`, `external_unreachable`, `high_latency`, `latency_oscillation`, `packet_loss`, `frequent_interruptions`, `progressive_degradation` e `all_checks_nominal`.
- Migration v2 em `src/storage/sqlite_db.cpp` (`quality_targets`, `quality_samples` e índices) integrada ao escritor em lote assíncrono e retenção em `HistoryStore`.
- APIs em `ApiRouter`: `GET /api/quality/status`, `GET /api/quality/history?targetId=...&range=15m|1h|24h|7d`, `POST /api/quality/probe`, `POST /api/quality/rediscover`, `POST /api/quality/targets`, `POST /api/quality/targets/update`, `POST /api/quality/targets/delete` / `DELETE /api/quality/targets` (Operator+ com confirmação explícita e auditoria).
- Modal `#qualityModal` na Web UI com gráfico Canvas2D (`15m`, `1h`, `24h`, `7d`), diagnósticos e gestão de destinos.
- Teste `testNetworkQualityMathAndDiagnosis` + extensão HTTP/RBAC em `tests/test_core.cpp`.

## [1.4.0] - 2026-11-18 — Fase 1: Histórico e Analytics (SQLite WAL)

### Adicionado
- SQLite 3.54.1 amalgamation vendored em `third_party/sqlite/` (`sqlite3.c`, `sqlite3.h`) sem dependências externas.
- Camada de persistência `SqliteDb` e `SqliteStmt` (`src/storage/sqlite_db.*`) com `PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `auto_vacuum = INCREMENTAL`, `busy_timeout = 5000`, `PRAGMA quick_check(1)`, checkpoint/vacuum e migrations versionadas (`schema_migrations` v1).
- Modelo relacional em `data/netpulse.db`: tabelas `events`, `service_metrics`, `connection_history`, `traffic_rollups` e `nic_traffic_samples` com índices B-Tree.
- Migração automática idempotente de dados legados (`events_history.tsv` e `service_metrics.tsv`, protegida por marcador `.tsv_imported_v1`).
- Escritor assíncrono dedicado (`HistoryStore::writerThread_`) com transações em lote (flush a cada 2s ou >=128 itens) para não bloquear o `pollThread`.
- Novos endpoints em `ApiRouter`: `GET /api/history/connections` (filtros + paginação), `GET /api/history/processes`, `GET /api/history/analytics` (rankings Top 10 de aplicações, destinos e países + série diária RX/TX), `GET /api/history/storage` e `POST /api/history/prune` (Administrator + `"confirm": true` + auditoria).
- Filtros `offset`, `severity` e `kind` em `GET /api/history/events`.
- Configurações de retenção em `SettingsStore` e `/api/settings`: `retentionDays` (`1..365`, presets UI `1`/`7`/`30`/`90`/personalizado) e `maxDbSizeMb` (`32..2048`).
- Modal `#analyticsModal` (`static/index.html`, `static/styles.css`, `static/app.js`) com gráfico Canvas2D diário RX/TX, Top-10 rankings, busca paginada de conexões, histórico de aplicações e diagnóstico/limpeza do banco SQLite.
- Documentação em `DATABASE.md` e suíte ampliada para 14 testes + benchmark em `tests/test_core.cpp`.

## [1.3.0] - 2026-11-18 — Fase 0: Auditoria Completa & Segurança (Prioridade Zero)

### Adicionado
- Parser JSON estrito RFC-8259 (`src/core/json_lite.*`) com limite de profundidade e payload.
- Motor de Autenticação e RBAC (`src/security/auth_manager.*`) com perfis `Viewer`, `Operator` e `Administrator`, tokens com hash salted SHA-256, expiração e revogação de sessões.
- Proteção CSRF (`X-CSRF-Token` + `HttpOnly; SameSite=Strict`) e tickets efêmeros de uso único para WebSocket (`/api/auth/ws-ticket`).
- Camada TLS nativa multiplataforma (`src/security/tls_context.*`): SChannel no Windows e OpenSSL no Linux.
- Rate limiting por IP (`src/security/rate_limiter.*`) com proteção contra brute-force no login.
- Log de auditoria operacional (`src/security/audit_log.*`) persistido em `data/security_audit.tsv` e endpoint `/api/security/audit`.
- Reversão de bloqueio de firewall (`POST /api/action/unblock-ip` e `GET /api/security/blocks`) com confirmação explícita (`"confirm": true`).
- Roteador central `/api/*` e `/api/v1/*` (`src/api/api_router.*`).
- UI de login, badge de perfil RBAC, modal de Central de Segurança (tokens, bloqueios reversíveis e log de auditoria).
- `CMakeLists.txt` multiplataforma e suíte de testes de segurança e integração HTTP/WS em `tests/test_core.cpp`.
- Documentação inicial: `ARCHITECTURE.md`, `ROADMAP.md`, `SECURITY.md`, `CHANGELOG.md`.

### Alterado / Corrigido
- Removido `Access-Control-Allow-Origin: *` de `WsServer`; adicionada validação estrita de `Host` (anti-DNS rebinding) e `Origin` (anti-CSRF/CSWSH).
- Corrigido risco de path traversal em `WsServer` com decodificação URL + validação via `std::filesystem::weakly_canonical`.
- Substituído `popen` em `src/traceroute.cpp` (Linux) por `fork` + `execlp` sem invocação de shell.
- Endurecido `src/updater.cpp` para exigir `checksums.txt` e validação de URL HTTPS oficial do GitHub (fail-closed).
- Exigido `--allow-remote` / `NETPULSE_ALLOW_REMOTE=1` para binds não-loopback em `src/main.cpp` com TLS automático.
- Expandida proteção de processos críticos do sistema em `src/actions.cpp`.
