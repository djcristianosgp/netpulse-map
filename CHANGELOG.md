# Changelog

Todas as mudanças relevantes do **NetPulse** serão documentadas neste arquivo.

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
