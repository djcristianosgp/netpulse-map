# Changelog

Todas as mudanças relevantes do **NetPulse** serão documentadas neste arquivo.

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
