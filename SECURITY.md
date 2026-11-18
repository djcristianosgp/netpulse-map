# NetPulse — Política e Arquitetura de Segurança

## 1. Princípios Padrão (Secure by Default)

- **Bind padrão em `127.0.0.1:8740`**: o servidor nunca escuta em interfaces externas implicitamente.
- **Exposição remota explícita**: `--host 0.0.0.0` (ou qualquer IP não-loopback) exige `--allow-remote` ou `NETPULSE_ALLOW_REMOTE=1` e falha fechado (exit code `2`) caso contrário.
- **TLS automático em acesso remoto**: ao habilitar bind remoto sem `--behind-tls-proxy`, o motor ativa TLS nativo (SChannel no Windows / OpenSSL no Linux) usando `--tls-cert`/`--tls-key` ou certificado autoassinado em `data/tls/`.
- **Sem CORS irrestrito**: removido `Access-Control-Allow-Origin: *`. Requisições com `Origin` divergente ou `Host` não autorizado recebem `403 Forbidden`.

## 2. Autenticação e RBAC

| Nível (`Role`) | Capacidades |
| :--- | :--- |
| **`viewer`** | Somente leitura: snapshots, histórico, serviços, status de traceroute, auditoria e bloqueios. |
| **`operator`** | Operações não destrutivas: adicionar/remover serviços, probes manuais, traceroute, alternar alertas, checar updates. |
| **`administrator`** | Operações administrativas e destrutivas: configurações, encerrar PID, bloquear/reverter IP no firewall, elevação UAC, aplicar update, gerenciar tokens RBAC. |

### Armazenamento de Credenciais
- Tokens de API (`np_adm_...`, `np_opr_...`, `np_vwr_...`) nunca são armazenados em texto plano após emissão: `data/auth_tokens.tsv` guarda apenas `salt` aleatório (CSPRNG) e hash iterativo SHA-256 (4096 rodadas), comparados em tempo constante.
- No primeiro boot sem `NETPULSE_ADMIN_TOKEN`, um token inicial é gravado em `data/initial_admin_token.txt`.
- A janela desktop local (`--app`) utiliza um `nonce` efêmero de uso único (`/?boot=...`) trocado via `POST /api/auth/exchange` (restrito a loopback) por cookie `HttpOnly; SameSite=Strict`.

## 3. Proteções Adicionais

- **CSRF**: todas as requisições mutáveis autenticadas por cookie exigem cabeçalho `X-CSRF-Token` correspondente à sessão.
- **Confirmação Explícita**: ações destrutivas (encerrar processo, bloqueio/reversão de IP, firewall granular, remoção de regras/alvos/dispositivos/canais, prune manual do banco) exigem `"confirm": true` no JSON validado por `JsonValue`.
- **Reversão**: bloqueios de IP (`POST /api/action/unblock-ip`, `data/blocked_ips.tsv`) e regras granulares de firewall por IP/porta/executável (`POST /api/security/firewall/delete` + `removeOsFirewallRule`) são auditados e reversíveis em tempo de execução.
- **Notificações & Segredos**: endpoints externos em `NotificationEngine` exigem `https://` para destinos remotos (`http://` permitido apenas em loopback local), assinam webhooks com HMAC-SHA256 (`X-NetPulse-Signature`) e mascaram segredos/tokens (`secretPreview`) em todas as respostas GET.
- **Exportador `/metrics` & NOC**: Prometheus `/metrics`, `/api/v1/openapi.json` e `/api/v1/noc/overview` exigem autenticação (`Viewer+`); o Modo NOC TV opera estritamente em modo somente leitura sem controles de mutação.
- **Rate Limiting**: limite por IP na camada HTTP e bloqueio temporário contra brute force em `/api/auth/login`.
- **Path Traversal & Command Injection**: canonicalização estrita de caminhos em `static/` e `assets/`; `traceroute` no Linux via `fork`/`execlp` sem shell; updater com verificação SHA-256 obrigatória (fail-closed) e URLs restritas ao GitHub oficial.
