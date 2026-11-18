# NetPulse — Roadmap de Evolução

Este roadmap organiza a evolução incremental da plataforma NetPulse em fases independentes, verificáveis e sem dependências de inteligência artificial.

## Status Geral

| Fase | Escopo | Status |
| :--- | :--- | :--- |
| **Etapa Zero** | Auditoria completa do repositório (arquitetura, segurança, concorrência, desempenho, portabilidade) | ✅ Concluída |
| **Fase 0** | Segurança (RBAC, Tokens/Sessões, CSRF, Origin/Host, TLS, Rate Limit, Auditoria, Hardening & Testes) | ✅ Concluída |
| **Fase 1** | Histórico e Analytics (Avaliação SQLite WAL vs TSV, histórico de conexões/processos, Top-10, retenção) | ✅ Concluída |
| **Fase 2** | Network Quality Engine (Ping contínuo, jitter, packet loss, P50/P90/P95/P99, DNS timing, diagnóstico) | ⏳ Próxima |
| **Fase 3** | Traceroute Avançado (Histórico de rotas, monitoramento periódico, detecção de variação e diff) | ⏳ Planejada |
| **Fase 4** | Multi-WAN e Interfaces de Rede (Inventário Ethernet/Wi-Fi/VPN/Virtual, gateways, DNS, RX/TX por link) | ⏳ Planejada |
| **Fase 5** | Discovery Engine (Descoberta LAN ARP/ICMP/vizinhos, OUI fabricante, inventário de dispositivos) | ⏳ Planejada |
| **Fase 6** | Mapa de Topologia LAN (Grafo interativo independente com evidência técnica de conectividade) | ⏳ Planejada |
| **Fase 7** | Security Engine & Intelligence Determinística (Regras comportamentais, índice de risco, allowlist/blocklist, firewall por app/porta) | ⏳ Planejada |
| **Fase 8** | Dashboard Analytics & Modo NOC (Navegação em 12 módulos + TV fullscreen somente leitura) | ⏳ Planejada |
| **Fase 9** | API v1 Documentada, Prometheus `/metrics` & Notificações (Webhook, Discord, Telegram) | ⏳ Planejada |
| **Fase 10** | Estabilização, Benchmarks, Portabilidade Linux CI, Instalador & Release | ⏳ Planejada |
