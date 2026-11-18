# NetPulse Platform (`v2.0.0`) — Observabilidade, Diagnóstico & Segurança de Redes

Plataforma nativa multiplataforma (Windows & Linux) de alta performance escrita em **C++20 (`/O2`)** com persistência em **SQLite WAL**, servidor HTTP/HTTPS/WebSocket RFC-6455 embutido e interface Web modular **HTML5 Canvas2D** — **100% determinística, offline-capable e zero IA/LLMs**.

## Os 12 Módulos + Modo NOC
1. **Mapa Global 2D** — Projeções Natural Earth / Equirectangular / Mercator, arcos geodésicos e terminador solar Dia/Noite.
2. **Conexões Ativas** — Sockets TCP/UDP IPv4/IPv6 via APIs diretas do kernel (`iphlpapi.dll` / `/proc/net`), PID e estado em `< 1 ms`.
3. **Consumo & Processos** — RX/TX em tempo real por executável (EStats / Process IO) e histórico evolutivo.
4. **Países & GeoIP** — Identificação GeoIP/ASN offline (MaxMind `.mmdb`) e cache assíncrono em lote + rDNS.
5. **Serviços & Sonda TCP** — Âncoras continentais e endpoints customizados monitorados continuamente.
6. **Network Quality Engine** — Gateway local, DNS do provedor e alvos ICMP/TCP/DNS (RFC-1035), percentis P50/P90/P95/P99, jitter, packet loss e diagnóstico determinístico.
7. **Traceroute Avançado & Route Diff** — Histórico salto a salto com rDNS/ASN/GeoIP, fingerprinting FNV-1a e monitoramento agendado.
8. **Multi-WAN & Interfaces** — Inventário Ethernet/Wi-Fi/VPN/Virtual, gateways, RX/TX/erros por link e failover Multi-WAN.
9. **Discovery LAN** — Descoberta passiva ARP e varredura ativa `/24`, fabricantes IEEE OUI offline, detecção de MAC randomizado/LAA e portas.
10. **Topologia LAN** — Grafo interativo Canvas2D independente (`static/lan-topo.js`) com evidência técnica por aresta.
11. **Intelligence Determinística & Security Engine** — 9 detectores comportamentais, baselines EWMA, índice de risco transparente (0–100), regras customizáveis, Allowlist/Blocklist e regras granulares de firewall (`netsh advfirewall`).
12. **Histórico & Analytics SQLite WAL** — Top 10 aplicações/destinos/países, séries RX/TX e retenção configurável (`1–365` dias).

Além de: **Modo NOC TV Fullscreen Somente Leitura (`?noc=1`)**, **Exportador Prometheus `/metrics`**, **API v1 OpenAPI 3.0.3 (`/api/v1/openapi.json`)** e **Notificações Externas** (Webhook HMAC-SHA256, Discord, Telegram).

## Por que C++20?
- **Leitura direta de sockets e interfaces do kernel (`GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfTable2`, `/proc/net/*`)** em poucos milissegundos por ciclo.
- **Zero garbage collector**, baixo consumo de memória e **SQLite 3.54.1 WAL** embutido em thread escritora assíncrona.
- **Servidor HTTP/HTTPS + WebSocket RFC-6455 nativo** (Winsock2/SChannel no Windows; POSIX/OpenSSL no Linux).

## Como Compilar e Executar

### Executar (binário já compilado)
```bat
cd tools\netpulse-map
build\netpulse.exe
```
Ou dê duplo clique em `run.bat` (abre automaticamente em janela dedicada `--app` sem barras de navegador).

Opções de linha de comando:
- `--port 8740`: define a porta local (padrão `8740`)
- `--host 127.0.0.1`: define o endereço de bind (padrão `127.0.0.1`)
- `--allow-remote`: obrigatório para binds não-loopback (ou `NETPULSE_ALLOW_REMOTE=1`); ativa TLS automaticamente
- `--tls` / `--tls-cert` / `--tls-key` / `--behind-tls-proxy`: controle explícito de TLS (SChannel/OpenSSL)
- `--interval 1000`: intervalo de leitura em milissegundos (`100` a `5000`, padrão `1000`)
- `--no-browser`: inicia apenas o servidor sem abrir janela
- `--browser-tab`: abre em aba normal do navegador padrão em vez de janela `--app`

Documentação adicional:
- [ARCHITECTURE.md](ARCHITECTURE.md) · [DATABASE.md](DATABASE.md) · [ROADMAP.md](ROADMAP.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

### Recompilar (Windows MSVC C++20 / Linux CMake)
```bat
cd tools\netpulse-map
build.bat 2.0.0
```
Linux / CI:
```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
ctest --test-dir build-linux --output-on-failure
```

### Executar Testes Nativos C++
```bat
cd tools\netpulse-map
build\test_core.exe
```

## Gerar Instalador e Release Automática por Tag no GitHub
O workflow [.github/workflows/release.yml](.github/workflows/release.yml) gera automaticamente o instalador **Inno Setup 6** (`NetPulse2D-Setup-x64.exe`), o pacote portátil (`NetPulse2D-Portable-x64.zip`) e os hashes (`checksums.txt`) em **GitHub Releases** sempre que uma tag `v*` é enviada:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Para gerar o pacote localmente via PowerShell (com Inno Setup 6 instalado):
```powershell
.\packaging\build-installer.ps1 -Version "1.0.0"
```

## Interações com o Mapa 2D
- **Planeta Completo**: visualiza todos os continentes e 177 países (`assets/countries-110m.json` offline) em 3 projeções alternáveis (**Natural Earth**, **Equirectangular**, **Mercator**).
- **Pan & Zoom**: arraste com o mouse para mover; role a roda do mouse para zoom centrado no cursor; duplo clique para aproximar; `R` ou botão **Planeta** para reajustar o planeta inteiro.
- **Hover e Clique em Países**: passe o mouse sobre qualquer país para ver conexões ativas; clique para filtrar e inspecionar.
- **Nós, Arcos Geodésicos e Pulsos**: clique em qualquer nó ou linha da lista para voar até a coordenada no mapa e inspecionar IP, domínio (PTR), ISP/ASN, processo, PID, portas e duração.
- **Atalhos**: `M` abre os 12 Módulos · `N` abre o Modo NOC TV · `Espaço` pausa/retoma stream · `F` foca a busca · `R` reseta a visão do planeta · `Esc` fecha modais/NOC/seleção.
