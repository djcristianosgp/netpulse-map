# NetPulse 2D — Mapa Planetário de Conexões de Rede em Tempo Real

Aplicação local de altíssimo desempenho com motor nativo em **C++20 (`/O2`)** integrado diretamente às APIs do Kernel do Windows (`iphlpapi.dll` / `WinHTTP` / `Winsock2`) e interface interativa acelerada por hardware em **HTML5 Canvas2D** exibindo **o planeta completo** em tempo real.

## Por que C++20?
- **Leitura direta de sockets do kernel (`GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfTable2`)** em menos de `1 ms` por ciclo (sem spawn de `netstat` ou PowerShell).
- **Zero garbage collector e consumo mínimo** (~4–8 MB RAM no daemon nativo).
- **Thread pool assíncrono** para resolução GeoIP em lote (`ip-api.com/batch` com cache persistente em `data/geoip_cache.tsv`) e Reverse DNS (`getnameinfo`).
- **Servidor HTTP + WebSocket RFC-6455 nativo em Winsock2** sem dependências externas ou `node_modules`.

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
- [ARCHITECTURE.md](ARCHITECTURE.md) · [ROADMAP.md](ROADMAP.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

### Recompilar (MSVC C++20)
```bat
cd tools\netpulse-map
build.bat
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
- **Atalhos**: `Espaço` pausa/retoma o stream · `F` foca a busca · `R` reseta a visão do planeta · `Esc` limpa seleção.
