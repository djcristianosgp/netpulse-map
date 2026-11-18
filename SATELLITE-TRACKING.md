# NetPulse — Satellite Tracking V1 (Guia de Uso & Especificação Operacional)

## 1. Visão Geral

O módulo **Satellite Tracking V1** adiciona ao mapa cartográfico 2D do NetPulse a visualização em tempo real de objetos espaciais em órbita terrestre baixa (LEO), operando de forma **100% independente do monitoramento de conexões de rede** e **sem inteligência artificial**.

### Objetos Suportados na V1
- **ISS — Estação Espacial Internacional** (`NORAD 25544` · `1998-067A`)
- **Tiangong — Estação Espacial Chinesa / CSS** (`NORAD 48274` · `2021-035A`)

---

## 2. Como Utilizar

1. **Abrir o Painel Lateral "Objetos orbitais"**:
   - Clique no botão **`🛰 Órbitas`** na barra superior do NetPulse, pressione a tecla **`S`** ou selecione **Satellite Tracking (Objetos Orbitais)** no menu **`⊞ 12 Módulos`** (`M`).
2. **Ativar / Desativar a Camada e Objetos**:
   - Use o switch **Camada Satellite Tracking** para ligar ou suspender completamente o módulo.
   - Use os checkboxes individuais para exibir ou ocultar **ISS** e **Tiangong**, ou utilize **Selecionar todos** / **Desmarcar todos**.
3. **Visualização no Mapa**:
   - **Marcador orbital**: ícone de estação espacial com halo luminoso e identificação de nome + altitude (`ISS · 418 km` / `Tiangong · 392 km`).
   - **Trajetória percorrida**: trilha contínua translúcida dos últimos 45 minutos.
   - **Projeção futura**: linha tracejada animada configurável para `45 min`, `90 min` (1 órbita) ou `180 min` (2 órbitas), com corte automático no antimeridiano (`±180°`).
   - **Projeções suportadas**: `Natural Earth`, `Equirectangular` e `Mercator`.
4. **Ficha Técnica de Informações**:
   - Clique em qualquer satélite na lista do painel **Objetos orbitais** ou diretamente no marcador no mapa para inspecionar:
     - **Nome**, **Identificador (NORAD / COSPAR)** e **Categoria**
     - **Altitude (km)**, **Velocidade orbital (km/s e km/h)** e **Inclinação (°)**
     - **Posição atual (Latitude / Longitude)** e **Período orbital (min)**
     - **Última atualização dos elementos orbitais** (época UTC + timestamp de coleta)
     - **Estado da atualização dos dados** (`Ao vivo (CelesTrak)`, `Cache local`, `Cache (falha de rede)` ou `Indisponível`)

---

## 3. Configurações Persistentes

As preferências são salvas em `data/satellite_settings.tsv`:
- **Ativação geral do módulo** (`enabled`)
- **Satélites visíveis** (`visibleNoradIds`)
- **Exibição de trajetória** (`showTrajectory`)
- **Extensão da trajetória futura** (`futureTrackMinutes`: `10..360` min, padrão `90`)
- **Frequência de cálculo/atualização visual** (`positionIntervalMs`: `500..30000` ms, padrão `2000`)
- **Intervalo de atualização do catálogo orbital** (`catalogRefreshSec`: `900..86400` s, padrão `21600` = 6h)

Quando a camada está desativada ou nenhum satélite está marcado, o serviço `SatellitePositionService` entra em **suspensão imediata**, zerando o consumo de CPU da propagação SGP4.

---

## 4. Dependências, Precisão & Limitações Conhecidas

### Dependências
- **Zero bibliotecas externas adicionais**: propagador SGP4 (Vallado AIAA-2006-6753, constantes WGS-72) e conversões TEME → GMST → WGS-84 implementados nativamente em **C++20** (`src/satellite/orbital_propagator.*`).
- Transporte HTTPS nativo utilizando **WinHTTP** (Windows) e **OpenSSL** (Linux), já presentes no NetPulse.

### Precisão
- O modelo SGP4 com elementos GP (OMM/TLE) fornece precisão típica na ordem de **~1 km na época**, degradando gradualmente para alguns quilômetros ao longo de dias devido a variações atmosféricas em órbita baixa (LEO) e manobras de reboost da ISS/Tiangong.
- A conversão TEME → ECEF utiliza GMST (IAU-1982) com `JD_UTC ≈ JD_UT1` ($|DUT1| < 0.9\text{ s}$, diferença inferior a `0.5 km` em solo) sem correção de movimento polar.

### Limitações Conhecidas (V1)
- Suporta órbitas próximas à Terra (Near-Earth SGP4, período `< 225 min`). Órbitas de espaço profundo (MEO/GEO/HEO que requerem SDP4) retornam erro explícito nesta versão.
- Catálogo V1 focado exclusivamente em **ISS (`25544`)** e **Tiangong (`48274`)**; adição dinâmica de novos NORAD IDs pela interface ficará para versões futuras.
- Em primeira execução completamente sem internet e sem `data/satellite_catalog_cache.json` prévio, os objetos permanecem listados com estado `Indisponível` até a primeira obtenção bem-sucedida de elementos orbitais.

---

## 5. Documentação Relacionada
- [SATELLITE-ARCHITECTURE.md](SATELLITE-ARCHITECTURE.md) — Auditoria, arquitetura modular e convenções matemáticas (UTC, TEME, WGS-84, antimeridiano).
- [SATELLITE-DATA-SOURCES.md](SATELLITE-DATA-SOURCES.md) — Endpoints CelesTrak OMM/TLE, validação, cache e resiliência.
