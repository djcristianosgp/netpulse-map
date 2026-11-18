# NetPulse — Fontes de Dados Orbitais (Satellite Tracking V1)

## 1. Objetos Monitorados na V1

| Objeto | Nome Canônico | NORAD Catalog ID | Designador Internacional (COSPAR) | Categoria |
| :--- | :--- | :--- | :--- | :--- |
| **ISS** | Estação Espacial Internacional (`ISS (ZARYA)`) | `25544` | `1998-067A` | Estação Espacial (LEO) |
| **Tiangong** | Estação Espacial Chinesa (`CSS (TIANHE)`) | `48274` | `2021-035A` | Estação Espacial (LEO) |

---

## 2. Fontes Públicas Utilizadas

### 2.1 Fonte Primária — CelesTrak GP OMM (JSON)
- **URL em lote (estações espaciais)**:  
  `https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=json`
- **URL individual (fallback por catálogo NORAD)**:  
  `https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=json`  
  `https://celestrak.org/NORAD/elements/gp.php?CATNR=48274&FORMAT=json`
- **Formato**: CCSDS Orbit Mean-Messages (OMM) serializado em JSON.
- **Campos utilizados**: `OBJECT_NAME`, `OBJECT_ID`, `EPOCH`, `MEAN_MOTION`, `ECCENTRICITY`, `INCLINATION`, `RA_OF_ASC_NODE`, `ARG_OF_PERICENTER`, `MEAN_ANOMALY`, `EPHEMERIS_TYPE`, `CLASSIFICATION_TYPE`, `NORAD_CAT_ID`, `ELEMENT_SET_NO`, `REV_AT_EPOCH`, `BSTAR`, `MEAN_MOTION_DOT`, `MEAN_MOTION_DDOT`.

### 2.2 Fonte Secundária / Fallback — CelesTrak GP TLE
- **URL individual TLE**:  
  `https://celestrak.org/NORAD/elements/gp.php?CATNR=<NORAD_ID>&FORMAT=tle`
- **Formato**: Two-Line Element Set (3 linhas com nome + linha 1 + linha 2).
- **Validação**: Comprimento mínimo de 68 caracteres, identificação de linha (`1` / `2`), correspondência de NORAD ID entre as linhas e verificação obrigatória do **checksum Módulo-10** em ambas as linhas.

---

## 3. Política de Cache, Atualização e Confiabilidade

1. **Elementos orbitais não são telemetria instantânea**:
   - OMM/TLE representam elementos médios ajustados por observações em uma época (`EPOCH`). A posição em tempo real é calculada localmente via propagação SGP4 a partir da época armazenada.
2. **Cache Local Persistente**:
   - Armazenado em `data/satellite_catalog_cache.json`.
   - Carregado imediatamente na inicialização do NetPulse para operação instantânea e capacidade offline.
3. **Prevenção de Downloads Repetidos**:
   - Intervalo padrão de atualização automática do catálogo: **6 horas (`21.600 s`)**, configurável entre `900 s` (15 min) e `86.400 s` (24 h).
   - Se o cache em disco ainda estiver dentro da janela de validade no boot, **nenhuma requisição externa** é feita ao CelesTrak.
   - Requisições manuais (`POST /api/satellites/refresh`) aplicam cooldown mínimo de proteção para evitar sobrecarga na fonte pública.
4. **Resiliência a Falhas de Conexão**:
   - Comunicação exclusivamente via **HTTPS** (WinHTTP no Windows; OpenSSL com verificação de certificado `SSL_VERIFY_PEER` + SNI no Linux).
   - Timeout de conexão/leitura e até 2 tentativas controladas em caso de erro transitório.
   - Em caso de falha de rede, HTTP != 200 ou payload inválido, **o último conjunto válido em cache nunca é descartado**; o estado passa a indicar `cached_fallback` com o detalhe do erro, mantendo a propagação contínua.
   - Falhas no módulo orbital nunca bloqueiam o monitoramento de conexões de rede ou a interface do NetPulse.

---

## 4. Validação de Integridade dos Elementos

Antes de aceitar qualquer registro OMM ou TLE:
- Limite máximo de tamanho de resposta (`1 MB`) e parsing estrito (JSON RFC-8259 / formato TLE com checksum Mod-10).
- `noradId > 0` correspondente a um objeto monitorado válido.
- Todos os parâmetros numéricos finitos (`std::isfinite`).
- `0.0 <= eccentricity < 1.0` (órbita fechada elíptica/circular compatível com SGP4).
- `0.0 <= inclinationDeg <= 180.0`.
- `meanMotionRevDay > 0.0` e `<= 25.0` (sanidade para órbitas terrestres).
- `EPOCH` válido e conversível para Julian Date UTC.
