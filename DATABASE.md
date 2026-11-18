# NetPulse — Persistência SQLite WAL & Modelo de Dados

Este documento detalha a arquitetura de persistência histórica introduzida na **Fase 1 (v1.4.0)** em substituição ao armazenamento baseado apenas em TSV em memória.

---

## 1. Avaliação: TSV vs. SQLite3 WAL

| Critério | TSV Legado (`events_history.tsv` / `service_metrics.tsv`) | SQLite3 Amalgamation 3.54.1 (`WAL`) |
| :--- | :--- | :--- |
| **Consultas filtradas e paginação** | Scan linear O(n) em memória / truncamento fixo (150 eventos, 60 pontos) | Índices B-Tree por timestamp, processo, IP remoto e país (`LIMIT/OFFSET`) |
| **Escrita em disco durante polling** | Append direto síncrono por evento ou reescrita de arquivo | Fila em memória drenada assincronamente em `writerThread_` (lotes a cada 2s ou 128 itens) |
| **Consistência em crash** | Risco de linha truncada sem atomicidade | Transações ACID + Write-Ahead Logging (`PRAGMA journal_mode = WAL`) |
| **Dependências externas** | Nenhuma | Nenhuma — amalgamation C vendored em `third_party/sqlite/` (zero runtime externo) |
| **Migração de dados existentes** | — | Importação automática e idempotente (`events_history.tsv`, `service_metrics.tsv`) protegida por marcador `.tsv_imported_v1` |

---

## 2. Configuração do Motor SQLite (`src/storage/sqlite_db.*`)

Ao abrir `data/netpulse.db`, o wrapper `SqliteDb` aplica:

- `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX`
- `sqlite3_busy_timeout(db_, 5000)`
- `PRAGMA auto_vacuum = INCREMENTAL;`
- `PRAGMA journal_mode = WAL;`
- `PRAGMA synchronous = NORMAL;`
- `PRAGMA foreign_keys = ON;`
- `PRAGMA temp_store = MEMORY;`
- `PRAGMA cache_size = -8000;` (~8 MB de page cache)

Integridade na abertura/inspeção é validada com `PRAGMA quick_check(1);` (`SqliteDb::quickCheckOk()`), e o encerramento seguro executa `sqlite3_wal_checkpoint_v2(..., SQLITE_CHECKPOINT_TRUNCATE, ...)` seguido de `sqlite3_close_v2`.

---

## 3. Schema Versionado (`schema_migrations` — v1)

### `schema_migrations`
```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at_ms INTEGER NOT NULL
);
```

### `events`
Armazena alertas e ações manuais com índices `idx_events_ts(ts_ms DESC)` e `idx_events_kind_ts(kind, ts_ms DESC)`:
- `id`, `ts_ms`, `severity`, `kind`, `title`, `detail`

### `service_metrics`
Armazena séries de disponibilidade e latência de serviços monitorados (`idx_svc_metrics_sid_ts`, `idx_svc_metrics_ts`):
- `id`, `ts_ms`, `service_id`, `status`, `latency_ms`

### `connection_history`
Ciclo de vida completo de conexões TCP/UDP (`UNIQUE(conn_key, started_at_ms)`):
- `id`, `conn_key`, `process_name`, `pid`, `exe_path`, `local_ip`, `remote_ip`, `local_port`, `remote_port`, `protocol`, `ip_version`, `state`, `scope`, `started_at_ms`, `ended_at_ms`, `duration_ms`, `country`, `country_code`, `city`, `asn`, `isp`, `dns_name`, `rx_bytes`, `tx_bytes`
- Índices: `idx_conn_started(started_at_ms DESC)`, `idx_conn_proc(process_name, started_at_ms DESC)`, `idx_conn_rip(remote_ip, started_at_ms DESC)`, `idx_conn_cc(country_code, started_at_ms DESC)`.

### `traffic_rollups`
Agregações por bucket de tempo, aplicação e IP remoto (`PRIMARY KEY (bucket_start_ms, process_name, remote_ip)`):
- `bucket_start_ms`, `process_name`, `remote_ip`, `country`, `country_code`, `rx_bytes`, `tx_bytes`, `conn_count`, `total_duration_ms`
- Índices: `idx_rollup_bucket(bucket_start_ms DESC)`, `idx_rollup_proc(process_name, bucket_start_ms DESC)`.

### `nic_traffic_samples`
Amostras agregadas da interface de rede (`PRIMARY KEY (bucket_start_ms)`):
- `bucket_start_ms`, `rx_bytes`, `tx_bytes`, `max_rx_bps`, `max_tx_bps`, `avg_conns`, `sample_count`

### `quality_targets` (Migration v2)
Destinos configuráveis do **Network Quality Engine** (`PRIMARY KEY (id)`):
- `id`, `name`, `host`, `port`, `category` (`gateway` | `isp_dns` | `public_dns` | `known_server` | `custom`), `probe_mode` (`icmp` | `tcp` | `dns`), `interval_sec`, `enabled`, `is_auto`, `created_at_ms`

### `quality_samples` (Migration v2)
Amostras contínuas de latência, jitter e resolução DNS:
- `id`, `ts_ms`, `target_id`, `ok`, `rtt_ms`, `dns_ms`, `jitter_ms`, `method`, `error`
- Índices: `idx_quality_tid_ts(target_id, ts_ms DESC)` e `idx_quality_ts(ts_ms DESC)`.
- Limpeza automática integrada a `applyRetentionLocked()` (`WHERE ts_ms < cutoff`) e controle de teto `maxDbSizeMb`.

### `trace_runs`, `trace_hops` & `trace_monitors` (Migration v3)
Persistência de execuções de traceroute avançado e monitoramento periódico de rotas:
- `trace_runs`: `id`, `target_ip`, `target_label`, `trigger_kind` (`manual` | `scheduled`), `started_at_ms`, `completed_at_ms`, `reached`, `hop_count`, `total_rtt_ms`, `path_hash` (FNV-1a 64-bit), `changed_from_prev`, `error` (`idx_trace_runs_target_ts`, `idx_trace_runs_ts`).
- `trace_hops`: `run_id`, `ttl`, `timed_out`, `ip`, `rtt_ms`, `hostname`, `asn`, `country`, `country_code`, `city`, `lat`, `lon` (`PRIMARY KEY (run_id, ttl)`).
- `trace_monitors`: `target_ip`, `label`, `interval_sec` (`30..3600`), `enabled`, `created_at_ms`, `last_run_ms`.
- Retenção automática remove `trace_runs WHERE started_at_ms < cutoff` e limpa `trace_hops` órfãos.

---

## 4. Pipeline Assíncrono & Política de Retenção (`src/history_store.*`)

1. **Zero bloqueio no loop de coleta**: `HistoryStore::processTelemetry()` e `processServices()` enfileiram deltas em memória protegidos por `queueMutex_` / `cacheMutex_`.
2. **Thread escritora dedicada**: `HistoryStore::writerLoop()` acorda a cada **2.000 ms** ou imediatamente quando a fila atinge **128 registros** (via `std::condition_variable`), gravando tudo em uma única transação SQLite (`BEGIN IMMEDIATE ... COMMIT`).
3. **Retenção configurável**: `retentionDays` (padrões de UI: `1`, `7`, `30`, `90` ou personalizado `1..365` dias) e `maxDbSizeMb` (`32..2048` MB), configuráveis em `/api/settings`.
4. **Limpeza automática e manual**: Prune periódico exclui registros anteriores a `now - retentionDays * 86400000 ms` e, se `netpulse.db` + `-wal` exceder `maxDbSizeMb`, remove lotes dos registros mais antigos seguido de `PRAGMA incremental_vacuum(200);` + `SQLITE_CHECKPOINT_TRUNCATE`. Operação manual exposta via `POST /api/history/prune` (Administrator + `"confirm": true` + auditoria).
