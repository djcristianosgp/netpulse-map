#include "sqlite_db.hpp"

#include <chrono>
#include <utility>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

} // namespace

SqliteStmt::SqliteStmt(sqlite3* db, const char* sql) {
  if (db && sql) {
    if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
      stmt_ = nullptr;
    }
  }
}

SqliteStmt::~SqliteStmt() {
  if (stmt_) {
    sqlite3_finalize(stmt_);
    stmt_ = nullptr;
  }
}

SqliteStmt::SqliteStmt(SqliteStmt&& other) noexcept : stmt_(other.stmt_) {
  other.stmt_ = nullptr;
}

SqliteStmt& SqliteStmt::operator=(SqliteStmt&& other) noexcept {
  if (this != &other) {
    if (stmt_) sqlite3_finalize(stmt_);
    stmt_ = other.stmt_;
    other.stmt_ = nullptr;
  }
  return *this;
}

bool SqliteStmt::bindText(int idx, const std::string& val) {
  return stmt_ && sqlite3_bind_text(stmt_, idx, val.data(), static_cast<int>(val.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool SqliteStmt::bindInt64(int idx, int64_t val) {
  return stmt_ && sqlite3_bind_int64(stmt_, idx, val) == SQLITE_OK;
}

bool SqliteStmt::bindDouble(int idx, double val) {
  return stmt_ && sqlite3_bind_double(stmt_, idx, val) == SQLITE_OK;
}

bool SqliteStmt::stepDone() {
  if (!stmt_) return false;
  int rc = sqlite3_step(stmt_);
  return rc == SQLITE_DONE;
}

int SqliteStmt::step() {
  if (!stmt_) return SQLITE_ERROR;
  return sqlite3_step(stmt_);
}

void SqliteStmt::reset() {
  if (stmt_) {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
  }
}

int64_t SqliteStmt::colInt64(int col) const {
  return stmt_ ? sqlite3_column_int64(stmt_, col) : 0;
}

double SqliteStmt::colDouble(int col) const {
  return stmt_ ? sqlite3_column_double(stmt_, col) : 0.0;
}

std::string SqliteStmt::colText(int col) const {
  if (!stmt_) return {};
  const unsigned char* txt = sqlite3_column_text(stmt_, col);
  int bytes = sqlite3_column_bytes(stmt_, col);
  if (!txt || bytes <= 0) return {};
  return std::string(reinterpret_cast<const char*>(txt), static_cast<size_t>(bytes));
}

SqliteDb::~SqliteDb() {
  close();
}

bool SqliteDb::open(const std::filesystem::path& dbPath, std::string& outError) {
  std::lock_guard lock(mutex_);
  if (db_) {
    sqlite3_close_v2(db_);
    db_ = nullptr;
  }

  path_ = dbPath;
  std::error_code ec;
  if (!dbPath.parent_path().empty()) {
    std::filesystem::create_directories(dbPath.parent_path(), ec);
  }

  const std::string utf8Path = dbPath.u8string().empty()
                                   ? dbPath.string()
                                   : std::string(reinterpret_cast<const char*>(dbPath.u8string().data()),
                                                 dbPath.u8string().size());

  int rc = sqlite3_open_v2(utf8Path.c_str(), &db_,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                           nullptr);
  if (rc != SQLITE_OK || !db_) {
    outError = db_ ? sqlite3_errmsg(db_) : "sqlite3_open_v2 failed";
    if (db_) {
      sqlite3_close_v2(db_);
      db_ = nullptr;
    }
    return false;
  }

  sqlite3_busy_timeout(db_, 5000);
  // auto_vacuum must be set before first table creation; harmless no-op on existing DBs
  execLocked("PRAGMA auto_vacuum = INCREMENTAL;", outError);
  if (!execLocked("PRAGMA journal_mode = WAL;", outError)) return false;
  if (!execLocked("PRAGMA synchronous = NORMAL;", outError)) return false;
  if (!execLocked("PRAGMA foreign_keys = ON;", outError)) return false;
  if (!execLocked("PRAGMA temp_store = MEMORY;", outError)) return false;
  if (!execLocked("PRAGMA cache_size = -8000;", outError)) return false;

  return true;
}

void SqliteDb::close() {
  std::lock_guard lock(mutex_);
  if (db_) {
    sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    sqlite3_close_v2(db_);
    db_ = nullptr;
  }
}

bool SqliteDb::execLocked(const char* sql, std::string& outError) {
  if (!db_) {
    outError = "database_closed";
    return false;
  }
  char* errMsg = nullptr;
  int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
  if (rc != SQLITE_OK) {
    outError = errMsg ? errMsg : sqlite3_errmsg(db_);
    if (errMsg) sqlite3_free(errMsg);
    return false;
  }
  return true;
}

bool SqliteDb::exec(const char* sql, std::string& outError) {
  std::lock_guard lock(mutex_);
  return execLocked(sql, outError);
}

int SqliteDb::currentSchemaVersion() const {
  std::lock_guard lock(mutex_);
  if (!db_) return 0;
  SqliteStmt tblCheck(db_, "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';");
  if (!tblCheck.valid() || tblCheck.step() != SQLITE_ROW) return 0;

  SqliteStmt verStmt(db_, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;");
  if (!verStmt.valid() || verStmt.step() != SQLITE_ROW) return 0;
  return static_cast<int>(verStmt.colInt64(0));
}

bool SqliteDb::runMigrations(std::string& outError) {
  std::lock_guard lock(mutex_);
  if (!db_) {
    outError = "database_closed";
    return false;
  }

  if (!execLocked(
          "CREATE TABLE IF NOT EXISTS schema_migrations ("
          "  version INTEGER PRIMARY KEY,"
          "  name TEXT NOT NULL,"
          "  applied_at_ms INTEGER NOT NULL"
          ");",
          outError)) {
    return false;
  }

  int currentVer = 0;
  {
    SqliteStmt verStmt(db_, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;");
    if (verStmt.valid() && verStmt.step() == SQLITE_ROW) {
      currentVer = static_cast<int>(verStmt.colInt64(0));
    }
  }

  if (currentVer < 1) {
    if (!execLocked("BEGIN IMMEDIATE;", outError)) return false;
    const char* m1 = R"SQL(
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms INTEGER NOT NULL,
        severity TEXT NOT NULL,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts_ms DESC);

      CREATE TABLE IF NOT EXISTS service_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms INTEGER NOT NULL,
        service_id TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms REAL NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_svc_metrics_sid_ts ON service_metrics(service_id, ts_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_svc_metrics_ts ON service_metrics(ts_ms DESC);

      CREATE TABLE IF NOT EXISTS connection_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conn_key TEXT NOT NULL,
        process_name TEXT NOT NULL,
        pid INTEGER NOT NULL,
        exe_path TEXT NOT NULL,
        local_ip TEXT NOT NULL,
        remote_ip TEXT NOT NULL,
        local_port INTEGER NOT NULL,
        remote_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        ip_version INTEGER NOT NULL,
        state TEXT NOT NULL,
        scope TEXT NOT NULL,
        started_at_ms INTEGER NOT NULL,
        ended_at_ms INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        country TEXT NOT NULL DEFAULT '',
        country_code TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        isp TEXT NOT NULL DEFAULT '',
        dns_name TEXT NOT NULL DEFAULT '',
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        UNIQUE(conn_key, started_at_ms)
      );
      CREATE INDEX IF NOT EXISTS idx_conn_started ON connection_history(started_at_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_conn_proc ON connection_history(process_name, started_at_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_conn_rip ON connection_history(remote_ip, started_at_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_conn_cc ON connection_history(country_code, started_at_ms DESC);

      CREATE TABLE IF NOT EXISTS traffic_rollups (
        bucket_start_ms INTEGER NOT NULL,
        process_name TEXT NOT NULL,
        remote_ip TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT '',
        country_code TEXT NOT NULL DEFAULT '',
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        conn_count INTEGER NOT NULL DEFAULT 0,
        total_duration_ms INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start_ms, process_name, remote_ip)
      );
      CREATE INDEX IF NOT EXISTS idx_rollup_bucket ON traffic_rollups(bucket_start_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_rollup_proc ON traffic_rollups(process_name, bucket_start_ms DESC);

      CREATE TABLE IF NOT EXISTS nic_traffic_samples (
        bucket_start_ms INTEGER PRIMARY KEY,
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        max_rx_bps REAL NOT NULL DEFAULT 0,
        max_tx_bps REAL NOT NULL DEFAULT 0,
        avg_conns REAL NOT NULL DEFAULT 0,
        sample_count INTEGER NOT NULL DEFAULT 0
      );
    )SQL";

    if (!execLocked(m1, outError)) {
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    SqliteStmt ins(db_, "INSERT INTO schema_migrations(version, name, applied_at_ms) VALUES(1, '001_initial_history', ?);");
    ins.bindInt64(1, static_cast<int64_t>(nowEpochMs()));
    if (!ins.stepDone()) {
      outError = sqlite3_errmsg(db_);
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    if (!execLocked("COMMIT;", outError)) return false;
  }

  if (currentVer < 2) {
    if (!execLocked("BEGIN IMMEDIATE;", outError)) return false;
    const char* m2 = R"SQL(
      CREATE TABLE IF NOT EXISTS quality_targets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 0,
        category TEXT NOT NULL DEFAULT 'custom',
        probe_mode TEXT NOT NULL DEFAULT 'icmp',
        interval_sec INTEGER NOT NULL DEFAULT 10,
        enabled INTEGER NOT NULL DEFAULT 1,
        is_auto INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS quality_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms INTEGER NOT NULL,
        target_id TEXT NOT NULL,
        ok INTEGER NOT NULL,
        rtt_ms REAL NOT NULL DEFAULT 0,
        dns_ms REAL NOT NULL DEFAULT 0,
        jitter_ms REAL NOT NULL DEFAULT 0,
        method TEXT NOT NULL DEFAULT 'icmp',
        error TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_quality_tid_ts ON quality_samples(target_id, ts_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_quality_ts ON quality_samples(ts_ms DESC);
    )SQL";

    if (!execLocked(m2, outError)) {
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    SqliteStmt ins2(db_, "INSERT INTO schema_migrations(version, name, applied_at_ms) VALUES(2, '002_network_quality', ?);");
    ins2.bindInt64(1, static_cast<int64_t>(nowEpochMs()));
    if (!ins2.stepDone()) {
      outError = sqlite3_errmsg(db_);
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    if (!execLocked("COMMIT;", outError)) return false;
  }

  if (currentVer < 3) {
    if (!execLocked("BEGIN IMMEDIATE;", outError)) return false;
    const char* m3 = R"SQL(
      CREATE TABLE IF NOT EXISTS trace_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip TEXT NOT NULL,
        target_label TEXT NOT NULL DEFAULT '',
        trigger_kind TEXT NOT NULL DEFAULT 'manual',
        started_at_ms INTEGER NOT NULL,
        completed_at_ms INTEGER NOT NULL DEFAULT 0,
        reached INTEGER NOT NULL DEFAULT 0,
        hop_count INTEGER NOT NULL DEFAULT 0,
        total_rtt_ms REAL NOT NULL DEFAULT 0,
        path_hash TEXT NOT NULL DEFAULT '',
        changed_from_prev INTEGER NOT NULL DEFAULT 0,
        error TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_trace_runs_target_ts ON trace_runs(target_ip, started_at_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_trace_runs_ts ON trace_runs(started_at_ms DESC);

      CREATE TABLE IF NOT EXISTS trace_hops (
        run_id INTEGER NOT NULL,
        ttl INTEGER NOT NULL,
        timed_out INTEGER NOT NULL DEFAULT 0,
        ip TEXT NOT NULL DEFAULT '',
        rtt_ms REAL NOT NULL DEFAULT 0,
        hostname TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        country_code TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '',
        lat REAL NOT NULL DEFAULT 0,
        lon REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (run_id, ttl)
      );

      CREATE TABLE IF NOT EXISTS trace_monitors (
        target_ip TEXT PRIMARY KEY,
        label TEXT NOT NULL DEFAULT '',
        interval_sec INTEGER NOT NULL DEFAULT 300,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        last_run_ms INTEGER NOT NULL DEFAULT 0
      );
    )SQL";

    if (!execLocked(m3, outError)) {
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    SqliteStmt ins3(db_, "INSERT INTO schema_migrations(version, name, applied_at_ms) VALUES(3, '003_traceroute_history', ?);");
    ins3.bindInt64(1, static_cast<int64_t>(nowEpochMs()));
    if (!ins3.stepDone()) {
      outError = sqlite3_errmsg(db_);
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    if (!execLocked("COMMIT;", outError)) return false;
  }

  if (currentVer < 4) {
    if (!execLocked("BEGIN IMMEDIATE;", outError)) return false;
    const char* m4 = R"SQL(
      CREATE TABLE IF NOT EXISTS interface_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms INTEGER NOT NULL,
        if_id TEXT NOT NULL,
        if_name TEXT NOT NULL DEFAULT '',
        if_type TEXT NOT NULL DEFAULT 'other',
        oper_status TEXT NOT NULL DEFAULT 'unknown',
        is_default_route INTEGER NOT NULL DEFAULT 0,
        link_speed_bps INTEGER NOT NULL DEFAULT 0,
        rx_bps REAL NOT NULL DEFAULT 0,
        tx_bps REAL NOT NULL DEFAULT 0,
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        rx_errors INTEGER NOT NULL DEFAULT 0,
        tx_errors INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_iface_id_ts ON interface_samples(if_id, ts_ms DESC);
      CREATE INDEX IF NOT EXISTS idx_iface_ts ON interface_samples(ts_ms DESC);
    )SQL";

    if (!execLocked(m4, outError)) {
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    SqliteStmt ins4(db_, "INSERT INTO schema_migrations(version, name, applied_at_ms) VALUES(4, '004_interfaces_multiwan', ?);");
    ins4.bindInt64(1, static_cast<int64_t>(nowEpochMs()));
    if (!ins4.stepDone()) {
      outError = sqlite3_errmsg(db_);
      std::string dummy;
      execLocked("ROLLBACK;", dummy);
      return false;
    }

    if (!execLocked("COMMIT;", outError)) return false;
  }

  return true;
}

bool SqliteDb::quickCheckOk() {
  std::lock_guard lock(mutex_);
  if (!db_) return false;
  SqliteStmt st(db_, "PRAGMA quick_check(1);");
  if (!st.valid() || st.step() != SQLITE_ROW) return false;
  return st.colText(0) == "ok";
}

bool SqliteDb::checkpointAndVacuum(std::string& outError) {
  std::lock_guard lock(mutex_);
  if (!db_) {
    outError = "database_closed";
    return false;
  }
  execLocked("PRAGMA incremental_vacuum(200);", outError);
  int rc = sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
  if (rc != SQLITE_OK) {
    outError = sqlite3_errmsg(db_);
    return false;
  }
  return true;
}

uint64_t SqliteDb::fileSizeBytes() const {
  std::error_code ec;
  uint64_t total = 0;
  if (std::filesystem::exists(path_, ec)) {
    total += std::filesystem::file_size(path_, ec);
  }
  auto walPath = path_;
  walPath += "-wal";
  if (std::filesystem::exists(walPath, ec)) {
    total += std::filesystem::file_size(walPath, ec);
  }
  return total;
}

} // namespace netpulse
