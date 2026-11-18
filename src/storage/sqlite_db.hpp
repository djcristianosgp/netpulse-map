#pragma once

#include "../../third_party/sqlite/sqlite3.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace netpulse {

class SqliteStmt {
public:
  SqliteStmt() = default;
  SqliteStmt(sqlite3* db, const char* sql);
  ~SqliteStmt();

  SqliteStmt(const SqliteStmt&) = delete;
  SqliteStmt& operator=(const SqliteStmt&) = delete;
  SqliteStmt(SqliteStmt&& other) noexcept;
  SqliteStmt& operator=(SqliteStmt&& other) noexcept;

  bool valid() const { return stmt_ != nullptr; }
  bool bindText(int idx, const std::string& val);
  bool bindInt64(int idx, int64_t val);
  bool bindDouble(int idx, double val);
  bool stepDone();
  int step();
  void reset();

  int64_t colInt64(int col) const;
  double colDouble(int col) const;
  std::string colText(int col) const;

private:
  sqlite3_stmt* stmt_ = nullptr;
};

class SqliteDb {
public:
  SqliteDb() = default;
  ~SqliteDb();

  SqliteDb(const SqliteDb&) = delete;
  SqliteDb& operator=(const SqliteDb&) = delete;

  bool open(const std::filesystem::path& dbPath, std::string& outError);
  void close();
  bool isOpen() const { return db_ != nullptr; }

  bool exec(const char* sql, std::string& outError);
  bool runMigrations(std::string& outError);
  bool quickCheckOk();
  bool checkpointAndVacuum(std::string& outError);

  uint64_t fileSizeBytes() const;
  int currentSchemaVersion() const;

  template <typename Fn>
  bool withLock(Fn&& fn) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;
    return fn(db_);
  }

  template <typename Fn>
  bool withTransaction(Fn&& fn) {
    std::lock_guard lock(mutex_);
    if (!db_) return false;
    char* errMsg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &errMsg) != SQLITE_OK) {
      if (errMsg) sqlite3_free(errMsg);
      return false;
    }
    if (!fn(db_)) {
      sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
      return false;
    }
    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errMsg) != SQLITE_OK) {
      if (errMsg) sqlite3_free(errMsg);
      sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
      return false;
    }
    return true;
  }

  std::mutex& mutex() { return mutex_; }
  sqlite3* rawHandle() const { return db_; }

private:
  bool execLocked(const char* sql, std::string& outError);

  std::filesystem::path path_;
  mutable std::mutex mutex_;
  sqlite3* db_ = nullptr;
};

} // namespace netpulse
