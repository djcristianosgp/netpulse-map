#pragma once

#include <cstdint>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace netpulse {

struct AuditEntry {
  uint64_t id = 0;
  uint64_t tsMs = 0;
  std::string actor;
  std::string role;
  std::string sourceIp;
  std::string action;
  std::string target;
  std::string outcome; // "allowed" | "denied" | "failed"
  std::string detail;
  bool reversible = false;
  bool reverted = false;
};

class AuditLog {
public:
  explicit AuditLog(std::filesystem::path filePath);

  uint64_t record(const std::string& actor,
                  const std::string& role,
                  const std::string& sourceIp,
                  const std::string& action,
                  const std::string& target,
                  const std::string& outcome,
                  const std::string& detail,
                  bool reversible = false);

  bool markReverted(uint64_t id);
  bool markTargetReverted(const std::string& action, const std::string& target);

  std::vector<AuditEntry> recent(size_t maxItems = 200) const;
  std::string toJson(size_t maxItems = 200) const;

private:
  void loadFromDisk();
  void rewriteDiskLocked();

  std::filesystem::path filePath_;
  mutable std::mutex mutex_;
  std::deque<AuditEntry> entries_;
  uint64_t nextId_ = 1;
};

} // namespace netpulse
