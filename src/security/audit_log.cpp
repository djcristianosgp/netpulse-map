#include "audit_log.hpp"
#include "../models.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace netpulse {

namespace {

constexpr size_t kMaxAuditEntriesInMemory = 500;
constexpr size_t kMaxAuditEntriesOnDisk = 2000;

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string sanitizeTsv(std::string s) {
  for (char& c : s) {
    if (c == '\t' || c == '\r' || c == '\n') c = ' ';
  }
  return s;
}

} // namespace

AuditLog::AuditLog(std::filesystem::path filePath) : filePath_(std::move(filePath)) {
  loadFromDisk();
}

void AuditLog::loadFromDisk() {
  std::lock_guard lock(mutex_);
  std::error_code ec;
  if (!std::filesystem::exists(filePath_, ec)) return;

  std::ifstream in(filePath_);
  if (!in.is_open()) return;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, '\t')) cols.push_back(item);
    if (cols.size() < 11) continue;

    AuditEntry e;
    e.id = std::strtoull(cols[0].c_str(), nullptr, 10);
    e.tsMs = std::strtoull(cols[1].c_str(), nullptr, 10);
    e.actor = cols[2];
    e.role = cols[3];
    e.sourceIp = cols[4];
    e.action = cols[5];
    e.target = cols[6];
    e.outcome = cols[7];
    e.detail = cols[8];
    e.reversible = (cols[9] == "1");
    e.reverted = (cols[10] == "1");

    if (e.id >= nextId_) nextId_ = e.id + 1;
    entries_.push_back(std::move(e));
    while (entries_.size() > kMaxAuditEntriesInMemory) entries_.pop_front();
  }
}

void AuditLog::rewriteDiskLocked() {
  std::error_code ec;
  std::filesystem::create_directories(filePath_.parent_path(), ec);
  std::ofstream out(filePath_, std::ios::trunc);
  if (!out.is_open()) return;
  for (const auto& e : entries_) {
    out << e.id << '\t'
        << e.tsMs << '\t'
        << sanitizeTsv(e.actor) << '\t'
        << sanitizeTsv(e.role) << '\t'
        << sanitizeTsv(e.sourceIp) << '\t'
        << sanitizeTsv(e.action) << '\t'
        << sanitizeTsv(e.target) << '\t'
        << sanitizeTsv(e.outcome) << '\t'
        << sanitizeTsv(e.detail) << '\t'
        << (e.reversible ? "1" : "0") << '\t'
        << (e.reverted ? "1" : "0") << '\n';
  }
}

uint64_t AuditLog::record(const std::string& actor,
                          const std::string& role,
                          const std::string& sourceIp,
                          const std::string& action,
                          const std::string& target,
                          const std::string& outcome,
                          const std::string& detail,
                          bool reversible) {
  std::lock_guard lock(mutex_);
  AuditEntry e;
  e.id = nextId_++;
  e.tsMs = nowEpochMs();
  e.actor = actor.empty() ? "anonymous" : actor;
  e.role = role.empty() ? "none" : role;
  e.sourceIp = sourceIp;
  e.action = action;
  e.target = target;
  e.outcome = outcome;
  e.detail = detail;
  e.reversible = reversible;
  e.reverted = false;

  entries_.push_back(e);
  while (entries_.size() > kMaxAuditEntriesInMemory) entries_.pop_front();

  std::error_code ec;
  std::filesystem::create_directories(filePath_.parent_path(), ec);
  if (std::filesystem::exists(filePath_, ec) &&
      std::filesystem::file_size(filePath_, ec) > kMaxAuditEntriesOnDisk * 220) {
    rewriteDiskLocked();
  } else {
    std::ofstream out(filePath_, std::ios::app);
    if (out.is_open()) {
      out << e.id << '\t'
          << e.tsMs << '\t'
          << sanitizeTsv(e.actor) << '\t'
          << sanitizeTsv(e.role) << '\t'
          << sanitizeTsv(e.sourceIp) << '\t'
          << sanitizeTsv(e.action) << '\t'
          << sanitizeTsv(e.target) << '\t'
          << sanitizeTsv(e.outcome) << '\t'
          << sanitizeTsv(e.detail) << '\t'
          << (e.reversible ? "1" : "0") << '\t'
          << (e.reverted ? "1" : "0") << '\n';
    }
  }
  return e.id;
}

bool AuditLog::markReverted(uint64_t id) {
  std::lock_guard lock(mutex_);
  for (auto& e : entries_) {
    if (e.id == id && e.reversible && !e.reverted) {
      e.reverted = true;
      rewriteDiskLocked();
      return true;
    }
  }
  return false;
}

bool AuditLog::markTargetReverted(const std::string& action, const std::string& target) {
  std::lock_guard lock(mutex_);
  bool changed = false;
  for (auto& e : entries_) {
    if (e.action == action && e.target == target && e.reversible && !e.reverted) {
      e.reverted = true;
      changed = true;
    }
  }
  if (changed) rewriteDiskLocked();
  return changed;
}

std::vector<AuditEntry> AuditLog::recent(size_t maxItems) const {
  std::lock_guard lock(mutex_);
  std::vector<AuditEntry> out;
  const size_t n = std::min(maxItems, entries_.size());
  out.reserve(n);
  for (auto it = entries_.rbegin(); it != entries_.rend() && out.size() < n; ++it) {
    out.push_back(*it);
  }
  return out;
}

std::string AuditLog::toJson(size_t maxItems) const {
  auto items = recent(maxItems);
  std::string out = "{\"entries\":[";
  for (size_t i = 0; i < items.size(); ++i) {
    const auto& e = items[i];
    if (i > 0) out.push_back(',');
    out += "{\"id\":";
    out += std::to_string(e.id);
    out += ",\"ts\":";
    out += std::to_string(e.tsMs);
    out += ",\"actor\":";
    appendJsonEscaped(out, e.actor);
    out += ",\"role\":";
    appendJsonEscaped(out, e.role);
    out += ",\"sourceIp\":";
    appendJsonEscaped(out, e.sourceIp);
    out += ",\"action\":";
    appendJsonEscaped(out, e.action);
    out += ",\"target\":";
    appendJsonEscaped(out, e.target);
    out += ",\"outcome\":";
    appendJsonEscaped(out, e.outcome);
    out += ",\"detail\":";
    appendJsonEscaped(out, e.detail);
    out += ",\"reversible\":";
    out += (e.reversible ? "true" : "false");
    out += ",\"reverted\":";
    out += (e.reverted ? "true" : "false");
    out.push_back('}');
  }
  out += "]}";
  return out;
}

} // namespace netpulse
