#pragma once

#include "models.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace netpulse {

// Pure C++20 reader for MaxMind DB (.mmdb) binary GeoIP/ASN files (v2.0 spec).
class MmdbReader {
public:
  struct DecodeResult {
    enum class Kind { None, Bool, Uint, Double, String, Array, Map };
    Kind kind = Kind::None;
    bool boolVal = false;
    uint64_t uintVal = 0;
    double doubleVal = 0.0;
    std::string strVal;
    std::vector<DecodeResult> arrVal;
    std::vector<std::pair<std::string, DecodeResult>> mapVal;
  };

  bool load(const std::filesystem::path& path);
  bool isLoaded() const { return loaded_; }
  const std::string& databaseType() const { return databaseType_; }

  std::optional<GeoInfo> lookup(const std::string& ip) const;

private:
  struct Metadata {
    uint32_t nodeCount = 0;
    uint16_t recordSize = 0;
    uint16_t ipVersion = 4;
    std::string databaseType;
  };

  bool parseMetadata();
  uint32_t readRecord(uint32_t nodeIndex, int bit) const;
  bool decodeValue(size_t& offset, DecodeResult& out, int depth = 0) const;
  uint64_t readBigEndianUint(size_t offset, size_t len) const;

  std::vector<uint8_t> data_;
  Metadata meta_;
  size_t searchTreeBytes_ = 0;
  size_t dataSectionStart_ = 0;
  uint32_t ipv4StartNode_ = 0;
  std::string databaseType_;
  bool loaded_ = false;
};

} // namespace netpulse
