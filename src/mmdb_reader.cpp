#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include "mmdb_reader.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace netpulse {

namespace {

constexpr uint8_t kMetadataMarker[] = {
    0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};

const MmdbReader::DecodeResult* findMapKey(const MmdbReader::DecodeResult& map,
                                           const char* key) {
  if (map.kind != MmdbReader::DecodeResult::Kind::Map) return nullptr;
  for (const auto& [k, v] : map.mapVal) {
    if (k == key) return &v;
  }
  return nullptr;
}

std::string extractLocalizedName(const MmdbReader::DecodeResult& parent,
                                 const char* objKey) {
  const auto* obj = findMapKey(parent, objKey);
  if (!obj) return {};
  const auto* names = findMapKey(*obj, "names");
  if (!names) return {};
  if (const auto* pt = findMapKey(*names, "pt-BR"); pt && pt->kind == MmdbReader::DecodeResult::Kind::String) {
    return pt->strVal;
  }
  if (const auto* en = findMapKey(*names, "en"); en && en->kind == MmdbReader::DecodeResult::Kind::String) {
    return en->strVal;
  }
  if (!names->mapVal.empty() && names->mapVal[0].second.kind == MmdbReader::DecodeResult::Kind::String) {
    return names->mapVal[0].second.strVal;
  }
  return {};
}

} // namespace

uint64_t MmdbReader::readBigEndianUint(size_t offset, size_t len) const {
  if (offset + len > data_.size() || len > 8) return 0;
  uint64_t v = 0;
  for (size_t i = 0; i < len; ++i) {
    v = (v << 8) | data_[offset + i];
  }
  return v;
}

bool MmdbReader::load(const std::filesystem::path& path) {
  loaded_ = false;
  data_.clear();

  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in.is_open()) return false;
  const auto sz = in.tellg();
  if (sz <= 32 || sz > 256 * 1024 * 1024) return false;

  data_.resize(static_cast<size_t>(sz));
  in.seekg(0, std::ios::beg);
  if (!in.read(reinterpret_cast<char*>(data_.data()), sz)) {
    data_.clear();
    return false;
  }

  if (!parseMetadata()) {
    data_.clear();
    return false;
  }

  loaded_ = true;
  return true;
}

bool MmdbReader::parseMetadata() {
  const size_t markerLen = sizeof(kMetadataMarker);
  const size_t searchStart = (data_.size() > 131072) ? (data_.size() - 131072) : 0;

  size_t markerPos = std::string::npos;
  for (size_t i = data_.size() - markerLen; i >= searchStart; --i) {
    if (std::memcmp(data_.data() + i, kMetadataMarker, markerLen) == 0) {
      markerPos = i;
      break;
    }
    if (i == 0) break;
  }
  if (markerPos == std::string::npos) return false;

  // Temporarily set dataSectionStart_ to metadata offset so pointer decoding works if any
  size_t metaOffset = markerPos + markerLen;
  dataSectionStart_ = metaOffset;

  DecodeResult metaMap;
  if (!decodeValue(metaOffset, metaMap) || metaMap.kind != DecodeResult::Kind::Map) {
    return false;
  }

  if (const auto* nc = findMapKey(metaMap, "node_count")) meta_.nodeCount = static_cast<uint32_t>(nc->uintVal);
  if (const auto* rs = findMapKey(metaMap, "record_size")) meta_.recordSize = static_cast<uint16_t>(rs->uintVal);
  if (const auto* iv = findMapKey(metaMap, "ip_version")) meta_.ipVersion = static_cast<uint16_t>(iv->uintVal);
  if (const auto* dt = findMapKey(metaMap, "database_type")) meta_.databaseType = dt->strVal;

  if (meta_.nodeCount == 0 || (meta_.recordSize != 24 && meta_.recordSize != 28 && meta_.recordSize != 32)) {
    return false;
  }

  const size_t nodeByteSize = (meta_.recordSize * 2) / 8;
  searchTreeBytes_ = static_cast<size_t>(meta_.nodeCount) * nodeByteSize;
  if (searchTreeBytes_ + 16 > markerPos) return false;

  // Per MaxMind DB spec, 16 zero bytes separate search tree from data section.
  dataSectionStart_ = searchTreeBytes_ + 16;
  databaseType_ = meta_.databaseType;

  // Precompute IPv4 start node in IPv6 trees (96 zero bits)
  ipv4StartNode_ = 0;
  if (meta_.ipVersion == 6) {
    uint32_t node = 0;
    for (int i = 0; i < 96 && node < meta_.nodeCount; ++i) {
      node = readRecord(node, 0);
    }
    ipv4StartNode_ = node;
  }
  return true;
}

uint32_t MmdbReader::readRecord(uint32_t nodeIndex, int bit) const {
  const size_t nodeSize = (meta_.recordSize * 2) / 8;
  const size_t base = static_cast<size_t>(nodeIndex) * nodeSize;
  if (base + nodeSize > searchTreeBytes_) return meta_.nodeCount;

  if (meta_.recordSize == 24) {
    const size_t off = base + (bit ? 3 : 0);
    return (static_cast<uint32_t>(data_[off]) << 16) |
           (static_cast<uint32_t>(data_[off + 1]) << 8) |
           static_cast<uint32_t>(data_[off + 2]);
  }
  if (meta_.recordSize == 28) {
    uint32_t middle = data_[base + 3];
    if (bit == 0) {
      return ((middle & 0xF0) << 20) |
             (static_cast<uint32_t>(data_[base]) << 16) |
             (static_cast<uint32_t>(data_[base + 1]) << 8) |
             static_cast<uint32_t>(data_[base + 2]);
    }
    return ((middle & 0x0F) << 24) |
           (static_cast<uint32_t>(data_[base + 4]) << 16) |
           (static_cast<uint32_t>(data_[base + 5]) << 8) |
           static_cast<uint32_t>(data_[base + 6]);
  }
  const size_t off = base + (bit ? 4 : 0);
  return static_cast<uint32_t>(readBigEndianUint(off, 4));
}

bool MmdbReader::decodeValue(size_t& offset, DecodeResult& out, int depth) const {
  if (depth > 32 || offset >= data_.size()) return false;

  const uint8_t ctrl = data_[offset++];
  uint32_t type = (ctrl >> 5) & 0x07;
  uint32_t size = ctrl & 0x1F;

  if (type == 1) {
    // Pointer
    const uint32_t ptrSize = (size >> 3) & 0x03;
    const uint32_t baseVal = size & 0x07;
    uint32_t ptr = 0;
    if (ptrSize == 0) {
      if (offset >= data_.size()) return false;
      ptr = (baseVal << 8) | data_[offset++];
    } else if (ptrSize == 1) {
      if (offset + 2 > data_.size()) return false;
      ptr = ((baseVal << 16) | static_cast<uint32_t>(readBigEndianUint(offset, 2))) + 2048;
      offset += 2;
    } else if (ptrSize == 2) {
      if (offset + 3 > data_.size()) return false;
      ptr = ((baseVal << 24) | static_cast<uint32_t>(readBigEndianUint(offset, 3))) + 526336;
      offset += 3;
    } else {
      if (offset + 4 > data_.size()) return false;
      ptr = static_cast<uint32_t>(readBigEndianUint(offset, 4));
      offset += 4;
    }
    size_t target = dataSectionStart_ + ptr;
    return decodeValue(target, out, depth + 1);
  }

  if (type == 0) {
    if (offset >= data_.size()) return false;
    type = 7 + data_[offset++];
  }

  if (type != 14) { // bool uses size directly as value
    if (size == 29) {
      if (offset >= data_.size()) return false;
      size = 29 + data_[offset++];
    } else if (size == 30) {
      if (offset + 2 > data_.size()) return false;
      size = 285 + static_cast<uint32_t>(readBigEndianUint(offset, 2));
      offset += 2;
    } else if (size == 31) {
      if (offset + 3 > data_.size()) return false;
      size = 65821 + static_cast<uint32_t>(readBigEndianUint(offset, 3));
      offset += 3;
    }
  }

  switch (type) {
    case 2: { // UTF-8 string
      if (offset + size > data_.size()) return false;
      out.kind = DecodeResult::Kind::String;
      out.strVal.assign(reinterpret_cast<const char*>(data_.data() + offset), size);
      offset += size;
      return true;
    }
    case 3: { // IEEE-754 double (8 bytes big-endian)
      if (size != 8 || offset + 8 > data_.size()) return false;
      uint64_t raw = readBigEndianUint(offset, 8);
      offset += 8;
      double d = 0.0;
      std::memcpy(&d, &raw, sizeof(d));
      out.kind = DecodeResult::Kind::Double;
      out.doubleVal = d;
      return true;
    }
    case 4: { // bytes
      if (offset + size > data_.size()) return false;
      offset += size;
      out.kind = DecodeResult::Kind::None;
      return true;
    }
    case 5: // uint16
    case 6: // uint32
    case 9: // uint64
    case 8: { // int32 (treated unsigned for small metadata/ASN)
      if (offset + size > data_.size()) return false;
      out.kind = DecodeResult::Kind::Uint;
      out.uintVal = readBigEndianUint(offset, size);
      offset += size;
      return true;
    }
    case 7: { // Map
      out.kind = DecodeResult::Kind::Map;
      out.mapVal.reserve(size);
      for (uint32_t i = 0; i < size; ++i) {
        DecodeResult kRes, vRes;
        if (!decodeValue(offset, kRes, depth + 1) || !decodeValue(offset, vRes, depth + 1)) {
          return false;
        }
        out.mapVal.emplace_back(std::move(kRes.strVal), std::move(vRes));
      }
      return true;
    }
    case 10: { // uint128
      if (offset + size > data_.size()) return false;
      offset += size;
      out.kind = DecodeResult::Kind::None;
      return true;
    }
    case 11: { // Array
      out.kind = DecodeResult::Kind::Array;
      out.arrVal.reserve(size);
      for (uint32_t i = 0; i < size; ++i) {
        DecodeResult item;
        if (!decodeValue(offset, item, depth + 1)) return false;
        out.arrVal.push_back(std::move(item));
      }
      return true;
    }
    case 14: { // Boolean
      out.kind = DecodeResult::Kind::Bool;
      out.boolVal = (size != 0);
      return true;
    }
    case 15: { // Float (4 bytes)
      if (size != 4 || offset + 4 > data_.size()) return false;
      uint32_t raw = static_cast<uint32_t>(readBigEndianUint(offset, 4));
      offset += 4;
      float f = 0.0f;
      std::memcpy(&f, &raw, sizeof(f));
      out.kind = DecodeResult::Kind::Double;
      out.doubleVal = static_cast<double>(f);
      return true;
    }
    default:
      if (offset + size > data_.size()) return false;
      offset += size;
      return true;
  }
}

std::optional<GeoInfo> MmdbReader::lookup(const std::string& ip) const {
  if (!loaded_) return std::nullopt;

  uint8_t addrBytes[16] = {};
  int bitCount = 0;
  uint32_t node = 0;

  IN_ADDR in4{};
  IN6_ADDR in6{};
  if (inet_pton(AF_INET, ip.c_str(), &in4) == 1) {
    std::memcpy(addrBytes, &in4, 4);
    bitCount = 32;
    node = (meta_.ipVersion == 6) ? ipv4StartNode_ : 0;
  } else if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1) {
    if (meta_.ipVersion != 6) return std::nullopt;
    std::memcpy(addrBytes, &in6, 16);
    bitCount = 128;
    node = 0;
  } else {
    return std::nullopt;
  }

  for (int i = 0; i < bitCount && node < meta_.nodeCount; ++i) {
    int bit = (addrBytes[i >> 3] >> (7 - (i & 7))) & 1;
    node = readRecord(node, bit);
  }

  if (node <= meta_.nodeCount) return std::nullopt; // not found or invalid

  const size_t dataOffset = (node - meta_.nodeCount) - 16;
  size_t off = dataSectionStart_ + dataOffset;
  DecodeResult root;
  if (!decodeValue(off, root) || root.kind != DecodeResult::Kind::Map) {
    return std::nullopt;
  }

  GeoInfo g;
  if (const auto* country = findMapKey(root, "country")) {
    if (const auto* iso = findMapKey(*country, "iso_code"); iso && iso->kind == DecodeResult::Kind::String) {
      g.countryCode = iso->strVal;
    }
  }
  g.country = extractLocalizedName(root, "country");
  g.city = extractLocalizedName(root, "city");

  if (const auto* subs = findMapKey(root, "subdivisions");
      subs && subs->kind == DecodeResult::Kind::Array && !subs->arrVal.empty()) {
    const auto* names = findMapKey(subs->arrVal[0], "names");
    if (names) {
      if (const auto* en = findMapKey(*names, "en"); en && en->kind == DecodeResult::Kind::String) {
        g.region = en->strVal;
      }
    }
  }

  if (const auto* loc = findMapKey(root, "location")) {
    if (const auto* lat = findMapKey(*loc, "latitude"); lat && lat->kind == DecodeResult::Kind::Double) {
      g.lat = lat->doubleVal;
    }
    if (const auto* lon = findMapKey(*loc, "longitude"); lon && lon->kind == DecodeResult::Kind::Double) {
      g.lon = lon->doubleVal;
    }
  }

  if (const auto* asn = findMapKey(root, "autonomous_system_number"); asn && asn->kind == DecodeResult::Kind::Uint) {
    g.asn = "AS" + std::to_string(asn->uintVal);
  }
  if (const auto* org = findMapKey(root, "autonomous_system_organization");
      org && org->kind == DecodeResult::Kind::String) {
    g.org = org->strVal;
    g.isp = org->strVal;
  }

  if (g.country.empty() && g.countryCode.empty() && g.lat == 0.0 && g.lon == 0.0 && g.asn.empty()) {
    return std::nullopt;
  }
  g.resolved = true;
  return g;
}

} // namespace netpulse
