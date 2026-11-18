#include "json_lite.hpp"

#include <cctype>
#include <cstdlib>
#include <limits>

namespace netpulse {

namespace {

constexpr int kMaxJsonDepth = 32;

class Parser {
public:
  explicit Parser(const std::string& src) : src_(src) {}

  bool parseRoot(JsonValue& out, std::string& err) {
    skipWs();
    if (!parseValue(out, err, 0)) return false;
    skipWs();
    if (pos_ != src_.size()) {
      err = "trailing_characters";
      return false;
    }
    return true;
  }

private:
  void skipWs() {
    while (pos_ < src_.size()) {
      char c = src_[pos_];
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool parseValue(JsonValue& out, std::string& err, int depth) {
    if (depth > kMaxJsonDepth) {
      err = "max_depth_exceeded";
      return false;
    }
    skipWs();
    if (pos_ >= src_.size()) {
      err = "unexpected_eof";
      return false;
    }

    char c = src_[pos_];
    if (c == '{') return parseObject(out, err, depth + 1);
    if (c == '[') return parseArray(out, err, depth + 1);
    if (c == '"') {
      std::string s;
      if (!parseString(s, err)) return false;
      out = JsonValue(std::move(s));
      return true;
    }
    if (c == 't') {
      if (src_.compare(pos_, 4, "true") == 0) {
        pos_ += 4;
        out = JsonValue(true);
        return true;
      }
      err = "invalid_literal";
      return false;
    }
    if (c == 'f') {
      if (src_.compare(pos_, 5, "false") == 0) {
        pos_ += 5;
        out = JsonValue(false);
        return true;
      }
      err = "invalid_literal";
      return false;
    }
    if (c == 'n') {
      if (src_.compare(pos_, 4, "null") == 0) {
        pos_ += 4;
        out = JsonValue();
        return true;
      }
      err = "invalid_literal";
      return false;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
      return parseNumber(out, err);
    }

    err = "unexpected_token";
    return false;
  }

  static void appendUtf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  bool parseHex4(uint32_t& out) {
    if (pos_ + 4 > src_.size()) return false;
    uint32_t val = 0;
    for (int i = 0; i < 4; ++i) {
      char c = src_[pos_++];
      val <<= 4;
      if (c >= '0' && c <= '9') val |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') val |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') val |= static_cast<uint32_t>(c - 'A' + 10);
      else return false;
    }
    out = val;
    return true;
  }

  bool parseString(std::string& out, std::string& err) {
    if (pos_ >= src_.size() || src_[pos_] != '"') {
      err = "expected_string";
      return false;
    }
    ++pos_;
    out.clear();
    while (pos_ < src_.size()) {
      unsigned char c = static_cast<unsigned char>(src_[pos_++]);
      if (c == '"') {
        return true;
      }
      if (c < 0x20) {
        err = "unescaped_control_char";
        return false;
      }
      if (c == '\\') {
        if (pos_ >= src_.size()) {
          err = "unterminated_escape";
          return false;
        }
        char esc = src_[pos_++];
        switch (esc) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            uint32_t cp = 0;
            if (!parseHex4(cp)) {
              err = "invalid_unicode_escape";
              return false;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              if (pos_ + 2 <= src_.size() && src_[pos_] == '\\' && src_[pos_ + 1] == 'u') {
                pos_ += 2;
                uint32_t low = 0;
                if (!parseHex4(low) || low < 0xDC00 || low > 0xDFFF) {
                  err = "invalid_surrogate_pair";
                  return false;
                }
                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
              }
            }
            appendUtf8(out, cp);
            break;
          }
          default:
            err = "invalid_escape";
            return false;
        }
      } else {
        out.push_back(static_cast<char>(c));
      }
    }
    err = "unterminated_string";
    return false;
  }

  bool parseNumber(JsonValue& out, std::string& err) {
    size_t start = pos_;
    if (src_[pos_] == '-') ++pos_;
    if (pos_ >= src_.size() || !std::isdigit(static_cast<unsigned char>(src_[pos_]))) {
      err = "invalid_number";
      return false;
    }
    if (src_[pos_] == '0') {
      ++pos_;
    } else {
      while (pos_ < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_]))) ++pos_;
    }

    bool isFloat = false;
    if (pos_ < src_.size() && src_[pos_] == '.') {
      isFloat = true;
      ++pos_;
      if (pos_ >= src_.size() || !std::isdigit(static_cast<unsigned char>(src_[pos_]))) {
        err = "invalid_fraction";
        return false;
      }
      while (pos_ < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_]))) ++pos_;
    }
    if (pos_ < src_.size() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
      isFloat = true;
      ++pos_;
      if (pos_ < src_.size() && (src_[pos_] == '+' || src_[pos_] == '-')) ++pos_;
      if (pos_ >= src_.size() || !std::isdigit(static_cast<unsigned char>(src_[pos_]))) {
        err = "invalid_exponent";
        return false;
      }
      while (pos_ < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_]))) ++pos_;
    }

    std::string token = src_.substr(start, pos_ - start);
    if (!isFloat) {
      char* endPtr = nullptr;
      errno = 0;
      long long val = std::strtoll(token.c_str(), &endPtr, 10);
      if (errno == 0 && endPtr == token.c_str() + token.size()) {
        out = JsonValue(static_cast<int64_t>(val));
        return true;
      }
    }

    char* endPtr = nullptr;
    double d = std::strtod(token.c_str(), &endPtr);
    if (endPtr != token.c_str() + token.size()) {
      err = "invalid_number";
      return false;
    }
    out = JsonValue(d);
    return true;
  }

  bool parseArray(JsonValue& out, std::string& err, int depth) {
    ++pos_; // consume '['
    skipWs();
    JsonValue::Array arr;
    if (pos_ < src_.size() && src_[pos_] == ']') {
      ++pos_;
      out = JsonValue(std::move(arr));
      return true;
    }
    while (pos_ < src_.size()) {
      JsonValue elem;
      if (!parseValue(elem, err, depth)) return false;
      arr.push_back(std::move(elem));
      skipWs();
      if (pos_ >= src_.size()) break;
      if (src_[pos_] == ']') {
        ++pos_;
        out = JsonValue(std::move(arr));
        return true;
      }
      if (src_[pos_] != ',') {
        err = "expected_comma_or_bracket";
        return false;
      }
      ++pos_;
    }
    err = "unterminated_array";
    return false;
  }

  bool parseObject(JsonValue& out, std::string& err, int depth) {
    ++pos_; // consume '{'
    skipWs();
    JsonValue::Object obj;
    if (pos_ < src_.size() && src_[pos_] == '}') {
      ++pos_;
      out = JsonValue(std::move(obj));
      return true;
    }
    while (pos_ < src_.size()) {
      skipWs();
      std::string key;
      if (!parseString(key, err)) return false;
      skipWs();
      if (pos_ >= src_.size() || src_[pos_] != ':') {
        err = "expected_colon";
        return false;
      }
      ++pos_;
      JsonValue val;
      if (!parseValue(val, err, depth)) return false;
      obj[std::move(key)] = std::move(val);
      skipWs();
      if (pos_ >= src_.size()) break;
      if (src_[pos_] == '}') {
        ++pos_;
        out = JsonValue(std::move(obj));
        return true;
      }
      if (src_[pos_] != ',') {
        err = "expected_comma_or_brace";
        return false;
      }
      ++pos_;
    }
    err = "unterminated_object";
    return false;
  }

  const std::string& src_;
  size_t pos_ = 0;
};

const JsonValue::Array kEmptyArray;
const JsonValue::Object kEmptyObject;

} // namespace

bool JsonValue::parse(const std::string& input, JsonValue& out, std::string& outError, size_t maxBytes) {
  if (input.size() > maxBytes) {
    outError = "payload_too_large";
    return false;
  }
  Parser p(input);
  return p.parseRoot(out, outError);
}

bool JsonValue::asBool(bool fallback) const {
  if (type_ == Type::Bool) return boolVal_;
  if (type_ == Type::Int) return intVal_ != 0;
  return fallback;
}

int64_t JsonValue::asInt(int64_t fallback) const {
  if (type_ == Type::Int) return intVal_;
  if (type_ == Type::Double) return static_cast<int64_t>(doubleVal_);
  return fallback;
}

double JsonValue::asDouble(double fallback) const {
  if (type_ == Type::Double) return doubleVal_;
  if (type_ == Type::Int) return static_cast<double>(intVal_);
  return fallback;
}

std::string JsonValue::asString(const std::string& fallback) const {
  if (type_ == Type::String) return strVal_;
  return fallback;
}

const JsonValue::Array& JsonValue::asArray() const {
  return (type_ == Type::Array) ? arrVal_ : kEmptyArray;
}

const JsonValue::Object& JsonValue::asObject() const {
  return (type_ == Type::Object) ? objVal_ : kEmptyObject;
}

const JsonValue* JsonValue::get(const std::string& key) const {
  if (type_ != Type::Object) return nullptr;
  auto it = objVal_.find(key);
  return (it != objVal_.end()) ? &it->second : nullptr;
}

std::string JsonValue::getString(const std::string& key, const std::string& fallback) const {
  const auto* v = get(key);
  return v ? v->asString(fallback) : fallback;
}

bool JsonValue::getBool(const std::string& key, bool fallback) const {
  const auto* v = get(key);
  return v ? v->asBool(fallback) : fallback;
}

int64_t JsonValue::getInt(const std::string& key, int64_t fallback) const {
  const auto* v = get(key);
  return v ? v->asInt(fallback) : fallback;
}

double JsonValue::getDouble(const std::string& key, double fallback) const {
  const auto* v = get(key);
  return v ? v->asDouble(fallback) : fallback;
}

} // namespace netpulse
