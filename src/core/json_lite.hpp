#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace netpulse {

class JsonValue {
public:
  enum class Type : uint8_t {
    Null = 0,
    Bool,
    Int,
    Double,
    String,
    Array,
    Object,
  };

  using Array = std::vector<JsonValue>;
  using Object = std::unordered_map<std::string, JsonValue>;

  JsonValue() = default;
  explicit JsonValue(bool b) : type_(Type::Bool), boolVal_(b) {}
  explicit JsonValue(int64_t i) : type_(Type::Int), intVal_(i), doubleVal_(static_cast<double>(i)) {}
  explicit JsonValue(double d) : type_(Type::Double), doubleVal_(d) {}
  explicit JsonValue(std::string s) : type_(Type::String), strVal_(std::move(s)) {}
  explicit JsonValue(Array a) : type_(Type::Array), arrVal_(std::move(a)) {}
  explicit JsonValue(Object o) : type_(Type::Object), objVal_(std::move(o)) {}

  static bool parse(const std::string& input, JsonValue& out, std::string& outError, size_t maxBytes = 65536);

  Type type() const { return type_; }
  bool isNull() const { return type_ == Type::Null; }
  bool isBool() const { return type_ == Type::Bool; }
  bool isNumber() const { return type_ == Type::Int || type_ == Type::Double; }
  bool isString() const { return type_ == Type::String; }
  bool isArray() const { return type_ == Type::Array; }
  bool isObject() const { return type_ == Type::Object; }

  bool asBool(bool fallback = false) const;
  int64_t asInt(int64_t fallback = 0) const;
  double asDouble(double fallback = 0.0) const;
  std::string asString(const std::string& fallback = {}) const;
  const Array& asArray() const;
  const Object& asObject() const;

  const JsonValue* get(const std::string& key) const;
  std::string getString(const std::string& key, const std::string& fallback = {}) const;
  bool getBool(const std::string& key, bool fallback = false) const;
  int64_t getInt(const std::string& key, int64_t fallback = 0) const;
  double getDouble(const std::string& key, double fallback = 0.0) const;

private:
  Type type_ = Type::Null;
  bool boolVal_ = false;
  int64_t intVal_ = 0;
  double doubleVal_ = 0.0;
  std::string strVal_;
  Array arrVal_;
  Object objVal_;
};

} // namespace netpulse
