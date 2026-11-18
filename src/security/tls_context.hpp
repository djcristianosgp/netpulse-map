#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace netpulse {

struct TlsConfig {
  bool enabled = false;
  std::filesystem::path certPath;
  std::filesystem::path keyPath;
  std::filesystem::path autoCertDir;
  std::string commonName = "localhost";
};

class TlsConnection {
public:
  virtual ~TlsConnection() = default;
  virtual bool handshake() = 0;
  virtual int recvBytes(char* buf, size_t len) = 0;
  virtual int sendBytes(const char* buf, size_t len) = 0;
  virtual void shutdownTls() = 0;
};

class TlsContext {
public:
  TlsContext();
  ~TlsContext();

  TlsContext(const TlsContext&) = delete;
  TlsContext& operator=(const TlsContext&) = delete;

  bool init(const TlsConfig& cfg, std::string& outError);
  bool isReady() const { return ready_; }
  std::unique_ptr<TlsConnection> wrapAcceptedSocket(uintptr_t rawSock) const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  bool ready_ = false;
};

} // namespace netpulse
