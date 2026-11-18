#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <schannel.h>
#else
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "tls_context.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace netpulse {

#ifdef _WIN32

struct TlsContext::Impl {
  HCRYPTPROV hProv = 0;
  HCRYPTKEY hKey = 0;
  PCCERT_CONTEXT cert = nullptr;
  CredHandle cred{};
  bool hasCred = false;

  ~Impl() {
    if (hasCred) FreeCredentialsHandle(&cred);
    if (cert) CertFreeCertificateContext(cert);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
  }
};

namespace {

class WinSChannelConnection final : public TlsConnection {
public:
  WinSChannelConnection(SOCKET sock, CredHandle* cred)
      : sock_(sock), cred_(cred) {}

  ~WinSChannelConnection() override {
    shutdownTls();
    if (hasCtx_) {
      DeleteSecurityContext(&ctx_);
      hasCtx_ = false;
    }
  }

  bool handshake() override {
    std::vector<uint8_t> inBuf;
    inBuf.reserve(16384);
    bool firstCall = true;

    while (true) {
      if (inBuf.empty()) {
        uint8_t tmp[4096];
        int n = recv(sock_, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (n <= 0) return false;
        inBuf.insert(inBuf.end(), tmp, tmp + n);
      }

      SecBuffer inBuffers[2]{};
      inBuffers[0].BufferType = SECBUFFER_TOKEN;
      inBuffers[0].pvBuffer = inBuf.data();
      inBuffers[0].cbBuffer = static_cast<unsigned long>(inBuf.size());
      inBuffers[1].BufferType = SECBUFFER_EMPTY;

      SecBufferDesc inDesc{};
      inDesc.ulVersion = SECBUFFER_VERSION;
      inDesc.cBuffers = 2;
      inDesc.pBuffers = inBuffers;

      SecBuffer outBuffers[1]{};
      outBuffers[0].BufferType = SECBUFFER_TOKEN;
      SecBufferDesc outDesc{};
      outDesc.ulVersion = SECBUFFER_VERSION;
      outDesc.cBuffers = 1;
      outDesc.pBuffers = outBuffers;

      DWORD ctxReq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                     ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                     ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
      DWORD ctxAttr = 0;
      TimeStamp expiry{};

      SECURITY_STATUS ss = AcceptSecurityContext(
          cred_,
          firstCall ? nullptr : &ctx_,
          &inDesc,
          ctxReq,
          0,
          firstCall ? &ctx_ : nullptr,
          &outDesc,
          &ctxAttr,
          &expiry);

      if (firstCall && (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)) {
        hasCtx_ = true;
        firstCall = false;
      }

      if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer) {
        bool sentOk = sendRaw(reinterpret_cast<const char*>(outBuffers[0].pvBuffer),
                              outBuffers[0].cbBuffer);
        FreeContextBuffer(outBuffers[0].pvBuffer);
        if (!sentOk) return false;
      }

      if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        uint8_t tmp[4096];
        int n = recv(sock_, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (n <= 0) return false;
        inBuf.insert(inBuf.end(), tmp, tmp + n);
        continue;
      }

      if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
        size_t extra = inBuffers[1].cbBuffer;
        std::vector<uint8_t> rem(inBuf.end() - static_cast<ptrdiff_t>(extra), inBuf.end());
        inBuf.swap(rem);
      } else {
        inBuf.clear();
      }

      if (ss == SEC_E_OK) {
        if (!inBuf.empty()) {
          encInBuf_.insert(encInBuf_.end(), inBuf.begin(), inBuf.end());
        }
        QueryContextAttributes(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
        established_ = true;
        return true;
      }
      if (ss != SEC_I_CONTINUE_NEEDED) {
        return false;
      }
      if (inBuf.empty()) {
        uint8_t tmp[4096];
        int n = recv(sock_, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (n <= 0) return false;
        inBuf.insert(inBuf.end(), tmp, tmp + n);
      }
    }
  }

  int recvBytes(char* buf, size_t len) override {
    if (!established_) return -1;
    if (!decBuf_.empty()) {
      size_t take = std::min(len, decBuf_.size());
      std::memcpy(buf, decBuf_.data(), take);
      decBuf_.erase(decBuf_.begin(), decBuf_.begin() + static_cast<ptrdiff_t>(take));
      return static_cast<int>(take);
    }

    while (true) {
      if (encInBuf_.empty()) {
        uint8_t tmp[8192];
        int n = recv(sock_, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (n <= 0) return n;
        encInBuf_.insert(encInBuf_.end(), tmp, tmp + n);
      }

      SecBuffer bufs[4]{};
      bufs[0].BufferType = SECBUFFER_DATA;
      bufs[0].pvBuffer = encInBuf_.data();
      bufs[0].cbBuffer = static_cast<unsigned long>(encInBuf_.size());
      bufs[1].BufferType = SECBUFFER_EMPTY;
      bufs[2].BufferType = SECBUFFER_EMPTY;
      bufs[3].BufferType = SECBUFFER_EMPTY;

      SecBufferDesc desc{};
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = bufs;

      SECURITY_STATUS ss = DecryptMessage(&ctx_, &desc, 0, nullptr);
      if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        uint8_t tmp[8192];
        int n = recv(sock_, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (n <= 0) return n;
        encInBuf_.insert(encInBuf_.end(), tmp, tmp + n);
        continue;
      }
      if (ss == SEC_I_CONTEXT_EXPIRED) {
        return 0;
      }
      if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE) {
        return -1;
      }

      SecBuffer* dataBuf = nullptr;
      SecBuffer* extraBuf = nullptr;
      for (int i = 0; i < 4; ++i) {
        if (bufs[i].BufferType == SECBUFFER_DATA) dataBuf = &bufs[i];
        else if (bufs[i].BufferType == SECBUFFER_EXTRA) extraBuf = &bufs[i];
      }

      if (dataBuf && dataBuf->cbBuffer > 0) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(dataBuf->pvBuffer);
        decBuf_.insert(decBuf_.end(), p, p + dataBuf->cbBuffer);
      }

      if (extraBuf && extraBuf->cbBuffer > 0) {
        std::vector<uint8_t> rem(
            reinterpret_cast<const uint8_t*>(extraBuf->pvBuffer),
            reinterpret_cast<const uint8_t*>(extraBuf->pvBuffer) + extraBuf->cbBuffer);
        encInBuf_.swap(rem);
      } else {
        encInBuf_.clear();
      }

      if (!decBuf_.empty()) {
        size_t take = std::min(len, decBuf_.size());
        std::memcpy(buf, decBuf_.data(), take);
        decBuf_.erase(decBuf_.begin(), decBuf_.begin() + static_cast<ptrdiff_t>(take));
        return static_cast<int>(take);
      }
    }
  }

  int sendBytes(const char* buf, size_t len) override {
    if (!established_) return -1;
    size_t sentTotal = 0;
    const size_t maxChunk = sizes_.cbMaximumMessage > 0 ? sizes_.cbMaximumMessage : 16384;
    while (sentTotal < len) {
      size_t chunk = std::min(len - sentTotal, maxChunk);
      std::vector<uint8_t> msg(sizes_.cbHeader + chunk + sizes_.cbTrailer);
      std::memcpy(msg.data() + sizes_.cbHeader, buf + sentTotal, chunk);

      SecBuffer bufs[4]{};
      bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
      bufs[0].pvBuffer = msg.data();
      bufs[0].cbBuffer = sizes_.cbHeader;
      bufs[1].BufferType = SECBUFFER_DATA;
      bufs[1].pvBuffer = msg.data() + sizes_.cbHeader;
      bufs[1].cbBuffer = static_cast<unsigned long>(chunk);
      bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
      bufs[2].pvBuffer = msg.data() + sizes_.cbHeader + chunk;
      bufs[2].cbBuffer = sizes_.cbTrailer;
      bufs[3].BufferType = SECBUFFER_EMPTY;

      SecBufferDesc desc{};
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers = 4;
      desc.pBuffers = bufs;

      if (EncryptMessage(&ctx_, 0, &desc, 0) != SEC_E_OK) return -1;
      size_t outLen = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
      if (!sendRaw(reinterpret_cast<const char*>(msg.data()), outLen)) return -1;
      sentTotal += chunk;
    }
    return static_cast<int>(sentTotal);
  }

  void shutdownTls() override {
    if (!established_ || !hasCtx_) return;
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer outBuf{};
    outBuf.BufferType = SECBUFFER_TOKEN;
    outBuf.pvBuffer = &type;
    outBuf.cbBuffer = sizeof(type);
    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 1;
    desc.pBuffers = &outBuf;
    if (ApplyControlToken(&ctx_, &desc) == SEC_E_OK) {
      SecBuffer respBuf{};
      respBuf.BufferType = SECBUFFER_TOKEN;
      SecBufferDesc respDesc{};
      respDesc.ulVersion = SECBUFFER_VERSION;
      respDesc.cBuffers = 1;
      respDesc.pBuffers = &respBuf;
      DWORD ctxAttr = 0;
      TimeStamp expiry{};
      if (AcceptSecurityContext(cred_, &ctx_, nullptr, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                0, nullptr, &respDesc, &ctxAttr, &expiry) == SEC_E_OK) {
        if (respBuf.cbBuffer > 0 && respBuf.pvBuffer) {
          sendRaw(reinterpret_cast<const char*>(respBuf.pvBuffer), respBuf.cbBuffer);
          FreeContextBuffer(respBuf.pvBuffer);
        }
      }
    }
    established_ = false;
  }

private:
  bool sendRaw(const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
      int n = send(sock_, data + off, static_cast<int>(len - off), 0);
      if (n <= 0) return false;
      off += static_cast<size_t>(n);
    }
    return true;
  }

  SOCKET sock_ = INVALID_SOCKET;
  CredHandle* cred_ = nullptr;
  CtxtHandle ctx_{};
  bool hasCtx_ = false;
  bool established_ = false;
  SecPkgContext_StreamSizes sizes_{};
  std::vector<uint8_t> encInBuf_;
  std::vector<uint8_t> decBuf_;
};

} // namespace

TlsContext::TlsContext() = default;
TlsContext::~TlsContext() = default;

bool TlsContext::init(const TlsConfig& cfg, std::string& outError) {
  ready_ = false;
  impl_.reset();
  if (!cfg.enabled) return true;

  auto impl = std::make_unique<Impl>();

  const wchar_t* container = L"NetPulse2D_SelfSigned_TLS";
  if (!CryptAcquireContextW(&impl->hProv, container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0)) {
    if (!CryptAcquireContextW(&impl->hProv, container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
      outError = "CryptAcquireContextW failed (" + std::to_string(GetLastError()) + ")";
      return false;
    }
  }

  if (!CryptGetUserKey(impl->hProv, AT_KEYEXCHANGE, &impl->hKey)) {
    if (!CryptGenKey(impl->hProv, AT_KEYEXCHANGE, (2048U << 16) | CRYPT_EXPORTABLE, &impl->hKey)) {
      outError = "CryptGenKey failed (" + std::to_string(GetLastError()) + ")";
      return false;
    }
  }

  std::wstring wCn(cfg.commonName.begin(), cfg.commonName.end());
  std::wstring x500 = L"CN=" + (wCn.empty() ? L"localhost" : wCn);
  DWORD cbEncoded = 0;
  if (!CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &cbEncoded, nullptr)) {
    outError = "CertStrToNameW size failed";
    return false;
  }
  std::vector<BYTE> subjBytes(cbEncoded);
  if (!CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR, nullptr, subjBytes.data(), &cbEncoded, nullptr)) {
    outError = "CertStrToNameW encode failed";
    return false;
  }

  CERT_NAME_BLOB subjBlob{};
  subjBlob.cbData = cbEncoded;
  subjBlob.pbData = subjBytes.data();

  CRYPT_KEY_PROV_INFO kpi{};
  kpi.pwszContainerName = const_cast<LPWSTR>(container);
  kpi.pwszProvName = const_cast<LPWSTR>(MS_ENH_RSA_AES_PROV_W);
  kpi.dwProvType = PROV_RSA_AES;
  kpi.dwKeySpec = AT_KEYEXCHANGE;

  CRYPT_ALGORITHM_IDENTIFIER sigAlg{};
  sigAlg.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);

  SYSTEMTIME st{};
  GetSystemTime(&st);
  st.wYear += 2;

  impl->cert = CertCreateSelfSignCertificate(impl->hProv, &subjBlob, 0, &kpi, &sigAlg, nullptr, &st, nullptr);
  if (!impl->cert) {
    outError = "CertCreateSelfSignCertificate failed (" + std::to_string(GetLastError()) + ")";
    return false;
  }

  SCHANNEL_CRED scred{};
  scred.dwVersion = SCHANNEL_CRED_VERSION;
  scred.cCreds = 1;
  scred.paCred = &impl->cert;
  scred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
  scred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

  TimeStamp expiry{};
  SECURITY_STATUS ss = AcquireCredentialsHandleW(
      nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
      nullptr, &scred, nullptr, nullptr, &impl->cred, &expiry);
  if (ss != SEC_E_OK) {
    outError = "AcquireCredentialsHandleW failed (" + std::to_string(ss) + ")";
    return false;
  }
  impl->hasCred = true;
  impl_ = std::move(impl);
  ready_ = true;
  return true;
}

std::unique_ptr<TlsConnection> TlsContext::wrapAcceptedSocket(uintptr_t rawSock) const {
  if (!ready_ || !impl_) return nullptr;
  return std::make_unique<WinSChannelConnection>(static_cast<SOCKET>(rawSock), &impl_->cred);
}

#else

struct TlsContext::Impl {
  SSL_CTX* ctx = nullptr;
  ~Impl() {
    if (ctx) SSL_CTX_free(ctx);
  }
};

namespace {

class OpenSslConnection final : public TlsConnection {
public:
  OpenSslConnection(int sock, SSL_CTX* ctx) : ssl_(SSL_new(ctx)) {
    if (ssl_) SSL_set_fd(ssl_, sock);
  }
  ~OpenSslConnection() override {
    shutdownTls();
    if (ssl_) {
      SSL_free(ssl_);
      ssl_ = nullptr;
    }
  }
  bool handshake() override {
    return ssl_ && SSL_accept(ssl_) == 1;
  }
  int recvBytes(char* buf, size_t len) override {
    if (!ssl_) return -1;
    return SSL_read(ssl_, buf, static_cast<int>(len));
  }
  int sendBytes(const char* buf, size_t len) override {
    if (!ssl_) return -1;
    size_t sent = 0;
    while (sent < len) {
      int n = SSL_write(ssl_, buf + sent, static_cast<int>(len - sent));
      if (n <= 0) return -1;
      sent += static_cast<size_t>(n);
    }
    return static_cast<int>(sent);
  }
  void shutdownTls() override {
    if (ssl_ && !shut_) {
      shut_ = true;
      SSL_shutdown(ssl_);
    }
  }

private:
  SSL* ssl_ = nullptr;
  bool shut_ = false;
};

bool generateSelfSignedPem(const std::filesystem::path& certPath,
                           const std::filesystem::path& keyPath,
                           const std::string& cn) {
  std::error_code ec;
  std::filesystem::create_directories(certPath.parent_path(), ec);

  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!pctx) return false;
  EVP_PKEY* pkey = nullptr;
  bool ok = (EVP_PKEY_keygen_init(pctx) == 1) &&
            (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) == 1) &&
            (EVP_PKEY_keygen(pctx, &pkey) == 1);
  EVP_PKEY_CTX_free(pctx);
  if (!ok || !pkey) return false;

  X509* x509 = X509_new();
  if (!x509) {
    EVP_PKEY_free(pkey);
    return false;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 365L * 24L * 3600L * 2L);
  X509_set_pubkey(x509, pkey);

  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(cn.empty() ? "localhost" : cn.c_str()),
                             -1, -1, 0);
  X509_set_issuer_name(x509, name);

  bool signedOk = (X509_sign(x509, pkey, EVP_sha256()) > 0);
  if (signedOk) {
    FILE* kf = fopen(keyPath.c_str(), "wb");
    FILE* cf = fopen(certPath.c_str(), "wb");
    if (kf && cf) {
      PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr);
      PEM_write_X509(cf, x509);
      fclose(kf);
      fclose(cf);
      chmod(keyPath.c_str(), 0600);
    } else {
      if (kf) fclose(kf);
      if (cf) fclose(cf);
      signedOk = false;
    }
  }

  X509_free(x509);
  EVP_PKEY_free(pkey);
  return signedOk;
}

} // namespace

TlsContext::TlsContext() = default;
TlsContext::~TlsContext() = default;

bool TlsContext::init(const TlsConfig& cfg, std::string& outError) {
  ready_ = false;
  impl_.reset();
  if (!cfg.enabled) return true;

  auto impl = std::make_unique<Impl>();
  impl->ctx = SSL_CTX_new(TLS_server_method());
  if (!impl->ctx) {
    outError = "SSL_CTX_new failed";
    return false;
  }
  SSL_CTX_set_min_proto_version(impl->ctx, TLS1_2_VERSION);

  std::filesystem::path cert = cfg.certPath;
  std::filesystem::path key = cfg.keyPath;
  if (cert.empty() || key.empty()) {
    cert = cfg.autoCertDir / "server.crt";
    key = cfg.autoCertDir / "server.key";
    std::error_code ec;
    if (!std::filesystem::exists(cert, ec) || !std::filesystem::exists(key, ec)) {
      if (!generateSelfSignedPem(cert, key, cfg.commonName)) {
        outError = "Failed to generate self-signed TLS certificate";
        return false;
      }
    }
  }

  if (SSL_CTX_use_certificate_file(impl->ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0 ||
      SSL_CTX_use_PrivateKey_file(impl->ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0 ||
      SSL_CTX_check_private_key(impl->ctx) != 1) {
    outError = "Failed to load TLS certificate or private key";
    return false;
  }

  impl_ = std::move(impl);
  ready_ = true;
  return true;
}

std::unique_ptr<TlsConnection> TlsContext::wrapAcceptedSocket(uintptr_t rawSock) const {
  if (!ready_ || !impl_ || !impl_->ctx) return nullptr;
  return std::make_unique<OpenSslConnection>(static_cast<int>(rawSock), impl_->ctx);
}

#endif

} // namespace netpulse
