#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

#include "actions.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace netpulse {

namespace {

#ifdef _WIN32
std::wstring utf8ToWide(const std::string& s) {
  if (s.empty()) return {};
  int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
  return out;
}
#endif

std::string toLowerAscii(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

} // namespace

bool isValidIpAddress(const std::string& ip) {
  if (ip.empty() || ip.size() > 64) return false;
  struct in_addr in4{};
  if (inet_pton(AF_INET, ip.c_str(), &in4) == 1) return true;
  struct in6_addr in6{};
  return inet_pton(AF_INET6, ip.c_str(), &in6) == 1;
}

bool isLoopbackOrUnspecifiedIp(const std::string& ip) {
  return ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "::";
}

bool isProtectedSystemProcess(uint32_t pid, const std::string& procName) {
#ifdef _WIN32
  if (pid <= 4 || pid == GetCurrentProcessId()) return true;
  const std::string lower = toLowerAscii(procName);
  return lower == "system" || lower == "system idle" || lower == "registry" ||
         lower == "csrss.exe" || lower == "smss.exe" || lower == "lsaiso.exe" ||
         lower == "wininit.exe" || lower == "winlogon.exe" ||
         lower == "services.exe" || lower == "lsass.exe" ||
         lower == "dwm.exe" || lower == "svchost.exe";
#else
  if (pid <= 1 || pid == static_cast<uint32_t>(getpid())) return true;
  const std::string lower = toLowerAscii(procName);
  return lower == "systemd" || lower == "init" || lower == "sshd" ||
         lower == "dockerd" || lower == "containerd" || lower == "netpulse";
#endif
}

bool terminateTargetProcess(uint32_t pid, const std::string& procName, std::string& outError) {
  if (isProtectedSystemProcess(pid, procName)) {
    outError = "Processo protegido do sistema nao pode ser encerrado";
    return false;
  }

#ifdef _WIN32
  HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!hProc) {
    DWORD err = GetLastError();
    outError = (err == ERROR_ACCESS_DENIED)
                   ? "Permissao negada (execute como Administrador para encerrar este processo)"
                   : ("Falha ao abrir processo (erro " + std::to_string(err) + ")");
    return false;
  }

  BOOL ok = TerminateProcess(hProc, 1);
  DWORD err = GetLastError();
  CloseHandle(hProc);
  if (!ok) {
    outError = "Falha ao encerrar processo (erro " + std::to_string(err) + ")";
    return false;
  }
  return true;
#else
  if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
    outError = "Falha ao encerrar processo: " + std::string(std::strerror(errno));
    return false;
  }
  return true;
#endif
}

#ifdef _WIN32
namespace {
bool runNetshFirewall(const std::wstring& params, bool isElevated, std::string& outError) {
  SHELLEXECUTEINFOW sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = isElevated ? L"open" : L"runas";
  sei.lpFile = L"netsh.exe";
  sei.lpParameters = params.c_str();
  sei.nShow = SW_HIDE;

  if (!ShellExecuteExW(&sei)) {
    DWORD err = GetLastError();
    outError = (err == ERROR_CANCELLED)
                   ? "Elevacao UAC cancelada pelo usuario"
                   : ("Falha ao executar netsh (erro " + std::to_string(err) + ")");
    return false;
  }

  if (sei.hProcess) {
    WaitForSingleObject(sei.hProcess, 8000);
    DWORD exitCode = 1;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);
    if (exitCode != 0) {
      outError = "netsh retornou codigo " + std::to_string(exitCode);
      return false;
    }
  }
  return true;
}
} // namespace
#endif

bool blockIpInWindowsFirewall(const std::string& ip, bool isElevated, std::string& outError) {
#ifdef _WIN32
  if (!isValidIpAddress(ip)) {
    outError = "Endereco IP invalido";
    return false;
  }
  if (isLoopbackOrUnspecifiedIp(ip)) {
    outError = "IP de loopback/sistema nao pode ser bloqueado";
    return false;
  }

  const std::wstring wIp = utf8ToWide(ip);
  const std::wstring params = L"advfirewall firewall add rule name=\"NetPulse2D Block " + wIp +
                              L"\" dir=out action=block remoteip=" + wIp;
  return runNetshFirewall(params, isElevated, outError);
#else
  (void)ip;
  (void)isElevated;
  outError = "Bloqueio automatico via firewall disponivel apenas no Windows";
  return false;
#endif
}

bool unblockIpInWindowsFirewall(const std::string& ip, bool isElevated, std::string& outError) {
#ifdef _WIN32
  if (!isValidIpAddress(ip)) {
    outError = "Endereco IP invalido";
    return false;
  }
  if (isLoopbackOrUnspecifiedIp(ip)) {
    outError = "IP de loopback/sistema nao permitido";
    return false;
  }

  const std::wstring wIp = utf8ToWide(ip);
  const std::wstring params = L"advfirewall firewall delete rule name=\"NetPulse2D Block " + wIp + L"\"";
  return runNetshFirewall(params, isElevated, outError);
#else
  (void)ip;
  (void)isElevated;
  outError = "Reversao de firewall disponivel apenas no Windows";
  return false;
#endif
}

namespace {
bool isSafeRuleToken(const std::string& s) {
  if (s.empty() || s.size() > 96) return false;
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == ' ' || c == '-' || c == '_' || c == '.' || c == ':') continue;
    return false;
  }
  return true;
}

bool isSafeExePath(const std::string& p) {
  if (p.empty()) return true;
  if (p.size() > 260) return false;
  for (unsigned char c : p) {
    if (c < 32 || c == '"' || c == '\'' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>' || c == '`' || c == '$') {
      return false;
    }
  }
  return true;
}
} // namespace

bool applyOsFirewallRule(const std::string& ruleName,
                         const std::string& direction,
                         const std::string& action,
                         const std::string& protocol,
                         const std::string& remoteIp,
                         uint16_t remotePort,
                         const std::string& programPath,
                         bool isElevated,
                         std::string& outError) {
  if (!isSafeRuleToken(ruleName)) {
    outError = "Nome de regra de firewall invalido";
    return false;
  }
  if (!remoteIp.empty() && (!isValidIpAddress(remoteIp) || isLoopbackOrUnspecifiedIp(remoteIp))) {
    outError = "IP remoto invalido ou protegido (loopback/unspecified)";
    return false;
  }
  if (!isSafeExePath(programPath)) {
    outError = "Caminho de executavel contem caracteres invalidos";
    return false;
  }
  const std::string dir = (direction == "in") ? "in" : "out";
  const std::string act = (action == "allow") ? "allow" : "block";
  std::string proto = "ANY";
  if (protocol == "TCP" || protocol == "tcp") proto = "TCP";
  else if (protocol == "UDP" || protocol == "udp") proto = "UDP";
  if (remotePort > 0 && proto == "ANY") proto = "TCP";

#ifdef _WIN32
  std::wstring params = L"advfirewall firewall add rule name=\"" + utf8ToWide(ruleName) +
                        L"\" dir=" + utf8ToWide(dir) +
                        L" action=" + utf8ToWide(act) +
                        L" protocol=" + utf8ToWide(proto);
  if (!remoteIp.empty()) params += L" remoteip=" + utf8ToWide(remoteIp);
  if (remotePort > 0) params += L" remoteport=" + std::to_wstring(remotePort);
  if (!programPath.empty()) params += L" program=\"" + utf8ToWide(programPath) + L"\"";
  return runNetshFirewall(params, isElevated, outError);
#else
  (void)isElevated;
  outError = "Aplicacao automatica de firewall no SO disponivel apenas no Windows neste ciclo (regra salva no banco)";
  return false;
#endif
}

bool removeOsFirewallRule(const std::string& ruleName, bool isElevated, std::string& outError) {
  if (!isSafeRuleToken(ruleName)) {
    outError = "Nome de regra invalido";
    return false;
  }
#ifdef _WIN32
  const std::wstring params = L"advfirewall firewall delete rule name=\"" + utf8ToWide(ruleName) + L"\"";
  return runNetshFirewall(params, isElevated, outError);
#else
  (void)isElevated;
  outError = "Remocao automatica de firewall no SO disponivel apenas no Windows neste ciclo";
  return false;
#endif
}

bool relaunchAsAdministrator() {
#ifdef _WIN32
  wchar_t exeBuf[MAX_PATH * 2] = {};
  if (GetModuleFileNameW(nullptr, exeBuf, static_cast<DWORD>(std::size(exeBuf))) == 0) {
    return false;
  }
  HINSTANCE res = ShellExecuteW(nullptr, L"runas", exeBuf, L"--wait-slot --no-browser", nullptr, SW_SHOWNORMAL);
  return reinterpret_cast<INT_PTR>(res) > 32;
#else
  return false;
#endif
}

} // namespace netpulse
