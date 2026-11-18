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
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <fstream>
#include <sstream>
#endif

#include "discovery_engine.hpp"
#include "../models.hpp"
#include "../net_monitor.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

namespace netpulse {

namespace {

uint64_t nowEpochMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string toLowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string cidr24OfIpv4(const std::string& ip) {
  struct in_addr a{};
  if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return {};
  uint32_t hostOrder = ntohl(a.s_addr);
  hostOrder &= 0xFFFFFF00U;
  struct in_addr net{};
  net.s_addr = htonl(hostOrder);
  char buf[INET_ADDRSTRLEN] = {};
  if (!inet_ntop(AF_INET, &net, buf, sizeof(buf))) return {};
  return std::string(buf) + "/24";
}

bool isValidMacCandidate(const std::string& mac) {
  if (mac.size() != 17) return false;
  if (mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") return false;
  // Exclude multicast MACs (bit 0 of first octet)
  unsigned int firstByte = static_cast<unsigned int>(std::strtoul(mac.substr(0, 2).c_str(), nullptr, 16));
  if ((firstByte & 0x01U) != 0) return false;
  return true;
}

const std::unordered_map<std::string, const char*>& ouiDatabase() {
  static const std::unordered_map<std::string, const char*> kDb = {
      // Network Infrastructure & Routers
      {"00:0C:42", "MikroTik"}, {"48:8F:5A", "MikroTik"}, {"B8:69:F4", "MikroTik"}, {"D4:01:C3", "MikroTik"}, {"E4:8D:8C", "MikroTik"},
      {"18:E8:29", "Ubiquiti"}, {"24:5A:4C", "Ubiquiti"}, {"68:D7:9A", "Ubiquiti"}, {"74:83:C2", "Ubiquiti"}, {"80:2A:A8", "Ubiquiti"}, {"F0:9F:C2", "Ubiquiti"},
      {"14:CC:20", "TP-Link"}, {"50:C7:BF", "TP-Link"}, {"60:32:B1", "TP-Link"}, {"98:DA:C4", "TP-Link"}, {"B0:BE:76", "TP-Link"}, {"D8:07:B6", "TP-Link"},
      {"00:1B:44", "Cisco"}, {"00:1E:13", "Cisco"}, {"3C:57:31", "Cisco"}, {"F4:CF:E2", "Cisco"},
      {"00:14:BF", "Linksys"}, {"C8:3A:35", "Tenda"}, {"D8:32:14", "Tenda"},
      {"00:17:7C", "D-Link"}, {"1C:7E:E5", "D-Link"}, {"B8:A3:86", "D-Link"},
      {"04:D4:C4", "ASUS"}, {"2C:FD:A1", "ASUS"}, {"38:D5:47", "ASUS"}, {"AC:9E:17", "ASUS"},
      {"00:1F:C6", "ASUS"}, {"04:92:26", "ASUS"},
      {"3C:84:6A", "TP-Link"}, {"AC:84:C6", "TP-Link"}, {"90:9A:4A", "TP-Link"},

      // Intelbras / Cameras / NVR
      {"38:AF:29", "Intelbras"}, {"90:E7:C4", "Intelbras"}, {"D8:C4:97", "Intelbras"}, {"EC:71:DB", "Intelbras"},
      {"00:12:12", "Hikvision"}, {"44:19:B6", "Hikvision"}, {"54:C4:15", "Hikvision"}, {"C0:56:E3", "Hikvision"},
      {"3C:EF:8C", "Dahua"}, {"90:02:A9", "Dahua"}, {"E0:50:8B", "Dahua"},

      // PC NICs & Motherboards
      {"00:1B:21", "Intel"}, {"3C:97:0E", "Intel"}, {"68:05:CA", "Intel"}, {"8C:8D:28", "Intel"}, {"A4:C4:94", "Intel"}, {"B4:2E:99", "Intel"}, {"D4:3D:7E", "Intel"},
      {"00:E0:4C", "Realtek"}, {"1C:1B:0D", "GigaByte"}, {"40:8D:5C", "GigaByte"}, {"D8:BB:C1", "MSI"}, {"2C:F0:5D", "MSI"},
      {"18:66:DA", "Dell"}, {"54:9F:35", "Dell"}, {"B8:AC:6F", "Dell"}, {"F8:BC:12", "Dell"},
      {"00:21:CC", "Lenovo"}, {"28:D2:44", "Lenovo"}, {"50:7B:9D", "Lenovo"}, {"98:FA:9B", "Lenovo"},
      {"00:1A:4B", "HP"}, {"3C:D9:2B", "HP"}, {"94:57:A5", "HP"}, {"DC:4A:3E", "HP"},
      {"00:0A:F7", "Broadcom"}, {"00:10:18", "Broadcom"}, {"20:10:7A", "Qualcomm"},

      // Mobile / Smart / IoT / SBC
      {"00:17:F2", "Apple"}, {"28:CF:E9", "Apple"}, {"3C:15:C2", "Apple"}, {"A4:83:E7", "Apple"}, {"F0:18:98", "Apple"},
      {"00:16:32", "Samsung"}, {"24:4B:03", "Samsung"}, {"50:01:BB", "Samsung"}, {"8C:77:12", "Samsung"}, {"CC:07:AB", "Samsung"},
      {"28:6C:07", "Xiaomi"}, {"64:CC:2E", "Xiaomi"}, {"78:11:DC", "Xiaomi"}, {"9C:99:A0", "Xiaomi"},
      {"00:18:82", "Huawei"}, {"24:69:A5", "Huawei"}, {"70:72:3C", "Huawei"},
      {"24:0A:C4", "Espressif IoT"}, {"30:AE:A4", "Espressif IoT"}, {"4C:11:AE", "Espressif IoT"}, {"84:F3:EB", "Espressif IoT"}, {"A4:CF:12", "Espressif IoT"}, {"DC:4F:22", "Espressif IoT"},
      {"28:CD:C1", "Raspberry Pi"}, {"B8:27:EB", "Raspberry Pi"}, {"D8:3A:DD", "Raspberry Pi"}, {"DC:A6:32", "Raspberry Pi"}, {"E4:5F:01", "Raspberry Pi"},
      {"3C:5A:B4", "Google"}, {"54:60:09", "Google"}, {"F4:F5:D8", "Google"},
      {"18:74:2E", "Amazon"}, {"40:B4:CD", "Amazon"}, {"68:54:FD", "Amazon"},

      // Printers
      {"00:00:48", "Epson"}, {"00:26:AB", "Epson"}, {"64:EB:8C", "Epson"},
      {"00:1B:A9", "Brother"}, {"30:05:5C", "Brother"}, {"D4:6A:6A", "Brother"},

      // Virtualization / Hypervisors / NAS
      {"00:05:69", "VMware"}, {"00:0C:29", "VMware"}, {"00:50:56", "VMware"},
      {"00:15:5D", "Microsoft Hyper-V"},
      {"08:00:27", "VirtualBox"},
      {"52:54:00", "QEMU / KVM"},
      {"00:11:32", "Synology"}, {"00:08:9B", "QNAP"},
  };
  return kDb;
}

bool probeTcpPortQuick(const std::string& ip, uint16_t port, int timeoutMs, double& outRttMs) {
  struct sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return false;

#ifdef _WIN32
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return false;
  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
#else
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0) return false;
  int flags = fcntl(s, F_GETFL, 0);
  if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

  const auto t0 = std::chrono::steady_clock::now();
  int rc = connect(s, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
  bool ok = false;
  if (rc == 0) {
    ok = true;
  } else {
#ifdef _WIN32
    int err = WSAGetLastError();
    bool inProg = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
    int err = errno;
    bool inProg = (err == EINPROGRESS || err == EWOULDBLOCK);
#endif
    if (inProg) {
      fd_set wset, eset;
      FD_ZERO(&wset);
      FD_ZERO(&eset);
      FD_SET(s, &wset);
      FD_SET(s, &eset);
      timeval tv{};
      tv.tv_sec = timeoutMs / 1000;
      tv.tv_usec = (timeoutMs % 1000) * 1000;
#ifdef _WIN32
      int sel = select(0, nullptr, &wset, &eset, &tv);
#else
      int sel = select(s + 1, nullptr, &wset, &eset, &tv);
#endif
      if (sel > 0) {
        int soErr = 0;
        socklen_t len = sizeof(soErr);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len) == 0 && soErr == 0) {
          ok = true;
        }
      }
    }
  }
  const auto t1 = std::chrono::steady_clock::now();
#ifdef _WIN32
  closesocket(s);
#else
  ::close(s);
#endif
  if (ok) {
    outRttMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
  }
  return ok;
}

std::string resolveLanHostname(const std::string& ip) {
  struct sockaddr_in sa{};
  sa.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return {};
  char hostBuf[NI_MAXHOST] = {};
  if (getnameinfo(reinterpret_cast<const sockaddr*>(&sa), sizeof(sa), hostBuf, sizeof(hostBuf),
                  nullptr, 0, NI_NAMEREQD | NI_NOFQDN) == 0) {
    std::string h = hostBuf;
    if (h != ip) return h;
  }
  return {};
}

std::vector<uint16_t> scanCommonPorts(const std::string& ip, double& ioBestRttMs) {
  static constexpr std::array<uint16_t, 8> kPorts = {80, 443, 22, 445, 53, 3389, 554, 9100};
  std::vector<uint16_t> open;
  for (uint16_t p : kPorts) {
    double rtt = 0.0;
    if (probeTcpPortQuick(ip, p, 50, rtt)) {
      open.push_back(p);
      if (ioBestRttMs <= 0.0 || rtt < ioBestRttMs) ioBestRttMs = rtt;
    }
  }
  return open;
}

std::string joinPorts(const std::vector<uint16_t>& ports) {
  std::string out;
  for (size_t i = 0; i < ports.size(); ++i) {
    if (i > 0) out.push_back(',');
    out += std::to_string(ports[i]);
  }
  return out;
}

std::vector<uint16_t> splitPorts(const std::string& csv) {
  std::vector<uint16_t> out;
  size_t pos = 0;
  while (pos < csv.size()) {
    auto comma = csv.find(',', pos);
    if (comma == std::string::npos) comma = csv.size();
    int p = std::atoi(csv.substr(pos, comma - pos).c_str());
    if (p > 0 && p <= 65535) out.push_back(static_cast<uint16_t>(p));
    pos = comma + 1;
  }
  return out;
}

} // namespace

std::string normalizeMacUpper(const std::string& rawMac) {
  std::string hex;
  hex.reserve(12);
  for (unsigned char c : rawMac) {
    if (std::isxdigit(c)) {
      hex.push_back(static_cast<char>(std::toupper(c)));
    }
  }
  if (hex.size() != 12) return {};
  std::string out;
  out.reserve(17);
  for (size_t i = 0; i < 12; i += 2) {
    if (i > 0) out.push_back(':');
    out.push_back(hex[i]);
    out.push_back(hex[i + 1]);
  }
  return out;
}

bool isLocallyAdministeredMac(const std::string& mac) {
  std::string norm = normalizeMacUpper(mac);
  if (norm.size() < 2) return false;
  unsigned int firstByte = static_cast<unsigned int>(std::strtoul(norm.substr(0, 2).c_str(), nullptr, 16));
  return (firstByte & 0x02U) != 0;
}

std::string lookupOuiVendor(const std::string& mac) {
  std::string norm = normalizeMacUpper(mac);
  if (norm.size() < 8) return {};
  const std::string prefix = norm.substr(0, 8);
  const auto& db = ouiDatabase();
  auto it = db.find(prefix);
  if (it != db.end()) {
    return it->second;
  }
  if (isLocallyAdministeredMac(norm)) {
    return "MAC Privado / Randomizado";
  }
  return {};
}

std::string inferDeviceType(bool isLocalHost,
                            bool isGateway,
                            const std::string& vendor,
                            const std::string& hostname,
                            const std::vector<uint16_t>& openPorts) {
  if (isLocalHost) return "Estação Local";
  if (isGateway) return "Roteador / Gateway";

  auto hasPort = [&](uint16_t p) {
    return std::find(openPorts.begin(), openPorts.end(), p) != openPorts.end();
  };
  const std::string vLow = toLowerCopy(vendor);
  const std::string hLow = toLowerCopy(hostname);

  if (hasPort(9100) || vLow.find("epson") != std::string::npos || vLow.find("brother") != std::string::npos) {
    return "Impressora";
  }
  if (hasPort(554) || vLow.find("hikvision") != std::string::npos ||
      vLow.find("dahua") != std::string::npos || vLow.find("intelbras") != std::string::npos) {
    return "Câmera / NVR";
  }
  if (vLow.find("vmware") != std::string::npos || vLow.find("hyper-v") != std::string::npos ||
      vLow.find("virtualbox") != std::string::npos || vLow.find("qemu") != std::string::npos) {
    return "Máquina Virtual";
  }
  if (vLow.find("synology") != std::string::npos || vLow.find("qnap") != std::string::npos ||
      (hasPort(22) && (hasPort(445) || hasPort(80) || hasPort(443))) ||
      vLow.find("raspberry") != std::string::npos) {
    return "Servidor / NAS";
  }
  if (vLow.find("mikrotik") != std::string::npos || vLow.find("ubiquiti") != std::string::npos ||
      vLow.find("cisco") != std::string::npos || vLow.find("tp-link") != std::string::npos) {
    return "Ativo de Rede";
  }
  if (vLow.find("espressif") != std::string::npos || vLow.find("google") != std::string::npos ||
      vLow.find("amazon") != std::string::npos || hasPort(8008)) {
    return "IoT / Smart Device";
  }
  if (hasPort(3389) || hasPort(445) || vLow.find("dell") != std::string::npos ||
      vLow.find("lenovo") != std::string::npos || hLow.find("desktop") != std::string::npos ||
      hLow.find("laptop") != std::string::npos) {
    return "Computador / Estação";
  }
  if (vLow.find("apple") != std::string::npos || vLow.find("samsung") != std::string::npos ||
      vLow.find("xiaomi") != std::string::npos || vLow.find("privado") != std::string::npos) {
    return "Dispositivo Móvel";
  }
  return "Dispositivo LAN";
}

std::vector<std::string> enumerateSubnetHosts(const std::string& ipOrCidr, size_t maxHosts) {
  std::vector<std::string> hosts;
  std::string baseIp = ipOrCidr;
  auto slash = ipOrCidr.find('/');
  if (slash != std::string::npos) {
    baseIp = ipOrCidr.substr(0, slash);
  }
  struct in_addr a{};
  if (inet_pton(AF_INET, baseIp.c_str(), &a) != 1) return hosts;

  uint32_t netHostOrder = ntohl(a.s_addr) & 0xFFFFFF00U;
  const size_t limit = std::min<size_t>(254, maxHosts);
  hosts.reserve(limit);
  for (uint32_t i = 1; i <= limit; ++i) {
    struct in_addr h{};
    h.s_addr = htonl(netHostOrder | i);
    char buf[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &h, buf, sizeof(buf))) {
      hosts.emplace_back(buf);
    }
  }
  return hosts;
}

DiscoveryEngine::DiscoveryEngine(HistoryStore& history, InterfaceMonitor& interfaces)
    : history_(history), interfaces_(interfaces) {}

DiscoveryEngine::~DiscoveryEngine() {
  stop();
}

void DiscoveryEngine::start() {
  if (running_.exchange(true)) return;
  {
    auto loaded = history_.loadLanDevices();
    std::lock_guard lock(mutex_);
    devices_ = std::move(loaded);
    knownKeys_.clear();
    for (const auto& d : devices_) knownKeys_.insert(d.deviceKey);
  }
  runPassiveRefresh();
  workerThread_ = std::jthread([this](std::stop_token st) { workerLoop(st); });
}

void DiscoveryEngine::stop() {
  if (!running_.exchange(false)) return;
  if (workerThread_.joinable()) {
    workerThread_.request_stop();
    wakeCv_.notify_all();
    workerThread_.join();
  }
}

bool DiscoveryEngine::triggerScanAsync(const std::string& subnetOverride) {
  if (scanRunning_.load()) return false;
  {
    std::lock_guard lk(wakeMutex_);
    scanRequested_ = true;
    pendingSubnetOverride_ = subnetOverride;
  }
  wakeCv_.notify_all();
  return true;
}

std::vector<LanDeviceRecord> DiscoveryEngine::harvestLocalAndArp(uint64_t nowMs) {
  std::vector<LanDeviceRecord> found;
  std::unordered_map<std::string, size_t> byIp;

  const auto ifSnap = interfaces_.collect(nowMs);
  std::unordered_map<uint32_t, std::string> ifNameByIdx;
  std::unordered_map<std::string, std::string> gwToIfName;
  std::unordered_set<std::string> localIps;
  std::vector<std::string> subnets;

  char hostNameBuf[256] = {};
  std::string localHostname;
  if (gethostname(hostNameBuf, sizeof(hostNameBuf)) == 0) {
    localHostname = hostNameBuf;
  }

  auto pushSubnet = [&](const std::string& cidr) {
    if (cidr.empty()) return;
    if (std::find(subnets.begin(), subnets.end(), cidr) == subnets.end()) {
      subnets.push_back(cidr);
    }
  };

  for (const auto& ifc : ifSnap.interfaces) {
    ifNameByIdx[ifc.ifIndex] = ifc.name;
    for (const auto& gw : ifc.gateways) {
      gwToIfName[gw] = ifc.name;
    }
    if (ifc.type == "loopback" || ifc.operStatus != "up") continue;
    for (const auto& ip : ifc.ipv4) {
      localIps.insert(ip);
      const std::string sub = cidr24OfIpv4(ip);
      if (ifc.isDefaultRoute || ifc.hardwareInterface) pushSubnet(sub);

      LanDeviceRecord selfRec;
      selfRec.mac = ifc.macAddress;
      selfRec.deviceKey = !selfRec.mac.empty() ? selfRec.mac : ("ip:" + ip);
      selfRec.ip = ip;
      selfRec.vendor = lookupOuiVendor(selfRec.mac);
      selfRec.hostname = localHostname;
      selfRec.deviceType = "Estação Local";
      selfRec.interfaceName = ifc.name;
      selfRec.subnet = sub;
      selfRec.isLocalHost = true;
      selfRec.online = true;
      selfRec.firstSeenMs = nowMs;
      selfRec.lastSeenMs = nowMs;
      byIp[ip] = found.size();
      found.push_back(std::move(selfRec));
    }
  }

  {
    std::lock_guard lock(mutex_);
    activeSubnets_ = std::move(subnets);
  }

#ifdef _WIN32
  ULONG size = 16384;
  std::vector<uint8_t> buf(size);
  ULONG rc = GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buf.data()), &size, FALSE);
  if (rc == ERROR_INSUFFICIENT_BUFFER) {
    buf.resize(size);
    rc = GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buf.data()), &size, FALSE);
  }
  if (rc == NO_ERROR) {
    const auto* tbl = reinterpret_cast<const MIB_IPNETTABLE*>(buf.data());
    for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
      const MIB_IPNETROW& row = tbl->table[i];
      if (row.dwType != MIB_IPNET_TYPE_DYNAMIC && row.dwType != MIB_IPNET_TYPE_STATIC) continue;
      struct in_addr a{};
      a.S_un.S_addr = row.dwAddr;
      char ipBuf[INET_ADDRSTRLEN] = {};
      if (!inet_ntop(AF_INET, &a, ipBuf, sizeof(ipBuf))) continue;
      std::string ip = ipBuf;
      if (classifyIpString(ip) != IpScope::Lan) continue;

      std::string mac = formatMacAddress(row.bPhysAddr, static_cast<size_t>(row.dwPhysAddrLen));
      if (!isValidMacCandidate(mac)) continue;

      if (byIp.find(ip) != byIp.end()) continue;
      LanDeviceRecord d;
      d.ip = ip;
      d.mac = mac;
      d.deviceKey = mac;
      d.vendor = lookupOuiVendor(mac);
      d.interfaceName = ifNameByIdx.count(row.dwIndex) ? ifNameByIdx[row.dwIndex] : "";
      d.subnet = cidr24OfIpv4(ip);
      d.isGateway = (gwToIfName.count(ip) > 0);
      d.online = true;
      d.firstSeenMs = nowMs;
      d.lastSeenMs = nowMs;
      d.deviceType = inferDeviceType(false, d.isGateway, d.vendor, "", {});
      byIp[ip] = found.size();
      found.push_back(std::move(d));
    }
  }
#else
  std::ifstream arpIn("/proc/net/arp");
  if (arpIn.is_open()) {
    std::string line;
    std::getline(arpIn, line);
    while (std::getline(arpIn, line)) {
      std::istringstream ss(line);
      std::string ip, hwType, flags, mac, mask, dev;
      if (!(ss >> ip >> hwType >> flags >> mac >> mask >> dev)) continue;
      if (flags == "0x0") continue; // incomplete ARP entry
      std::string normMac = normalizeMacUpper(mac);
      if (!isValidMacCandidate(normMac)) continue;
      if (classifyIpString(ip) != IpScope::Lan) continue;
      if (byIp.find(ip) != byIp.end()) continue;

      LanDeviceRecord d;
      d.ip = ip;
      d.mac = normMac;
      d.deviceKey = normMac;
      d.vendor = lookupOuiVendor(normMac);
      d.interfaceName = dev;
      d.subnet = cidr24OfIpv4(ip);
      d.isGateway = (gwToIfName.count(ip) > 0);
      d.online = true;
      d.firstSeenMs = nowMs;
      d.lastSeenMs = nowMs;
      d.deviceType = inferDeviceType(false, d.isGateway, d.vendor, "", {});
      byIp[ip] = found.size();
      found.push_back(std::move(d));
    }
  }
#endif

  return found;
}

bool DiscoveryEngine::runPassiveRefresh() {
  const uint64_t nowMs = nowEpochMs();
  auto harvested = harvestLocalAndArp(nowMs);
  if (harvested.empty()) return false;

  std::vector<LanDeviceRecord> newlyDiscovered;
  {
    std::lock_guard lock(mutex_);
    for (const auto& d : harvested) {
      if (!d.isLocalHost && knownKeys_.insert(d.deviceKey).second) {
        newlyDiscovered.push_back(d);
      }
    }
  }

  history_.upsertLanDevices(harvested, false);
  for (const auto& nd : newlyDiscovered) {
    history_.recordManualAction(
        "info",
        "Novo dispositivo detectado na LAN: " + nd.ip,
        (nd.vendor.empty() ? "MAC " + nd.mac : nd.vendor + " (" + nd.mac + ")") + " · " + nd.interfaceName);
  }

  auto refreshed = history_.loadLanDevices();
  std::lock_guard lock(mutex_);
  devices_ = std::move(refreshed);
  return true;
}

void DiscoveryEngine::runActiveScan(std::stop_token st, const std::string& subnetOverride) {
  scanRunning_.store(true);
  const uint64_t nowMs = nowEpochMs();

  auto passiveBase = harvestLocalAndArp(nowMs);
  std::vector<std::string> targetCidrs;
  if (!subnetOverride.empty()) {
    targetCidrs.push_back(subnetOverride);
  } else {
    std::lock_guard lock(mutex_);
    targetCidrs = activeSubnets_;
  }
  if (targetCidrs.size() > 2) targetCidrs.resize(2); // Guard against scanning huge virtual interface lists

  std::unordered_map<std::string, LanDeviceRecord> merged;
  for (auto& d : passiveBase) {
    if (!d.isLocalHost) d.online = false; // verified by active sweep below
    merged[d.ip] = std::move(d);
  }

  std::vector<std::string> candidateIps;
  for (const auto& cidr : targetCidrs) {
    auto ips = enumerateSubnetHosts(cidr, 254);
    for (auto& ip : ips) {
      if (merged.find(ip) == merged.end() || !merged[ip].isLocalHost) {
        candidateIps.push_back(std::move(ip));
      }
    }
  }

  // Sweep subnet hosts with bounded 24-worker pool
  std::mutex resMutex;
  std::atomic<size_t> nextIdx{0};
  const size_t nThreads = std::min<size_t>(24, std::max<size_t>(1, candidateIps.size()));
  std::vector<std::jthread> pool;
  pool.reserve(nThreads);

  for (size_t w = 0; w < nThreads; ++w) {
    pool.emplace_back([&]() {
      while (!st.stop_requested()) {
        size_t idx = nextIdx.fetch_add(1);
        if (idx >= candidateIps.size()) break;
        const std::string& ip = candidateIps[idx];

        bool alive = false;
        std::string mac;
        double rttMs = 0.0;

#ifdef _WIN32
        struct in_addr dst{};
        if (inet_pton(AF_INET, ip.c_str(), &dst) == 1) {
          ULONG macBuf[2] = {};
          ULONG macLen = 6;
          const auto t0 = std::chrono::steady_clock::now();
          if (SendARP(dst.S_un.S_addr, 0, macBuf, &macLen) == NO_ERROR && macLen == 6) {
            rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
            mac = formatMacAddress(reinterpret_cast<const uint8_t*>(macBuf), 6);
            if (isValidMacCandidate(mac)) alive = true;
          }
        }
#else
        // Trigger kernel ARP/TCP discovery on common local ports
        for (uint16_t p : {80, 443, 22, 445}) {
          if (st.stop_requested()) break;
          if (probeTcpPortQuick(ip, p, 90, rttMs)) {
            alive = true;
            break;
          }
        }
#endif

        if (alive) {
          std::vector<uint16_t> openPorts = scanCommonPorts(ip, rttMs);
          std::string host = resolveLanHostname(ip);
          std::lock_guard lk(resMutex);
          auto& rec = merged[ip];
          rec.ip = ip;
          if (!mac.empty()) rec.mac = mac;
          rec.deviceKey = !rec.mac.empty() ? rec.mac : ("ip:" + ip);
          if (rec.vendor.empty() && !rec.mac.empty()) rec.vendor = lookupOuiVendor(rec.mac);
          if (!host.empty()) rec.hostname = std::move(host);
          rec.latencyMs = rttMs;
          rec.openPorts = joinPorts(openPorts);
          rec.subnet = cidr24OfIpv4(ip);
          rec.online = true;
          rec.firstSeenMs = nowMs;
          rec.lastSeenMs = nowMs;
          rec.deviceType = inferDeviceType(rec.isLocalHost, rec.isGateway, rec.vendor, rec.hostname, openPorts);
        }
      }
    });
  }
  pool.clear(); // joins all 16 jthreads before proceeding

#ifndef _WIN32
  // Re-read Linux /proc/net/arp after sweep probes to pick up newly resolved MACs
  for (auto& d : harvestLocalAndArp(nowMs)) {
    auto it = merged.find(d.ip);
    if (it == merged.end()) {
      merged[d.ip] = std::move(d);
    } else if (it->second.mac.empty() && !d.mac.empty()) {
      it->second.mac = d.mac;
      it->second.deviceKey = d.deviceKey;
      it->second.vendor = d.vendor;
    }
  }
#endif

  std::vector<LanDeviceRecord> finalBatch;
  finalBatch.reserve(merged.size());
  for (auto& [ip, rec] : merged) {
    (void)ip;
    finalBatch.push_back(std::move(rec));
  }

  std::vector<LanDeviceRecord> newlyDiscovered;
  {
    std::lock_guard lock(mutex_);
    for (const auto& d : finalBatch) {
      if (!d.isLocalHost && knownKeys_.insert(d.deviceKey).second) {
        newlyDiscovered.push_back(d);
      }
    }
  }

  history_.upsertLanDevices(finalBatch, subnetOverride.empty());
  for (const auto& nd : newlyDiscovered) {
    history_.recordManualAction(
        "info",
        "Novo dispositivo descoberto na LAN: " + nd.ip,
        (nd.vendor.empty() ? nd.deviceType : nd.vendor + " (" + nd.deviceType + ")") +
            (nd.mac.empty() ? "" : " · MAC " + nd.mac));
  }

  auto refreshed = history_.loadLanDevices();
  {
    std::lock_guard lock(mutex_);
    devices_ = std::move(refreshed);
    lastScanMs_ = nowEpochMs();
  }
  scanRunning_.store(false);
}

void DiscoveryEngine::workerLoop(std::stop_token st) {
  uint64_t lastPassiveMs = nowEpochMs();
  while (!st.stop_requested()) {
    bool doScan = false;
    std::string subOverride;
    {
      std::unique_lock lk(wakeMutex_);
      wakeCv_.wait_for(lk, st, std::chrono::seconds(30), [this]() { return scanRequested_; });
      if (scanRequested_) {
        doScan = true;
        subOverride = pendingSubnetOverride_;
        scanRequested_ = false;
        pendingSubnetOverride_.clear();
      }
    }
    if (st.stop_requested()) break;

    if (doScan) {
      runActiveScan(st, subOverride);
    } else if (nowEpochMs() - lastPassiveMs >= 60000ULL) {
      runPassiveRefresh();
      lastPassiveMs = nowEpochMs();
    }
  }
}

bool DiscoveryEngine::setDeviceLabel(const std::string& deviceKey, const std::string& label) {
  if (!history_.setLanDeviceLabel(deviceKey, label)) return false;
  std::lock_guard lock(mutex_);
  for (auto& d : devices_) {
    if (d.deviceKey == deviceKey) {
      d.customLabel = label;
      break;
    }
  }
  return true;
}

bool DiscoveryEngine::removeDevice(const std::string& deviceKey) {
  if (!history_.deleteLanDevice(deviceKey)) return false;
  std::lock_guard lock(mutex_);
  devices_.erase(std::remove_if(devices_.begin(), devices_.end(), [&](const LanDeviceRecord& d) {
                   return d.deviceKey == deviceKey;
                 }),
                 devices_.end());
  return true;
}

std::string DiscoveryEngine::getDevicesJson() const {
  std::vector<LanDeviceRecord> list;
  std::vector<std::string> subnets;
  uint64_t lastScan = 0;
  {
    std::lock_guard lock(mutex_);
    list = devices_;
    subnets = activeSubnets_;
    lastScan = lastScanMs_;
  }

  size_t onlineCnt = 0;
  size_t gwCnt = 0;
  std::unordered_set<std::string> vendors;
  for (const auto& d : list) {
    if (d.online) onlineCnt++;
    if (d.isGateway) gwCnt++;
    if (!d.vendor.empty()) vendors.insert(d.vendor);
  }

  char num[32];
  std::string out = "{\"summary\":{\"totalDevices\":";
  out += std::to_string(list.size());
  out += ",\"onlineCount\":";
  out += std::to_string(onlineCnt);
  out += ",\"offlineCount\":";
  out += std::to_string(list.size() - onlineCnt);
  out += ",\"gatewaysCount\":";
  out += std::to_string(gwCnt);
  out += ",\"vendorsCount\":";
  out += std::to_string(vendors.size());
  out += ",\"lastScanMs\":";
  out += std::to_string(lastScan);
  out += ",\"scanRunning\":";
  out += (scanRunning_.load() ? "true" : "false");
  out += ",\"subnets\":[";
  for (size_t i = 0; i < subnets.size(); ++i) {
    if (i > 0) out.push_back(',');
    appendJsonEscaped(out, subnets[i]);
  }
  out += "]},\"devices\":[";

  for (size_t i = 0; i < list.size(); ++i) {
    const auto& d = list[i];
    if (i > 0) out.push_back(',');
    out += "{\"key\":";
    appendJsonEscaped(out, d.deviceKey);
    out += ",\"ip\":";
    appendJsonEscaped(out, d.ip);
    out += ",\"mac\":";
    appendJsonEscaped(out, d.mac);
    out += ",\"randomizedMac\":";
    out += (isLocallyAdministeredMac(d.mac) ? "true" : "false");
    out += ",\"vendor\":";
    appendJsonEscaped(out, d.vendor);
    out += ",\"hostname\":";
    appendJsonEscaped(out, d.hostname);
    out += ",\"deviceType\":";
    appendJsonEscaped(out, d.deviceType);
    out += ",\"interface\":";
    appendJsonEscaped(out, d.interfaceName);
    out += ",\"subnet\":";
    appendJsonEscaped(out, d.subnet);
    out += ",\"isGateway\":";
    out += (d.isGateway ? "true" : "false");
    out += ",\"isLocalHost\":";
    out += (d.isLocalHost ? "true" : "false");
    out += ",\"online\":";
    out += (d.online ? "true" : "false");
    std::snprintf(num, sizeof(num), "%.1f", d.latencyMs);
    out += ",\"latencyMs\":";
    out += num;
    out += ",\"openPorts\":[";
    auto ports = splitPorts(d.openPorts);
    for (size_t pIdx = 0; pIdx < ports.size(); ++pIdx) {
      if (pIdx > 0) out.push_back(',');
      out += std::to_string(ports[pIdx]);
    }
    out += "],\"customLabel\":";
    appendJsonEscaped(out, d.customLabel);
    out += ",\"firstSeen\":";
    out += std::to_string(d.firstSeenMs);
    out += ",\"lastSeen\":";
    out += std::to_string(d.lastSeenMs);
    out += ",\"seenCount\":";
    out += std::to_string(d.seenCount);
    out.push_back('}');
  }

  out += "]}";
  return out;
}

} // namespace netpulse
