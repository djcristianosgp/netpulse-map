#pragma once

#include <cstdint>
#include <string>

namespace netpulse {

bool isValidIpAddress(const std::string& ip);
bool isLoopbackOrUnspecifiedIp(const std::string& ip);
bool isProtectedSystemProcess(uint32_t pid, const std::string& procName);

bool terminateTargetProcess(uint32_t pid, const std::string& procName, std::string& outError);
bool blockIpInWindowsFirewall(const std::string& ip, bool isElevated, std::string& outError);
bool unblockIpInWindowsFirewall(const std::string& ip, bool isElevated, std::string& outError);
bool applyOsFirewallRule(const std::string& ruleName,
                         const std::string& direction,
                         const std::string& action,
                         const std::string& protocol,
                         const std::string& remoteIp,
                         uint16_t remotePort,
                         const std::string& programPath,
                         bool isElevated,
                         std::string& outError);
bool removeOsFirewallRule(const std::string& ruleName, bool isElevated, std::string& outError);
bool relaunchAsAdministrator();

} // namespace netpulse
