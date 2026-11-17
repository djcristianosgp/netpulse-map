#pragma once

#include <cstdint>
#include <string>

namespace netpulse {

bool isValidIpAddress(const std::string& ip);
bool isProtectedSystemProcess(uint32_t pid, const std::string& procName);

bool terminateTargetProcess(uint32_t pid, const std::string& procName, std::string& outError);
bool blockIpInWindowsFirewall(const std::string& ip, bool isElevated, std::string& outError);
bool relaunchAsAdministrator();

} // namespace netpulse
