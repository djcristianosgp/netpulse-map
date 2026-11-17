#pragma once

#include <atomic>
#include <functional>
#include <string>

namespace netpulse {

struct TrayCallbacks {
  std::function<void()> onOpenApp;
  std::function<void()> onOpenBrowser;
  std::function<void()> onCheckUpdates;
  std::function<void()> onQuit;
};

// Runs a hidden Win32 window message loop with a System Tray icon.
// Blocks until quit is requested via tray menu or requestTrayQuit().
void runTrayMessageLoop(const std::string& url,
                        std::atomic<bool>& runningFlag,
                        TrayCallbacks callbacks);

void requestTrayQuit();
void showTrayBalloon(const std::string& title, const std::string& body, bool isWarning);

// Checks single-instance mutex; if already running, signals existing instance to reopen the map.
bool acquireSingleInstanceOrFocusExisting(void** outMutexHandle);
void releaseSingleInstance(void* mutexHandle);

} // namespace netpulse
