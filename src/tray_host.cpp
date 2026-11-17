#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shellapi.h>

#include "tray_host.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>

namespace netpulse {

namespace {

constexpr wchar_t kTrayClassName[] = L"NetPulse2DTrayClass";
constexpr wchar_t kMutexName[] = L"NetPulse2D_SingleInstance_Mutex";

constexpr UINT WM_TRAY_CALLBACK = WM_APP + 1;
constexpr UINT WM_OPEN_EXISTING = WM_APP + 2;
constexpr UINT WM_SHOW_BALLOON = WM_APP + 3;

struct PendingBalloon {
  std::wstring title;
  std::wstring body;
  bool isWarning = false;
};

std::mutex gBalloonMutex;
PendingBalloon gPendingBalloon;

std::wstring utf8ToWideTruncated(const std::string& s, size_t maxChars) {
  if (s.empty()) return {};
  int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
  if (out.size() > maxChars) out.resize(maxChars);
  return out;
}

constexpr UINT ID_MENU_OPEN_APP = 1001;
constexpr UINT ID_MENU_MINIMIZE_TRAY = 1005;
constexpr UINT ID_MENU_OPEN_BROWSER = 1002;
constexpr UINT ID_MENU_CHECK_UPDATE = 1003;
constexpr UINT ID_MENU_QUIT = 1004;
constexpr UINT_PTR ID_TIMER_MINIMIZE_WATCH = 2001;

struct TrayState {
  TrayCallbacks callbacks;
  std::atomic<bool>* runningFlag = nullptr;
  NOTIFYICONDATAW nid{};
  UINT taskbarCreatedMsg = 0;
  bool iconAdded = false;
};

std::atomic<HWND> gTrayHwnd{nullptr};
std::atomic<bool> gMinimizeToTray{true};

HWND findMapBrowserWindow(bool onlyVisible) {
  struct SearchCtx {
    bool onlyVisible;
    HWND found = nullptr;
  } ctx{onlyVisible, nullptr};

  EnumWindows(
      [](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* c = reinterpret_cast<SearchCtx*>(lParam);
        if (c->onlyVisible && !IsWindowVisible(hwnd)) return TRUE;
        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, static_cast<int>(std::size(title))) <= 0) return TRUE;
        if (wcsncmp(title, L"NetPulse 2D", 11) != 0) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return TRUE;
        wchar_t exe[MAX_PATH] = {};
        DWORD sz = static_cast<DWORD>(std::size(exe));
        bool isBrowser = false;
        if (QueryFullProcessImageNameW(hProc, 0, exe, &sz)) {
          std::wstring p(exe, sz);
          for (auto& ch : p) ch = static_cast<wchar_t>(towlower(ch));
          isBrowser = (p.find(L"msedge.exe") != std::wstring::npos ||
                       p.find(L"chrome.exe") != std::wstring::npos);
        }
        CloseHandle(hProc);
        if (isBrowser) {
          c->found = hwnd;
          return FALSE;
        }
        return TRUE;
      },
      reinterpret_cast<LPARAM>(&ctx));

  return ctx.found;
}

void addTrayIcon(TrayState* st) {
  if (!st || !st->nid.hWnd) return;
  if (Shell_NotifyIconW(NIM_ADD, &st->nid)) {
    st->iconAdded = true;
  }
}

void removeTrayIcon(TrayState* st) {
  if (!st || !st->iconAdded) return;
  Shell_NotifyIconW(NIM_DELETE, &st->nid);
  st->iconAdded = false;
}

void showContextMenu(HWND hwnd, TrayState* st) {
  POINT pt{};
  GetCursorPos(&pt);

  HMENU menu = CreatePopupMenu();
  if (!menu) return;

  AppendMenuW(menu, MF_STRING, ID_MENU_OPEN_APP, L"Abrir / Restaurar Mapa 2D");
  if (findMapBrowserWindow(true)) {
    AppendMenuW(menu, MF_STRING, ID_MENU_MINIMIZE_TRAY, L"Minimizar para a Bandeja");
  }
  AppendMenuW(menu, MF_STRING, ID_MENU_OPEN_BROWSER, L"Abrir no Navegador");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, ID_MENU_CHECK_UPDATE, L"Verificar Atualizações");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, ID_MENU_QUIT, L"Sair do NetPulse 2D");
  SetMenuDefaultItem(menu, ID_MENU_OPEN_APP, FALSE);

  SetForegroundWindow(hwnd);
  UINT cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                            pt.x, pt.y, 0, hwnd, nullptr);
  DestroyMenu(menu);
  PostMessageW(hwnd, WM_NULL, 0, 0);

  if (cmd == ID_MENU_OPEN_APP && st->callbacks.onOpenApp) {
    st->callbacks.onOpenApp();
  } else if (cmd == ID_MENU_MINIMIZE_TRAY) {
    minimizeMapWindowToTray();
  } else if (cmd == ID_MENU_OPEN_BROWSER && st->callbacks.onOpenBrowser) {
    st->callbacks.onOpenBrowser();
  } else if (cmd == ID_MENU_CHECK_UPDATE && st->callbacks.onCheckUpdates) {
    st->callbacks.onCheckUpdates();
  } else if (cmd == ID_MENU_QUIT) {
    if (st->runningFlag) st->runningFlag->store(false);
    if (st->callbacks.onQuit) st->callbacks.onQuit();
    DestroyWindow(hwnd);
  }
}

LRESULT CALLBACK trayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  auto* st = reinterpret_cast<TrayState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

  if (st && st->taskbarCreatedMsg != 0 && msg == st->taskbarCreatedMsg) {
    addTrayIcon(st);
    return 0;
  }

  switch (msg) {
    case WM_TRAY_CALLBACK:
      if (lParam == WM_LBUTTONDBLCLK || lParam == WM_LBUTTONUP) {
        if (st && st->callbacks.onOpenApp) st->callbacks.onOpenApp();
      } else if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
        if (st) showContextMenu(hwnd, st);
      }
      return 0;

    case WM_OPEN_EXISTING:
      if (st && st->callbacks.onOpenApp) st->callbacks.onOpenApp();
      return 0;

    case WM_SHOW_BALLOON:
      if (st && st->iconAdded) {
        std::lock_guard lock(gBalloonMutex);
        NOTIFYICONDATAW info = st->nid;
        info.uFlags = NIF_INFO;
        info.dwInfoFlags = gPendingBalloon.isWarning ? NIIF_WARNING : NIIF_INFO;
        wcsncpy_s(info.szInfoTitle, gPendingBalloon.title.c_str(), _TRUNCATE);
        wcsncpy_s(info.szInfo, gPendingBalloon.body.c_str(), _TRUNCATE);
        Shell_NotifyIconW(NIM_MODIFY, &info);
      }
      return 0;

    case WM_TIMER:
      if (wParam == ID_TIMER_MINIMIZE_WATCH && gMinimizeToTray.load()) {
        HWND mapWin = findMapBrowserWindow(true);
        if (mapWin && IsIconic(mapWin)) {
          ShowWindow(mapWin, SW_HIDE);
        }
      }
      return 0;

    case WM_CLOSE:
      if (st && st->runningFlag) st->runningFlag->store(false);
      DestroyWindow(hwnd);
      return 0;

    case WM_DESTROY:
      KillTimer(hwnd, ID_TIMER_MINIMIZE_WATCH);
      if (st) removeTrayIcon(st);
      gTrayHwnd.store(nullptr);
      PostQuitMessage(0);
      return 0;

    default:
      return DefWindowProcW(hwnd, msg, wParam, lParam);
  }
}

} // namespace

bool acquireSingleInstanceOrFocusExisting(void** outMutexHandle) {
  HANDLE hMutex = CreateMutexW(nullptr, TRUE, kMutexName);
  if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
    HWND existing = FindWindowW(kTrayClassName, nullptr);
    if (existing) {
      PostMessageW(existing, WM_OPEN_EXISTING, 0, 0);
    }
    CloseHandle(hMutex);
    *outMutexHandle = nullptr;
    return false;
  }
  *outMutexHandle = hMutex;
  return true;
}

void releaseSingleInstance(void* mutexHandle) {
  if (mutexHandle) {
    HANDLE h = static_cast<HANDLE>(mutexHandle);
    ReleaseMutex(h);
    CloseHandle(h);
  }
}

void requestTrayQuit() {
  HWND hwnd = gTrayHwnd.load();
  if (hwnd) {
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
  }
}

void setMinimizeToTrayEnabled(bool enabled) {
  gMinimizeToTray.store(enabled);
}

bool focusExistingMapWindow() {
  HWND found = findMapBrowserWindow(false);
  if (!found) return false;
  if (!IsWindowVisible(found)) {
    ShowWindow(found, SW_SHOW);
  }
  if (IsIconic(found)) {
    ShowWindow(found, SW_RESTORE);
  }
  SetForegroundWindow(found);
  return true;
}

bool minimizeMapWindowToTray() {
  HWND found = findMapBrowserWindow(true);
  if (!found) return false;
  ShowWindow(found, SW_HIDE);
  return true;
}

void showTrayBalloon(const std::string& title, const std::string& body, bool isWarning) {
  HWND hwnd = gTrayHwnd.load();
  if (!hwnd) return;
  {
    std::lock_guard lock(gBalloonMutex);
    gPendingBalloon.title = utf8ToWideTruncated(title, 60);
    gPendingBalloon.body = utf8ToWideTruncated(body, 240);
    gPendingBalloon.isWarning = isWarning;
  }
  PostMessageW(hwnd, WM_SHOW_BALLOON, 0, 0);
}

void runTrayMessageLoop(const std::string& /*url*/,
                        std::atomic<bool>& runningFlag,
                        TrayCallbacks callbacks) {
  HINSTANCE hInst = GetModuleHandleW(nullptr);

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = trayWndProc;
  wc.hInstance = hInst;
  wc.lpszClassName = kTrayClassName;
  RegisterClassExW(&wc);

  TrayState state;
  state.callbacks = std::move(callbacks);
  state.runningFlag = &runningFlag;
  state.taskbarCreatedMsg = RegisterWindowMessageW(L"TaskbarCreated");

  HWND hwnd = CreateWindowExW(0, kTrayClassName, L"NetPulse 2D", WS_OVERLAPPEDWINDOW,
                              0, 0, 0, 0, nullptr, nullptr, hInst, nullptr);
  if (!hwnd) {
    while (runningFlag.load()) {
      Sleep(200);
    }
    return;
  }

  SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&state));
  gTrayHwnd.store(hwnd);

  state.nid.cbSize = sizeof(NOTIFYICONDATAW);
  state.nid.hWnd = hwnd;
  state.nid.uID = 1;
  state.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  state.nid.uCallbackMessage = WM_TRAY_CALLBACK;
  state.nid.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
  if (!state.nid.hIcon) {
    state.nid.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
  }
  wcscpy_s(state.nid.szTip, L"NetPulse 2D — Mapa de Conexões");
  addTrayIcon(&state);
  SetTimer(hwnd, ID_TIMER_MINIMIZE_WATCH, 350, nullptr);

  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  UnregisterClassW(kTrayClassName, hInst);
}

} // namespace netpulse
