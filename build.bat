@echo off
setlocal

set "APP_VER=%~1"
if not defined APP_VER set "APP_VER=2.0.0"

where cl >nul 2>&1
if not errorlevel 1 goto :msvc_ready

set "VCVARS="
for %%E in (BuildTools Enterprise Professional Community) do (
  if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    goto :init_msvc
  )
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    goto :init_msvc
  )
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" (
      set "VCVARS=%%I\VC\Auxiliary\Build\vcvars64.bat"
      goto :init_msvc
    )
  )
)

echo [ERROR] MSVC vcvars64.bat not found. Install Visual Studio Build Tools C++.
exit /b 1

:init_msvc
call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Failed to initialize MSVC environment.
  exit /b 1
)

:msvc_ready
set "ROOT=%~dp0"
if not exist "%ROOT%build" mkdir "%ROOT%build"
if not exist "%ROOT%build\obj_app" mkdir "%ROOT%build\obj_app"
if not exist "%ROOT%build\obj_test" mkdir "%ROOT%build\obj_test"

echo [Build] Compiling icon resource...
rc /nologo /fo "%ROOT%build\netpulse.res" "%ROOT%src\netpulse.rc"
if errorlevel 1 exit /b 1

if not exist "%ROOT%build\sqlite3.obj" (
  echo [Build] Compiling SQLite3 amalgamation...
  cl /nologo /TC /O2 /DSQLITE_THREADSAFE=1 /Fo"%ROOT%build\sqlite3.obj" /c "%ROOT%third_party\sqlite\sqlite3.c"
  if errorlevel 1 exit /b 1
)

echo [Build] Compiling netpulse.exe v%APP_VER% (C++20 /O2 GUI+Tray)...
cl /nologo /MP /std:c++20 /O2 /EHsc /W4 /utf-8 ^
  /I"%ROOT%src" /I"%ROOT%third_party\sqlite" ^
  /DNETPULSE_VERSION="\"%APP_VER%\"" ^
  /Fo"%ROOT%build\obj_app\\" /Fe"%ROOT%build\netpulse.exe" ^
  "%ROOT%src\main.cpp" ^
  "%ROOT%src\core\json_lite.cpp" ^
  "%ROOT%src\security\auth_manager.cpp" ^
  "%ROOT%src\security\audit_log.cpp" ^
  "%ROOT%src\security\rate_limiter.cpp" ^
  "%ROOT%src\security\tls_context.cpp" ^
  "%ROOT%src\storage\sqlite_db.cpp" ^
  "%ROOT%src\api\api_router.cpp" ^
  "%ROOT%src\api\prometheus_openapi.cpp" ^
  "%ROOT%src\net_monitor.cpp" ^
  "%ROOT%src\geo_dns.cpp" ^
  "%ROOT%src\ws_server.cpp" ^
  "%ROOT%src\updater.cpp" ^
  "%ROOT%src\service_monitor.cpp" ^
  "%ROOT%src\settings_store.cpp" ^
  "%ROOT%src\mmdb_reader.cpp" ^
  "%ROOT%src\traceroute.cpp" ^
  "%ROOT%src\history_store.cpp" ^
  "%ROOT%src\quality\network_quality_engine.cpp" ^
  "%ROOT%src\network\interface_monitor.cpp" ^
  "%ROOT%src\discovery\discovery_engine.cpp" ^
  "%ROOT%src\discovery\topology_builder.cpp" ^
  "%ROOT%src\intelligence\intelligence_engine.cpp" ^
  "%ROOT%src\notifications\notification_engine.cpp" ^
  "%ROOT%src\actions.cpp" ^
  "%ROOT%src\tray_host.cpp" ^
  "%ROOT%build\sqlite3.obj" ^
  "%ROOT%build\netpulse.res" ^
  ws2_32.lib iphlpapi.lib winhttp.lib bcrypt.lib crypt32.lib secur32.lib shell32.lib advapi32.lib user32.lib ^
  /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
if errorlevel 1 exit /b 1

echo [Build] Compiling test_core.exe...
cl /nologo /MP /std:c++20 /O2 /EHsc /W4 /utf-8 ^
  /I"%ROOT%src" /I"%ROOT%third_party\sqlite" ^
  /DNETPULSE_VERSION="\"%APP_VER%\"" ^
  /Fo"%ROOT%build\obj_test\\" /Fe"%ROOT%build\test_core.exe" ^
  "%ROOT%tests\test_core.cpp" ^
  "%ROOT%build\obj_app\json_lite.obj" ^
  "%ROOT%build\obj_app\auth_manager.obj" ^
  "%ROOT%build\obj_app\audit_log.obj" ^
  "%ROOT%build\obj_app\rate_limiter.obj" ^
  "%ROOT%build\obj_app\tls_context.obj" ^
  "%ROOT%build\obj_app\sqlite_db.obj" ^
  "%ROOT%build\obj_app\api_router.obj" ^
  "%ROOT%build\obj_app\prometheus_openapi.obj" ^
  "%ROOT%build\obj_app\net_monitor.obj" ^
  "%ROOT%build\obj_app\geo_dns.obj" ^
  "%ROOT%build\obj_app\ws_server.obj" ^
  "%ROOT%build\obj_app\updater.obj" ^
  "%ROOT%build\obj_app\service_monitor.obj" ^
  "%ROOT%build\obj_app\settings_store.obj" ^
  "%ROOT%build\obj_app\mmdb_reader.obj" ^
  "%ROOT%build\obj_app\traceroute.obj" ^
  "%ROOT%build\obj_app\history_store.obj" ^
  "%ROOT%build\obj_app\network_quality_engine.obj" ^
  "%ROOT%build\obj_app\interface_monitor.obj" ^
  "%ROOT%build\obj_app\discovery_engine.obj" ^
  "%ROOT%build\obj_app\topology_builder.obj" ^
  "%ROOT%build\obj_app\intelligence_engine.obj" ^
  "%ROOT%build\obj_app\notification_engine.obj" ^
  "%ROOT%build\obj_app\actions.obj" ^
  "%ROOT%build\obj_app\tray_host.obj" ^
  "%ROOT%build\sqlite3.obj" ^
  ws2_32.lib iphlpapi.lib winhttp.lib bcrypt.lib crypt32.lib secur32.lib shell32.lib advapi32.lib user32.lib
if errorlevel 1 exit /b 1

echo [Build] Done!
exit /b 0
