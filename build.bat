@echo off
setlocal

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

echo [Build] Compiling netpulse.exe (C++20 /O2)...
cl /nologo /std:c++20 /O2 /EHsc /W4 /utf-8 ^
  /Fo"%ROOT%build\\" /Fe"%ROOT%build\netpulse.exe" ^
  "%ROOT%src\main.cpp" ^
  "%ROOT%src\net_monitor.cpp" ^
  "%ROOT%src\geo_dns.cpp" ^
  "%ROOT%src\ws_server.cpp" ^
  ws2_32.lib iphlpapi.lib winhttp.lib bcrypt.lib crypt32.lib shell32.lib
if errorlevel 1 exit /b 1

echo [Build] Compiling test_core.exe...
cl /nologo /std:c++20 /O2 /EHsc /W4 /utf-8 ^
  /Fo"%ROOT%build\\" /Fe"%ROOT%build\test_core.exe" ^
  "%ROOT%tests\test_core.cpp" ^
  "%ROOT%src\net_monitor.cpp" ^
  "%ROOT%src\geo_dns.cpp" ^
  "%ROOT%src\ws_server.cpp" ^
  ws2_32.lib iphlpapi.lib winhttp.lib bcrypt.lib crypt32.lib
if errorlevel 1 exit /b 1

echo [Build] Done!
exit /b 0
