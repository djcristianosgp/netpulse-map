@echo off
setlocal
set "ROOT=%~dp0"
if not exist "%ROOT%build\netpulse.exe" (
  call "%ROOT%build.bat"
  if errorlevel 1 exit /b 1
)
"%ROOT%build\netpulse.exe" %*
