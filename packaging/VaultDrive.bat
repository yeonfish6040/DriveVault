@echo off
setlocal
set "VAULTDRIVE_PORTABLE_HOME=%~dp0"
set "VD_TARGET="
set "VD_ARCH=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "VD_ARCH=%PROCESSOR_ARCHITEW6432%"
if /I "%VD_ARCH%"=="ARM64" set "VD_TARGET=aarch64-pc-windows-msvc"
if /I "%VD_ARCH%"=="AMD64" set "VD_TARGET=x86_64-pc-windows-msvc"
if /I "%VD_ARCH%"=="x86" set "VD_TARGET=i686-pc-windows-msvc"
if not defined VD_TARGET (
  echo Unsupported Windows architecture: %VD_ARCH%
  exit /b 2
)
set "VD_APP=%~dp0bin\%VD_TARGET%\vault-gui.exe"
if not exist "%VD_APP%" (
  echo This package does not contain %VD_TARGET%.
  echo Extract the complete package or download the matching platform build.
  pause
  exit /b 3
)
start "" /D "%~dp0" "%VD_APP%" %*
if errorlevel 1 exit /b 4
exit /b 0
