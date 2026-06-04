@echo off
setlocal

where gcc >nul 2>nul
if errorlevel 1 (
  echo [!] gcc not found on PATH.
  echo [!] Install MinGW-w64 and ensure x86 gcc is available.
  exit /b 1
)

set SRC=badchar_target.c
set OUT=badchar_target.exe

echo [+] Building %OUT% with MinGW (x86 expected)...
gcc -m32 -g -O0 -Wall -Wextra -o %OUT% %SRC% -lws2_32
if errorlevel 1 (
  echo [-] Build failed.
  exit /b 1
)

echo [+] Build complete: %OUT%
exit /b 0
