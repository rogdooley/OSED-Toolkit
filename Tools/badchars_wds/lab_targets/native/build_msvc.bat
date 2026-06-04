@echo off
setlocal

if "%VCINSTALLDIR%"=="" (
  echo [!] MSVC environment is not initialized.
  echo [!] Open "x86 Native Tools Command Prompt for VS" and rerun this script.
  exit /b 1
)

set SRC=badchar_target.c
set OUT=badchar_target.exe

echo [+] Building %OUT% with cl /Zi /Od (x86 prompt expected)...
cl /nologo /Zi /Od /W3 /MTd /D_CRT_SECURE_NO_WARNINGS %SRC% /link /OUT:%OUT% ws2_32.lib
if errorlevel 1 (
  echo [-] Build failed.
  exit /b 1
)

echo [+] Build complete: %OUT%
exit /b 0
