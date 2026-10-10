@echo off
setlocal
where i686-w64-mingw32-gcc >nul 2>nul
if errorlevel 1 (
  echo error: i686-w64-mingw32-gcc is required to build x86 targets.
  exit /b 1
)
make %*
