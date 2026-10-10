@echo off
setlocal EnableExtensions

if /I "%~1"=="clean" (
  if exist dist rmdir /s /q dist
  if exist build-vs2022 rmdir /s /q build-vs2022
  if exist student\package rmdir /s /q student\package
  exit /b 0
)

where cmake >nul 2>nul
if errorlevel 1 (
  echo error: CMake is required. Install Visual Studio 2022 CMake tools or add CMake to PATH.
  exit /b 1
)

cmake -S . -B build-vs2022 -G "Visual Studio 17 2022" -A Win32
if errorlevel 1 exit /b 1
cmake --build build-vs2022 --config Release
if errorlevel 1 exit /b 1
if not exist dist mkdir dist
copy /y build-vs2022\Release\target01.exe dist\ >nul
copy /y build-vs2022\Release\target02.exe dist\ >nul
copy /y build-vs2022\Release\target03.exe dist\ >nul

if /I "%~1"=="validate" (
  py -3 tests\validate.py --dist dist
  exit /b %errorlevel%
)

if /I "%~1"=="student-package" (
  if exist student\package rmdir /s /q student\package
  mkdir student\package
  copy /y dist\target01.exe student\package\ >nul
  copy /y dist\target02.exe student\package\ >nul
  copy /y dist\target03.exe student\package\ >nul
  copy /y student\target01\README.md student\package\ >nul
  copy /y student\target02\README.md student\package\ >nul
  copy /y student\target03\README.md student\package\ >nul
  py -3 tests\make_sample.py student\package\sample.rvf
  exit /b %errorlevel%
)

echo PE32 x86 build complete. Run build.bat validate to verify the PE files.
