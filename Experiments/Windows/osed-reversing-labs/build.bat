@echo off
setlocal EnableExtensions

if /I "%~1"=="clean" (
  if exist dist rmdir /s /q dist
  if exist student\package rmdir /s /q student\package
  exit /b 0
)

where cl >nul 2>nul
if errorlevel 1 (
  echo error: run this from the "x86 Native Tools Command Prompt for VS 2022".
  exit /b 1
)

if defined VSCMD_ARG_TGT_ARCH if /I not "%VSCMD_ARG_TGT_ARCH%"=="x86" (
  echo error: this prompt targets %VSCMD_ARG_TGT_ARCH%; use the x86 Native Tools Command Prompt.
  exit /b 1
)

if not exist dist mkdir dist
cl /nologo /TC /std:c11 /W4 /Od /Oy- /GS- /Fo"dist\target01.obj" /Fe"dist\target01.exe" src\target01\main.c /link /INCREMENTAL:NO /DYNAMICBASE:NO /NXCOMPAT ws2_32.lib
if errorlevel 1 exit /b 1
cl /nologo /TC /std:c11 /W4 /Od /Oy- /GS- /Fo"dist\target02.obj" /Fe"dist\target02.exe" src\target02\main.c /link /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT ws2_32.lib
if errorlevel 1 exit /b 1
cl /nologo /TC /std:c11 /W4 /Od /Oy- /GS- /Fo"dist\target03.obj" /Fe"dist\target03.exe" src\target03\main.c /link /INCREMENTAL:NO /DYNAMICBASE:NO /NXCOMPAT
if errorlevel 1 exit /b 1

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

echo Build complete. Run build.bat validate to verify the PE files.
