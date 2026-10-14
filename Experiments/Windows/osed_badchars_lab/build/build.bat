@echo off
setlocal EnableExtensions

set "CONFIGURATION=%~1"
if "%CONFIGURATION%"=="" set "CONFIGURATION=Release"
if /I "%CONFIGURATION%"=="Debug" goto :configuration_ok
if /I "%CONFIGURATION%"=="Release" goto :configuration_ok
echo Usage: %~nx0 [Debug^|Release]
exit /b 2

:configuration_ok
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer was not found. Open a Visual Studio Developer Command Prompt and retry.
  exit /b 1
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do set "VSINSTALL=%%I"
if "%VSINSTALL%"=="" (
  echo No supported Visual Studio installation with MSBuild was found.
  exit /b 1
)

call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%

msbuild "%~dp0..\BadCharsLab.sln" /m /p:Configuration=%CONFIGURATION%;Platform=Win32
exit /b %errorlevel%
