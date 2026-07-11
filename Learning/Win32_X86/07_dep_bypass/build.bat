@echo off
rem ====================================================================
rem  VulnSvc lab build script.  Run from the x86 Native Tools Command
rem  Prompt for VS.  DLLs are built first so their import libs exist for
rem  the service.exe link step.
rem
rem  Common defines:
rem    WIN32_LEAN_AND_MEAN        - keep windows.h from pulling in the
rem                                 legacy Winsock 1 headers (winsock.h),
rem                                 which conflict with winsock2.h.
rem    _CRT_SECURE_NO_WARNINGS    - silence C4996 noise for sscanf/strcpy/
rem                                 fopen etc. (intentional in a lab).
rem ====================================================================
setlocal
set DEFS=/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS
if not exist bin mkdir bin
pushd bin

echo === compression.dll (CORRECT gadget source: no ASLR, VA/VP imports, /O2) ===
cl /nologo /O2 /MT /GS- /TC %DEFS% /I..\src\compression ..\src\compression\compression.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x61500000 ^
   /OUT:compression.dll /IMPLIB:compression.lib
if errorlevel 1 goto fail

echo === helper.dll (TRAP: ASLR ON, great gadgets, moving base) ===
cl /nologo /O2 /MT /GS- /TC %DEFS% ..\src\helper\helper.c ^
   /link /DLL /DYNAMICBASE /NXCOMPAT /BASE:0x62000000 ^
   /OUT:helper.dll /IMPLIB:helper.lib
if errorlevel 1 goto fail

echo === crypto.dll (noise: /Od poor density, no useful imports) ===
cl /nologo /Od /MT /GS- /TC %DEFS% ..\src\crypto\crypto.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x63000000 ^
   /OUT:crypto.dll /IMPLIB:crypto.lib
if errorlevel 1 goto fail

echo === network.dll (noise: good gadgets but no VA/VP import) ===
cl /nologo /O2 /MT /GS- /TC %DEFS% ..\src\network\netlib.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x64000000 ^
   /OUT:network.dll /IMPLIB:network.lib ws2_32.lib
if errorlevel 1 goto fail

echo === service.exe (VULNERABLE TARGET: base 0x00400000, DEP on, no ASLR/GS/SafeSEH) ===
cl /nologo /Od /MT /GS- /TC %DEFS% /I..\src\service ^
   ..\src\service\main.c ..\src\service\net.c ..\src\service\dispatch.c ^
   ..\src\service\handlers.c ..\src\service\parser.c ..\src\service\config.c ^
   ..\src\service\logging.c ^
   /link /DYNAMICBASE:NO /NXCOMPAT /SAFESEH:NO /BASE:0x00400000 ^
   compression.lib helper.lib crypto.lib network.lib ws2_32.lib ^
   /OUT:service.exe
if errorlevel 1 goto fail

popd
echo.
echo Build OK. Binaries in bin\  (run: cd bin ^&^& service.exe)
endlocal
goto :eof

:fail
popd
echo.
echo BUILD FAILED. Check the compiler output above.
endlocal
exit /b 1
