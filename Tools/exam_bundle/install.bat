@echo off
REM install.bat - Set up the exam bundle on the Windows exam box
REM
REM Run from the exam_bundle directory:
REM   cd C:\exam\exam_bundle
REM   install.bat
REM
REM Checks for Python 3.12+. If not found, extracts the bundled
REM embeddable Python. Then installs keystone-engine from wheels.

setlocal enabledelayedexpansion

echo [*] OSED Exam Bundle Installer
echo.

set "BUNDLEDIR=%~dp0"
set "BUNDLEDIR=%BUNDLEDIR:~0,-1%"
set "LOCALPY=%BUNDLEDIR%\python\python.exe"
set "USE_LOCAL=0"

REM ============================================================
REM 1. Find or set up Python 3.12+
REM ============================================================

REM Check system Python
set "PYTHON="
python --version >NUL 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PYTHON=python"
)
if not defined PYTHON (
    python3 --version >NUL 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "PYTHON=python3"
    )
)

REM Check version if system Python exists
set "NEED_LOCAL=1"
if defined PYTHON (
    echo [*] Found system Python:
    %PYTHON% --version
    for /f "tokens=2 delims= " %%V in ('%PYTHON% --version 2^>^&1') do set "PYVER=%%V"
    for /f "tokens=1,2 delims=." %%A in ("!PYVER!") do (
        set "PYMAJOR=%%A"
        set "PYMINOR=%%B"
    )
    if !PYMAJOR! GEQ 3 (
        if !PYMINOR! GEQ 12 (
            echo [+] Python !PYVER! meets the 3.12+ requirement.
            set "NEED_LOCAL=0"
        ) else (
            echo [-] Python !PYVER! is below 3.12.
        )
    ) else (
        echo [-] Python !PYVER! is below 3.12.
    )
) else (
    echo [-] No system Python found in PATH.
)

REM Set up local Python if needed
if !NEED_LOCAL! EQU 1 (
    echo.
    echo [*] Setting up bundled Python 3.12...

    REM Find the embed zip
    set "EMBED_ZIP="
    for %%F in ("%BUNDLEDIR%\python\python-3.12*-embed-win32.zip") do (
        set "EMBED_ZIP=%%F"
    )

    if not defined EMBED_ZIP (
        echo [-] No Python embeddable zip found in python\ folder.
        echo     Expected: python\python-3.12.x-embed-win32.zip
        if defined PYTHON (
            echo [*] Falling back to system Python !PYVER! -- some features may not work.
            goto :skip_local
        )
        echo [-] Cannot continue without Python. Exiting.
        exit /b 1
    )

    if exist "!LOCALPY!" (
        echo [+] Bundled Python already extracted.
        goto :use_local
    )

    echo [*] Extracting !EMBED_ZIP!...
    powershell -Command "Expand-Archive -Path '!EMBED_ZIP!' -DestinationPath '%BUNDLEDIR%\python' -Force" 2>NUL
    if not exist "!LOCALPY!" (
        echo [-] Extraction failed. Trying tar...
        tar -xf "!EMBED_ZIP!" -C "%BUNDLEDIR%\python" 2>NUL
    )

    if not exist "!LOCALPY!" (
        echo [-] Could not extract Python.
        if defined PYTHON (
            echo [*] Falling back to system Python !PYVER!.
            goto :skip_local
        )
        echo [-] Cannot continue without Python. Exiting.
        exit /b 1
    )

:use_local
    echo [+] Using bundled Python at: !LOCALPY!
    set "PYTHON=!LOCALPY!"
    set "USE_LOCAL=1"

    REM Patch the ._pth file to enable pip/site-packages
    for %%P in ("%BUNDLEDIR%\python\python3*._pth") do (
        set "PTHFILE=%%P"
    )
    if defined PTHFILE (
        findstr /C:"import site" "!PTHFILE!" >NUL 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo import site>> "!PTHFILE!"
            echo [+] Patched !PTHFILE! to enable site-packages.
        ) else (
            REM Uncomment if it's commented out
            powershell -Command "(Get-Content '!PTHFILE!') -replace '^#import site','import site' | Set-Content '!PTHFILE!'" 2>NUL
            echo [+] Ensured import site is enabled in !PTHFILE!.
        )
    )

    REM Install pip if not present
    "!PYTHON!" -m pip --version >NUL 2>&1
    if !ERRORLEVEL! NEQ 0 (
        if exist "%BUNDLEDIR%\python\get-pip.py" (
            echo [*] Installing pip from bundled wheels...
            "!PYTHON!" "%BUNDLEDIR%\python\get-pip.py" --no-index --find-links="%BUNDLEDIR%\wheels" --no-warn-script-location 2>&1
            if !ERRORLEVEL! NEQ 0 (
                echo [-] pip installation failed.
            ) else (
                echo [+] pip installed.
            )
        ) else (
            echo [-] get-pip.py not found. Cannot install pip.
        )
    ) else (
        echo [+] pip already available.
    )
)

:skip_local

REM Show which Python we are using
echo.
echo [*] Using: !PYTHON!
"!PYTHON!" --version

REM ============================================================
REM 2. Install keystone from local wheels
REM ============================================================
echo.
echo [*] Installing keystone-engine from bundled wheels...
"!PYTHON!" -m pip install --no-index --find-links="%BUNDLEDIR%\wheels" keystone-engine 2>NUL
if !ERRORLEVEL! NEQ 0 (
    echo [-] Wheel install failed. Trying with --user flag...
    "!PYTHON!" -m pip install --no-index --find-links="%BUNDLEDIR%\wheels" --user keystone-engine 2>NUL
)

REM Verify keystone
echo.
echo [*] Verifying keystone...
"!PYTHON!" -c "from keystone import Ks, KS_ARCH_X86, KS_MODE_32; ks = Ks(KS_ARCH_X86, KS_MODE_32); enc, _ = ks.asm('nop'); print('[+] Keystone OK: nop =', bytes(enc).hex())"
if !ERRORLEVEL! NEQ 0 (
    echo [-] Keystone verification failed.
    echo     You can still use pre-assembled shellcode.bin from the emitter.
)

REM ============================================================
REM 3. Verify recon.exe
REM ============================================================
echo.
echo [*] Verifying recon.exe...
if exist tools\recon.exe (
    tools\recon.exe --help >NUL 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [+] recon.exe OK
    ) else (
        echo [-] recon.exe found but failed to run
    )
) else (
    echo [-] recon.exe not found in tools\
)

REM ============================================================
REM 4. Write a helper script so "python" uses the right one
REM ============================================================
if !USE_LOCAL! EQU 1 (
    echo.
    echo [*] Creating py.bat helper...
    (
        echo @echo off
        echo "!PYTHON!" %%*
    ) > "%BUNDLEDIR%\py.bat"
    echo [+] Use "py.bat" instead of "python" to run scripts:
    echo     py.bat templates\stack_bof.py
    echo     py.bat convert\string2hex.py string "cmd.exe"
    echo.
    echo     Or add the python\ folder to your PATH:
    echo     set PATH=%BUNDLEDIR%\python;%%PATH%%
)

echo.
echo ============================================================
echo [+] Setup complete. Bundle contents:
echo ============================================================
echo.
echo HOST ENUMERATION:
echo   python tools\enum_host.py             Enumerate host, generate HTML report
echo   python tools\enum_host.py --quick     Skip slow service config queries
echo   start enum_report.html                Open report in browser
echo.
echo STATIC ANALYSIS:
echo   tools\recon.exe pe ^<target.exe^>     PE mitigations, imports, sections
echo   tools\recon.exe triage ^<target.exe^>  Function ranking by exploitability
echo   tools\recon.exe badchars ^<target.exe^> Static bad-char prediction
echo   tools\recon.exe pseudo ^<listing.txt^>  IDA listing to pseudocode
echo   tools\recon.exe filter --badchars ... Gadget address filtering
echo.
echo BAD CHARACTERS:
echo   badchars\badchar_auto.py             Automated bad-char discovery via cdb
echo   badchars\badchar_bp.wds              WinDbg breakpoint script
echo.
echo EXPLOIT TEMPLATES (copy + fill in per target):
echo   templates\stack_bof.py               Stack overflow, JMP ESP
echo   templates\seh_exploit.py             SEH overwrite
echo   templates\dep_bypass.py              DEP bypass with ROP
echo   templates\egghunter.py               Egghunter exploit
echo   templates\format_string.py           Format string attack
echo   templates\aslr_leak.py               ASLR info leak + exploit
echo   templates\badchars_ref.py            Bad character test scaffold
echo.
echo PAYLOAD HELPERS:
echo   payloads\eip_check.py                EIP control verification
echo   payloads\vp_skeleton.py              VirtualProtect skeleton
echo.
echo CONVERSION TOOLS:
echo   convert\string2hex.py string "text"  String to little-endian hex chunks
echo   convert\string2hex.py ip 10.0.0.1    IP to little-endian hex
echo   convert\string2hex.py sockaddr ...   sockaddr_in fields
echo   convert\opcode.py "FunctionName"     API name to ROR13 hash
echo.
echo PER-TARGET FILES (generated by emitter on Kali):
echo   code_snippet.py                      Keystone assembly, assemble + run
echo   debug_runner.py                      Assembly with line-by-line error scan
echo   test_harness.py                      Load shellcode.bin and run
echo.
echo REFERENCE (in reference\ folder):
echo   Markdown cheat sheets for WinDbg, DEP bypass, SEH, egghunters,
echo   bad characters, shellcode, gadgets, and exam-day checklist.
echo   Open with any text editor or Markdown viewer.
echo.

endlocal
