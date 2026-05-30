badchar_auto.py  -  Automated Bad Character Discovery
======================================================
Version 1.0.0  |  Python 3.7+  |  Windows only  |  No external dependencies


QUICK REFERENCE
---------------
Two files go on the Windows VM:

    badchar_auto.py       This script. Run it directly.
    examples\             Optional: customisable per-target templates.

The WDS debugger script (C:\badchar\badchar_bp.wds) is generated
automatically on first run. You do not manage it manually.


PREREQUISITES
-------------
1. cdb.exe from Debugging Tools for Windows
   Typically found at one of:
     C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe
     C:\Program Files\Debugging Tools for Windows (x86)\cdb.exe
   You only need the x86 version for 32-bit targets (all OSED targets).

2. Python 3.7+ on the Windows VM.
   Verify: python --version

3. The target application must be startable via a command line path.
   Services that auto-start via SCM need to be launched manually with
   the --target flag, or started separately with the debugger attaching
   via --pid (see ADVANCED section).


FINDING YOUR VALUES
-------------------
Before running, you need four things from your earlier debugging:

  --offset      Byte offset in the payload where the test region starts.
                This is the same offset you found during pattern offset analysis.
                Example: 2606 for SLMail PASS.

  --size        Total payload size (offset + test bytes + remaining buffer).
                Match what your working crash payload sends.

  --breakpoint  The function where the data is finally written to the
                destination buffer. NOT recv. The LAST copy.
                Start with: msvcrt!strcpy
                Also common: msvcrt!strncpy, msvcrt!memcpy, msvcrt!memmove

  --dump-expr   WinDbg expression that gives the destination buffer address
                at the moment of the breakpoint, BEFORE any stepping.

                For cdecl functions (most CRT functions):
                  strcpy(dst, src)    ->  poi(@esp+4)   (dst is arg1)
                  memcpy(dst, src, n) ->  poi(@esp+4)   (dst is arg1)

                If your offset is large and you want a smaller dump:
                  poi(@esp+4)+2606    (start dump at the test region directly)
                  In this case set --offset 0 in the tool.


STEP MODES
----------
  pt    Recommended default. Breakpoint fires at function ENTRY.
        $t0 saves the dst address. "pt" steps to the ret instruction.
        The destination buffer now contains the copied data. Dump.

  none  Use when the breakpoint is placed AFTER the copy has finished.
        Example: you break at the instruction following "call strcpy"
        in the caller. No stepping needed; destination is already written.
        Requires knowing the exact address in the binary.

  gu    Runs until the current function returns. Similar to pt but uses
        a temporary breakpoint rather than single-stepping. Use only when
        you have verified that no other code path returns first.


PROTOCOL FRAMING
----------------
For simple one-shot protocols use --prefix / --suffix:

  --prefix "TRUN ./:"  --suffix ""               (Vulnserver TRUN)
  --prefix "GTER ./:"  --suffix ""               (Vulnserver GTER)

For stateful protocols that require a login sequence before the
vulnerable command, use the importable API instead of the CLI.
See examples\slmail_pass.py for the pattern.

  Escape sequences in --prefix / --suffix:
    \\r   carriage return (0x0d)
    \\n   line feed (0x0a)
    \\t   tab (0x09)

  Example: --prefix "USER test\\r\\nPASS " --suffix "\\r\\n"


DUMP DIRECTORY
--------------
Default: C:\badchar\

Contents during a run:
  badchar_bp.wds       Generated cdb script (overwritten each run)
  _tmp.bin             Staging file (renamed to dump.bin atomically)
  dump.bin             Active dump (deleted after Python reads it)
  cdb_0001.log         cdb stdout transcript for iteration 1
  cdb_0002.log         cdb stdout transcript for iteration 2
  ...

The directory must have no spaces in its path. The paths are embedded
directly in the cdb breakpoint command, and inner quotes would end the
command string early.


MAGIC BYTES
-----------
Default: BC F0 BC F0  (binary mode)

These four bytes are embedded at the start of the test region in every
payload. After the copy, Python checks dump[0:4] == magic before
accepting the dump. This detects stale dumps and wrong dump-expr values.

Rules:
  - Magic must not overlap with --exclude bytes.
    The tool performs this check at startup and exits with an error.
  - Magic bytes should not be protocol-sensitive for your target.
    BC F0 BC F0 avoids NULL, CR, LF and common ASCII delimiters.

  --magic-mode ascii   Uses "w00t" (0x77 0x30 0x30 0x74).
                       Use for targets that mangle high bytes.

  --magic DEADBEEF     Override with any 4-byte hex string.
                       Verify none of those bytes are in --exclude.


TROUBLESHOOTING
---------------
SYMPTOM: No dump appears. Timeout after 15s.
  - Verify the breakpoint symbol is correct.
    In cdb: bp msvcrt!strcpy; g  -- does it fire on a normal connection?
  - Verify the target is actually calling that function.
    Try: x msvcrt!str*  to list available symbols.
  - Check cdb_0001.log. Look for "Unresolved breakpoint" messages.
  - If the app has ASLR or is 64-bit, the ABI may differ. Adjust --dump-expr.

SYMPTOM: Magic mismatch. Got: 00000000 or similar.
  - --dump-expr points to the wrong address.
  - Common cause: using poi(@esp+4) AFTER stepping (frame has unwound).
    The tool saves the expression BEFORE stepping. This should not happen
    with the default WDS. If you customised the script, check $t0 save order.
  - Try --dump-expr "poi(@esp+8)" if dst and src are swapped for your function.
  - Increase --dump-size and check what IS in the dump with a hex editor.

SYMPTOM: Short dump.
  - Increase --dump-size. Default is 512; try 1024.
  - Check that the destination buffer is at least that large.

SYMPTOM: Debugger exits immediately (iter 1, rc=0 or rc=-1).
  - Check cdb_0001.log for a startup error.
  - Verify --target path exists and is a runnable .exe.
  - Verify --cdb path is correct and the bitness matches (x86 cdb for x86 targets).
  - Some targets need to be started as administrator.

SYMPTOM: Crash before dump on every iteration.
  - A bad char is causing corruption before the copy function is reached.
  - Use --exclude to add that byte and retry.
  - Check cdb_0001.log for the exception address and faulting instruction.

SYMPTOM: Transformed bytes (e.g. 0x61 -> 0x41).
  - The application is normalising your bytes (e.g. uppercasing ASCII).
  - This is a transformation, not a missing byte.
  - The analyser records it separately. The src byte is the bad char.


ADVANCED: EXTERNAL DEBUGGER
----------------------------
Omit --cdb and --target to run without Python managing cdb.

1. Generate the WDS script manually:
   python badchar_auto.py --offset 2606 --size 3000 [other args] --generate-script-only
   (Not yet implemented in v1. Open badchar_bp.wds and copy it manually, or
    run once with --target and Ctrl-C immediately after script generation.)

2. Load the script in cdb or WinDbg:
   cdb.exe -o -g -G -c "$$>< C:\badchar\badchar_bp.wds" target.exe
   or in the WinDbg command box: $$>< C:\badchar\badchar_bp.wds

3. Run badchar_auto.py without --cdb / --target.
   It will send payloads and watch for dump.bin without managing the debugger.


ADVANCED: ATTACHING TO A RUNNING PROCESS
-----------------------------------------
Not directly supported by the CLI in v1.
Use the importable API and pass a pre-started CDBDriver:

    driver = CDBDriver(
        cdb_path    = r"C:\Tools\cdb.exe",
        target_exe  = "-p {}".format(pid),   # -p PID attaches
        script_path = r"C:\badchar\badchar_bp.wds",
    )
    # pass driver to BadCharOrchestrator and call driver.start() manually


SCP WORKFLOW
------------
From your dev machine:
    scp badchar_auto.py user@windowsvm:C:\badchar\
    scp examples\slmail_pass.py user@windowsvm:C:\badchar\examples\

On the Windows VM:
    python C:\badchar\badchar_auto.py [args]
    -- or --
    python C:\badchar\examples\slmail_pass.py


NOTES FOR EXAM CONDITIONS
--------------------------
- Run everything as the same user who starts the target application.
- If Windows Defender flags the script, add C:\badchar\ to exclusions.
- If cdb is not in PATH, use the full path in --cdb.
- The dump directory is created automatically. No manual setup needed.
- Each run overwrites badchar_bp.wds. This is expected.
- Transcripts in cdb_NNNN.log are the first place to look on failure.
