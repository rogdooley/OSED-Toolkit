---
title: "WinDbg / cdb Workflow Guide for OSED"
documentclass: extarticle
geometry: "margin=0.4in"
fontsize: 8pt
colorlinks: true
header-includes:
  - \usepackage{titlesec}
  - \setlength{\parindent}{0pt}
  - \setlength{\tabcolsep}{4pt}
  - \renewcommand{\arraystretch}{0.97}
  - \setlength{\parskip}{1pt}
  - \titlespacing*{\section}{0pt}{4pt}{1pt}
  - \titleformat{\section}{\bfseries\sffamily}{}{0pt}{}
  - \pagestyle{empty}
  - \usepackage{fvextra}
  - \fvset{fontsize=\scriptsize}
  - \AtBeginDocument{\footnotesize}
---

This guide is ordered the way OSED work usually unfolds: start the debug
session, triage the crash, inspect stack and memory, then move into module
enumeration, PE walking, and exploit-development helpers. The syntax is the
same debugger syntax you would use in WinDbg or cdb, but the examples are
chosen for x86 exploit work first.

Default number base is **hex**. Use `0n100` when you mean decimal 100.
Registers are written as `@eax`, `@esp`, and `@eip`. `poi(x)` means "read the
pointer stored at `x`". WinDbg comments use `$$` inside scripts.

## 1. Start the session

| Command | Why use it | Example |
|---|---|---|
| `cdb -o -G target.exe args` | Launch under the debugger and keep child processes visible. | `cdb -o -G vuln_strcpy_x86.exe AAAA` |
| `cdb -cf script.wds target.exe` | Run a command script at the initial loader break, then continue. | `cdb -cf setup.wds vuln_strcpy_x86.exe` |
| `windbgx -o -g target.exe args` | Same idea in WinDbg Preview. Use this when you want the GUI. | `windbgx -o -g vuln_strcpy_x86.exe AAAA` |
| `windbg -p <pid>` | Attach to a running process by PID. | `windbg -p 4128` |
| `windbg -pn name.exe` | Attach by image name when the PID is not stable. | `windbg -pn vuln_strcpy_x86.exe` |
| `.sympath srv*c:\sym*https://msdl.microsoft.com/download/symbols` | Set a symbol path that can pull Microsoft symbols on demand. | `.sympath srv*c:\sym*https://msdl.microsoft.com/download/symbols` |
| `.reload /f` | Force symbol reload after you change the symbol path or load a new module. | `.reload /f` |
| `lm` | List loaded modules. Good first check after attach. | `lm` |
| `lm m vuln*` | Filter the module list to a target pattern. | `lm m vuln*` |
| `lmf` | Show loaded modules with their paths. | `lmf` |
| `x ntdll!*Ldr*` | Search symbols by wildcard when you know the subsystem but not the exact name. | `x ntdll!*Ldr*` |
| `ln 0x76f7db6b` | Ask WinDbg for the nearest symbol to an address. | `ln 0x76f7db6b` |
| `!analyze -v` | Let WinDbg summarize the exception and common crash clues. | `!analyze -v` |
| `dx @$osed().help()` | If the osed-windbg toolkit is loaded, show command help first. | `dx @$osed().help()` |
| `dx @$osed().triage()` | Run a fast read-only crash triage for control, SEH, stack, and modules. | `dx @$osed().triage()` |

## Threads and expressions

Use this section when the debugger output is ambiguous and you need to confirm
which thread owns the state you are reading, or when you need to do explicit
address math instead of relying on a higher-level helper.

| Command | Why use it | Example |
|---|---|---|
| `~` | List all threads, their TEBs, and current execution state. | `~` |
| `~1s` | Switch to thread 1 when you want a different execution context. | `~1s` |
| `~*k` | Show the call stacks for all threads at once. | `~*k` |
| `? expr` | Evaluate an expression, including pointer arithmetic and offsets. | `? @esp+0x20` |
| `? poi(@rsp)` | Dereference a stack pointer and inspect the value it points to. | `? poi(@rsp)` |
| `? poi(@esp+4)` | Common pattern for following the first stack argument. | `? poi(@esp+4)` |
| `? @$ra` | Show the current return address without manually dereferencing the stack. | `? @$ra` |
| `?? expr` | Use the alternate expression evaluator when you want C++-style evaluation. | `?? (void**)@rsp` |
| `.formats expr` | Inspect a value in multiple numeric representations. | `.formats poi(@esp)` |
| `k 2` | Limit the stack trace to a small number of frames for quick triage. | `k 2` |
| `dx (void**)@rsp` | Typed pointer inspection bridge between raw memory and `dx`. | `dx (void**)@rsp` |

## 2. Read the crash state

| Command | Why use it | Example |
|---|---|---|
| `r` | Dump registers, flags, and the next instruction in one shot. | `r` |
| `r eip` | Check whether instruction pointer control is obvious. | `r eip` |
| `r esp` | Confirm the current stack pointer before reading stack data. | `r esp` |
| `.exr -1` | Show the last exception record. | `.exr -1` |
| `.ecxr` | Switch to the exception context register state. | `.ecxr` |
| `k` | Show the current call stack quickly. | `k` |
| `kb` | Show the stack with the first three arguments for each frame. | `kb` |
| `kp` | Show the stack with full parameters when symbols support it. | `kp` |
| `dps esp L40` | Dump stack pointers with symbol resolution. This is a common post-crash view. | `dps esp L40` |
| `dd esp L20` | Read raw DWORDs from the stack when you want exact values. | `dd esp L20` |
| `da poi(esp+4)` | Follow the argument pointer and read the pointed-to ASCII string. | `da poi(esp+4)` |
| `db esp L20` | Inspect the first bytes near the stack pointer. | `db esp L20` |

## 3. Control execution

| Command | Why use it | Example |
|---|---|---|
| `g` | Continue execution. | `g` |
| `g 0x401000` | Run until a specific address. | `g 0x401000` |
| `p` | Step over one instruction. | `p` |
| `t` | Step into one instruction. | `t` |
| `pa 0x401050` | Step over until an address is reached. | `pa 0x401050` |
| `pt` | Step to the next `ret`. | `pt` |
| `pc` | Step to the next `call`. | `pc` |
| `gu` | Run until the current function returns. | `gu` |
| `.restart` | Restart the target from scratch after a bad run. | `.restart` |
| `q` | Quit the debugger. | `q` |
| `qd` | Quit and detach. | `qd` |

## 4. Place breakpoints

| Command | Why use it | Example |
|---|---|---|
| `bp module+0x1821` | Break at a module-relative offset. | `bp vuln_strcpy_x86+0x1821` |
| `bp kernel32!WinExec` | Break on a known symbol. | `bp kernel32!WinExec` |
| `bu module!func` | Deferred breakpoint that resolves after the module loads. | `bu msvcrt!strcpy` |
| `ba w4 0x402000` | Break when 4 bytes at an address are written. | `ba w4 0x402000` |
| `bp address "command; g"` | Run a command list on break, then continue. | `bp kernel32!CreateFileA "kb; dd esp L10; g"` |
| `bl` | List active breakpoints. | `bl` |
| `bc *` | Clear all breakpoints. | `bc *` |
| `bd 0` | Disable breakpoint 0 without deleting it. | `bd 0` |
| `be 0` | Re-enable breakpoint 0. | `be 0` |

## 5. Read registers and flags

| Command | Why use it | Example |
|---|---|---|
| `r eax` | Show one register. | `r eax` |
| `r eax=0x41414141` | Set a register while testing assumptions. | `r eax=0x41414141` |
| `r $t0=0x100` | Use a scratch pseudo-register for notes or temporary values. | `r $t0=0x100` |
| `r @eip` | Read the instruction pointer without symbol lookup. | `r @eip` |
| `r` output flags | Read `zr`, `cy`, `ov`, `pl`, and `mi` when the flags matter. | `r` |

## 6. Inspect memory

| Command | Why use it | Example |
|---|---|---|
| `db addr L20` | View raw bytes and ASCII together. | `db esp L20` |
| `dd addr L40` | View DWORDs. This is the workhorse for stack reads. | `dd esp L40` |
| `dps addr L20` | View DWORDs and resolve any pointers to symbols. | `dps esp L20` |
| `dc addr` | View DWORDs as ASCII and hex. | `dc esp L10` |
| `dw addr` | View 16-bit words. | `dw esp L10` |
| `dq addr` | View 64-bit values. Useful on x64 or when reading 8-byte fields. | `dq rsp L10` |
| `da addr` | Read ASCII text at an address. | `da poi(esp+4)` |
| `du addr` | Read UTF-16 text at an address. | `du poi(esp+4)` |
| `dt ntdll!_PEB @$peb` | Dump the current process environment block if symbols are present. | `dt ntdll!_PEB @$peb` |
| `dt ntdll!_TEB @$teb` | Dump the current thread environment block if symbols are present. | `dt ntdll!_TEB @$teb` |
| `!address esp` | Check the memory region and protection flags around a pointer. | `!address esp` |
| `eb addr 90 90` | Patch bytes in memory. | `eb eip 90 90` |
| `ed addr 0x41414141` | Patch a DWORD in memory. | `ed esp 0x41414141` |

## 7. Disassemble and inspect code

| Command | Why use it | Example |
|---|---|---|
| `u eip` | Disassemble forward from the current instruction. | `u eip` |
| `u addr L20` | Disassemble a specific range. | `u 0x401000 L20` |
| `ub addr` | Disassemble backward to find the call that led here. | `ub 0x401050` |
| `uf module!func` | Disassemble a whole function. | `uf kernel32!WinExec` |
| `u poi(@esp)` | Disassemble the return target or saved code pointer on the stack. | `u poi(@esp)` |
| `dx @$osed().sc.base("kernel32")` | Use the toolkit to resolve a module base before reading code around it. | `dx @$osed().sc.base("kernel32")` |

## 8. Follow the stack and frames

| Command | Why use it | Example |
|---|---|---|
| `.frame N` | Switch to a different stack frame. | `.frame 2` |
| `dv` | Show local variables when private symbols are available. | `dv` |
| `k` | Re-check the stack after changing frame or context. | `k` |
| `kb` | Use when you want arguments alongside return addresses. | `kb` |
| `kp` | Use when you want fuller parameter decoding. | `kp` |

Stripped binary rule of thumb: read the prologue. `sub esp,0x208` tells you how
much local space was reserved. `[ebp-N]` is a local, `[ebp+8..]` are arguments,
and `[ebp+4]` is the saved return address.

## 9. Search memory

| Command | Why use it | Example |
|---|---|---|
| `s -a 0 L?80000000 "TRUN"` | Search for an ASCII string across memory. | `s -a 0 L?80000000 "TRUN"` |
| `s -u 0 L?80000000 "calc"` | Search for a UTF-16 string. | `s -u 0 L?80000000 "calc"` |
| `s -b 0 L?80000000 90 90 90 90` | Search for a raw byte pattern. | `s -b 0 L?80000000 90 90 90 90` |
| `s -d 0 L?80000000 0x41414141` | Search for a DWORD value. | `s -d 0 L?80000000 0x41414141` |
| `dx @$osed().pattern_create(300, "msf")` | Generate a cyclic pattern for offset finding. | `dx @$osed().pattern_create(300, "msf")` |
| `dx @$osed().pattern_offset(0x39654138, "msf")` | Convert a crash value into an offset. | `dx @$osed().pattern_offset(0x39654138, "msf")` |
| `dx @$osed().exploit("offset")` | Generate the usual pattern workflow commands in one step. | `dx @$osed().exploit("offset")` |

## 10. Walk the process model and loaded modules

| Command | Why use it | Example |
|---|---|---|
| `!teb` | Show thread environment block details quickly. | `!teb` |
| `!peb` | Show process environment block details quickly. | `!peb` |
| `dt ntdll!_PEB @$peb` | Read the current PEB as a typed structure. | `dt ntdll!_PEB @$peb` |
| `dt ntdll!_TEB @$teb` | Read the current TEB as a typed structure. | `dt ntdll!_TEB @$teb` |
| `lm` | Confirm which modules are loaded. | `lm` |
| `lm m kernel*` | Filter to the modules that matter. | `lm m kernel*` |
| `!dh kernel32` | Inspect PE headers for a loaded module. | `!dh kernel32` |
| `!lmi kernel32` | Show detailed loaded-module information. | `!lmi kernel32` |
| `dx @$osed().sc.peb()` | Ask the toolkit to summarize PEB state. | `dx @$osed().sc.peb()` |
| `dx @$osed().sc.modules()` | Ask the toolkit for a module table. | `dx @$osed().sc.modules()` |
| `dx @$osed().sc.modules("kernel")` | Filter the toolkit module view. | `dx @$osed().sc.modules("kernel")` |

## 11. Read PE headers and exports

| Command | Why use it | Example |
|---|---|---|
| `!dh -f module` | Dump headers and file layout for a module. | `!dh -f kernel32` |
| `!dh module` | Inspect the DOS and NT headers for the module. | `!dh kernel32` |
| `dx @$osed().sc.exportdir("kernel32")` | Show the export directory in a structured view. | `dx @$osed().sc.exportdir("kernel32")` |
| `dx @$osed().sc.export("kernel32", "GetProcAddress")` | Resolve a named export directly. | `dx @$osed().sc.export("kernel32", "GetProcAddress")` |
| `dx @$osed().sc.exportwalk("kernel32", "GetProcAddress")` | Walk exports the way shellcode would. | `dx @$osed().sc.exportwalk("kernel32", "GetProcAddress")` |
| `dx @$osed().sc.exportat("kernel32", 842)` | Resolve by ordinal/index when that is all you have. | `dx @$osed().sc.exportat("kernel32", 842)` |
| `dx @$osed().sc.hashes("kernel32", "crc32")` | See hash values for a whole module. | `dx @$osed().sc.hashes("kernel32", "crc32")` |
| `dx @$osed().sc.hash("WinExec", "ROR13")` | Compute a hash for one API name. | `dx @$osed().sc.hash("WinExec", "ROR13")` |
| `dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")` | Reverse a hash to a likely API name. | `dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")` |
| `dx @$osed().sc.algorithms()` | List the supported hash algorithms. | `dx @$osed().sc.algorithms()` |

## 12. Use exploit-development helpers

| Command | Why use it | Example |
|---|---|---|
| `!exchain` | Inspect the SEH chain during exception work. | `!exchain` |
| `sxe av` | Break on access violations so you can stop at the fault. | `sxe av` |
| `sxd av` | Ignore access violations when you want the program to continue. | `sxd av` |
| `sxe ld:module` | Break when a module loads. Useful for deferred breakpoint work. | `sxe ld:kernel32` |
| `.exr -1` | Re-check the exception record when you return to the crash. | `.exr -1` |
| `.ecxr` | Switch into the exception context before inspecting registers. | `.ecxr` |
| `dx @$osed().seh()` | Inspect the SEH chain with toolkit support. | `dx @$osed().seh()` |
| `dx @$osed().seh_ppr("libspp.dll", "00 0A 0D", 50, true, "fast")` | Find usable `pop; pop; ret` candidates for SEH work. | `dx @$osed().seh_ppr("libspp.dll", "00 0A 0D", 50, true, "fast")` |
| `dx @$osed().pivots("essfunc")` | Search for stack pivots in a chosen module. | `dx @$osed().pivots("essfunc")` |
| `dx @$osed().rop("essfunc")` | Scope the gadget search to a module. | `dx @$osed().rop("essfunc")` |
| `dx @$osed().rop_suggest("essfunc")` | Get validated gadget suggestions. | `dx @$osed().rop_suggest("essfunc")` |
| `dx @$osed().find_bytes("essfunc", "FF E4")` | Search a module for a specific instruction byte sequence. | `dx @$osed().find_bytes("essfunc", "FF E4")` |
| `dx @$osed().badchars(0x00B8F900)` | Compare memory against an expected byte sequence after a badchar probe. | `dx @$osed().badchars(0x00B8F900)` |
| `.writemem C:\dbg\dump.bin poi(@esp+4)+0x7d6 (poi(@esp+4)+0x7d6)+0x200` | Dump a candidate buffer for offline comparison. | `.writemem C:\dbg\dump.bin poi(@esp+4)+0x7d6 (poi(@esp+4)+0x7d6)+0x200` |
| `.logopen c:\dbg\log.txt` | Capture output to a file for later review. | `.logopen c:\dbg\log.txt` |
| `.logclose` | Stop logging. | `.logclose` |
| `.printf "eip=%x\n", @eip` | Print a formatted line inside a script or command list. | `.printf "eip=%x\n", @eip` |
| `.echo BADCHAR_CRASH` | Emit a marker that is easy to spot in logs. | `.echo BADCHAR_CRASH` |
| `$$<c:\s.wds` | Run a script file. | `$$<c:\s.wds` |
| `.foreach (a {!some}) { u a }` | Iterate over the output of another command. | `.foreach (a {!some}) { u a }` |
| `.shell -ci "cmd" cmd /c move ...` | Run a host command from the debugger. | `.shell -ci "dir" cmd /c dir` |

## 13. x86-to-x64 notes

The flow stays the same on x64, but the registers, pointer width, and a few
structure offsets change. Treat this section as the delta list, not a second
workflow.

| Command | Why use it | Example |
|---|---|---|
| `r rcx` / `r rdx` / `r r8` / `r r9` | x64 first four arguments live in registers. | `r rcx` |
| `dq addr` | Read 8-byte values on x64. | `dq rsp L10` |
| `dt ntdll!_PEB @$peb` | The idea is the same even though the structure layout changes. | `dt ntdll!_PEB @$peb` |
| `dx @$osed().sc.peb()` | The toolkit adapts to the active architecture. | `dx @$osed().sc.peb()` |
| `dx @$osed().sc.export("kernel32", "GetProcAddress")` | Export walking is still the same concept on x64. | `dx @$osed().sc.export("kernel32", "GetProcAddress")` |

WoW64 note: for OSED-style 32-bit exploitation, use the 32-bit PEB and 32-bit
register model. The x64 companion is for the native 64-bit side only.

ARM and ARM64 notes live in [windbg-arm/README.md](windbg-arm/README.md) as a
separate delta sheet.

## 14. Suggested study order

1. Start the session and set symbols.
2. Read the crash state.
3. Inspect registers, stack, and memory.
4. Control execution and place breakpoints.
5. Search memory for patterns and bad characters.
6. Walk the PEB and loaded modules.
7. Read PE headers and exports.
8. Use the SEH, pivot, and gadget helpers.
9. Move to the x64 delta sheet once the x86 flow is comfortable.
