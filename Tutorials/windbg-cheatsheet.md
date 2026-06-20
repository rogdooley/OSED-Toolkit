---
title: "WinDbg / cdb Cheat Sheet — x86 Exploit Dev (OSED)"
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

Default number base is **hex**. Write decimal as `0n100`. Registers are `@eax`, pseudo-regs `$teb`. `poi(x)` = deref pointer at x. Comment in scripts with `$$` or `*`.

## Launch / Attach / Symbols

| Command | Purpose |
|---|---|
| `cdb -o -G target.exe args` | Launch + debug children, ignore final break. (`-g` skips the *initial* break — usually leave it off.) |
| `cdb -cf script.wds target.exe` | Run script at initial loader break, then continue. |
| `windbg -p <pid>` / `-pn name.exe` | Attach to running process by pid / name. |
| `.sympath srv*c:\sym*https://msdl.microsoft.com/download/symbols` | Set Microsoft symbol path. |
| `.reload /f` | Force-reload symbols for all modules. |
| `lm` / `lmf` / `lm m vuln*` | List modules / with paths / filtered. |
| `x ntdll!*Ldr*` | Search symbols by wildcard. |
| `ln 0x76f7db6b` | Nearest symbol to an address. |

## Execution Control

| Command | Purpose |
|---|---|
| `g` | Go (run). `g 0x401000` = run to address. |
| `p` / `t` | Step over / step into (one instruction). |
| `pa 0x401050` | Step (over) until address is reached. |
| `pt` / `pc` | Step to next `ret` / next `call`. |
| `gu` | Go up — run until current function returns. |
| `.restart` | Restart the target from scratch. |
| `q` / `qd` | Quit (kill) / quit and detach. |

## Breakpoints

| Command | Purpose |
|---|---|
| `bp module+0x1821` | Software BP at module RVA (module already loaded). |
| `bp kernel32!WinExec` | BP on a symbol. |
| `bu module!func` | **Deferred** BP — resolves when module loads. |
| `ba w4 0x402000` | **Hardware** BP: break on 4-byte **w**rite (also `r`/`e`/`i`). |
| `bp x "command; g"` | BP that runs a command list then continues. |
| `` bp x ".if (poi(@esp+8)==0x41) {} .else {gc}" `` | Conditional BP (break only when condition holds). |
| `bl` / `bc *` / `bd 0` / `be 0` | List / clear all / disable / enable BP. |
| `bp x 1000` | Pass count — break only on the 1000th hit. |

## Registers and Flags

| Command | Purpose |
|---|---|
| `r` | Dump all registers + flags + next instruction. |
| `r eax` / `r eax=0x41414141` | Show / set a single register. |
| `r $t0=0x100` | Set a scratch pseudo-register (`$t0`..`$t19`). |
| flags | `zr`=ZF `cy`=CF `ov`=OF `pl/mi`=sign — shown in `r`. |

## Examining Memory

| Command | Purpose |
|---|---|
| `db esp L20` | Bytes + ASCII, 0x20 of them. |
| `dd esp L40` | DWORDs (the stack-reading workhorse). |
| `dps esp L20` | DWORDs **with symbol resolution** (find return addrs). |
| `dc`, `dw`, `dq` | DWORD+ASCII, WORDs, QWORDs. |
| `da` / `du addr` | ASCII / Unicode string at address. |
| `dt ntdll!_PEB @$peb` | Dump a typed structure (if symbols present). |
| `!address esp` | Region info + permissions for an address. |
| `eb addr 90 90` / `ed addr 0x..` | Edit bytes / dword in memory. |

## Disassembly

| Command | Purpose |
|---|---|
| `u eip` / `u addr L20` | Disassemble forward (default 8 instrs). |
| `ub addr` | Disassemble **backward** (find the call before a ret addr). |
| `uf module!func` | Disassemble a whole function. |
| `u poi(@esp)` | Disassemble at the address on top of stack. |

## Stack and Call Frames

| Command | Purpose |
|---|---|
| `k` / `kb` / `kp` | Call stack / with first 3 args / with full params. |
| `.frame N` | Switch to frame N (then `dv`, `dd ebp` are in its context). |
| `dv` | Local variables (needs **private** symbols — fails on stripped). |

Stripped binary (no `dv`): read the prologue. `sub esp,0x208` = local size; `[ebp-N]` = locals, `[ebp+8..]` = args, `[ebp+4]` = saved return address.

## Searching Memory

| Command | Purpose |
|---|---|
| `s -a 0 L?80000000 "TRUN"` | Search all memory for ASCII string. |
| `s -u 0 L?80000000 "calc"` | Search for Unicode string. |
| `s -b 0 L?80000000 90 90 90 90` | Search for a byte pattern (e.g. NOP sled). |
| `s -d 0 L?80000000 0x41414141` | Search for a DWORD value. |

## SEH / Exceptions (OSED-critical)

| Command | Purpose |
|---|---|
| `!exchain` | Show the SEH chain (handler addresses). |
| `sxe av` / `sxd av` | Break on / ignore access violations. |
| `sxe ld:module` | Break when a specific module loads. |
| `g` (after AV) | First chance vs second chance — pass once to reach handler. |
| `.exr -1` / `.ecxr` | Show last exception record / its context. |

## Exploit-Dev Recipes

```
Pattern -> offset (no Mona):
  send cyclic pattern, crash, then:   r eip
  msf-pattern_offset -q <eip value>   (or !mona findmsp)

Find a jmp esp / call esp return address:
  s -b 0x62500000 L?1000 ff e4          $$ jmp esp opcode
  s -b 0x62500000 L?1000 ff d4          $$ call esp
  !mona jmp -r esp -cpb '\x00\x0a\x0d'  $$ with bad-char filter

POP/POP/RET for SEH:
  !mona seh -cpb '\x00\x0a\x0d'

Dump a buffer to disk (bad-char capture):
  .writemem C:\dbg\dump.bin poi(@esp+4)+0x7d6 (poi(@esp+4)+0x7d6)+0x200

Compare bytes in memory vs a clean array:
  !mona compare -f C:\mona\bytearray.bin -a <addr>

Verify a candidate dump (Python side):  dump[:4] == b"\xbc\xf0\xbc\xf0"
```

## Pseudo-Registers and Operators

| Token | Meaning |
|---|---|
| `@eax @esp @eip` | Register values (the `@` avoids symbol lookup). |
| `$teb` `$peb` | TEB / PEB base for current thread/process. |
| `$ra` `$ip` `$csp` | Return address / instruction ptr / stack ptr. |
| `poi(x)` | Pointer dereference: the DWORD stored at x. |
| `by(x)` `wo(x)` `dwo(x)` | Byte / word / dword at x. |
| `? expr` | Evaluate an expression. `? poi(@esp+4)+0n2006`. |
| `0n100` / `0x64` | Decimal 100 / hex 100. Default base is **hex**. |

## Logging and Scripting

| Command | Purpose |
|---|---|
| `.logopen c:\dbg\log.txt` / `.logclose` | Capture session output to a file. |
| `.printf "eip=%x\\n", @eip` | Formatted output in a command/script. |
| `.echo BADCHAR_CRASH` | Emit a marker string (for harness detection). |
| `$$<c:\s.wds` / `$><c:\s.wds` | Run a script file (`$><` allows block commands). |
| `.foreach (a {!some}) { u a }` | Iterate over tokens of another command's output. |
| `.shell -ci "cmd" cmd /c move ...` | Run a host shell command (e.g. atomic dump rename). |
