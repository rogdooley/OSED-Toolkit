# peinfo -- Static PE Analysis for Exploit Development

A single-command replacement for the half-dozen tools exploit developers
bounce between (PE-bear, CFF Explorer, dumpbin, `!dh`, sigcheck, mona modules)
when evaluating a target binary.

Produces a structured report covering PE headers, compile-time mitigations,
section layout, import categorization, interesting strings, gadget
pre-enumeration, and an exploitability summary -- all from static analysis
of a PE file on disk.

---

## Quick start

```bash
uv run peinfo target.exe
```

Plain text (no colors, good for piping):

```bash
uv run peinfo target.exe --plain
```

Machine-readable JSON:

```bash
uv run peinfo target.dll --json
```

---

## CLI reference

```
peinfo <pe_file> [--plain] [--json]

Arguments:
  pe_file           Path to a PE file (.exe or .dll)

Options:
  --plain           Plain-text output (no ANSI colors)
  --json            JSON output (full structured report)
  -h, --help        Show help
```

---

## What it reports

### PE Information

Everything from `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, and `IMAGE_OPTIONAL_HEADER`:

- Machine type, subsystem, linker version
- Compiler timestamp
- Checksum, characteristics

### PE Mitigations (static)

Decodes `DllCharacteristics` into individual flags rather than showing a raw hex value:

| Flag                   | What it means                            |
|------------------------|------------------------------------------|
| NX_COMPAT              | Opted in to DEP enforcement              |
| DYNAMIC_BASE           | ASLR-compatible (image can be relocated)  |
| HIGH_ENTROPY_VA         | 64-bit ASLR with high entropy            |
| FORCE_INTEGRITY        | Code integrity checks enforced           |
| NO_SEH                 | No structured exception handlers         |
| GUARD_CF (CFG)         | Control Flow Guard enabled               |
| TERMINAL_SERVER_AWARE  | Terminal Services aware                  |

Also detects:

- **Relocations** -- whether `.reloc` section or base relocation directory exists (ASLR cannot work without them)
- **GS security cookie** -- looks for `__security_cookie` / `__security_check_cookie` imports or references
- **SafeSEH** -- checks the Load Configuration directory for an SEH handler table

**Important:** These are compile-time PE metadata only.  Runtime mitigations
(actual DEP policy, ASLR load address, process mitigation policies, CFG enforcement)
require a live process and are deliberately not reported here.

### Memory Layout

- Image base, entry point, image size
- Section and file alignment
- Stack/heap reserve and commit sizes

### Sections

For each section: virtual address, virtual size, raw offset, raw size,
entropy, and permissions (R/W/X).

High entropy (> 7.0) is highlighted in red as a packing indicator.
A missing `.reloc` section is called out explicitly.

### Imported DLLs

Lists every imported DLL with function count.

### Interesting APIs (categorized)

Imports are classified into exploit-relevant categories:

- **Exploitation APIs** -- VirtualProtect, VirtualAlloc, LoadLibraryA, GetProcAddress, WinExec, ShellExecuteA, WriteProcessMemory, etc.
- **Dangerous CRT** -- strcpy, sprintf, gets, memcpy, strcat, scanf, etc.
- **Networking** -- recv, send, accept, bind, WSAStartup, InternetOpenA, etc.
- **Registry** -- RegOpenKeyEx, RegSetValueEx, etc.
- **Process** -- CreateThread, CreateRemoteThread, OpenProcess, IsDebuggerPresent, etc.
- **Crypto** -- CryptAcquireContext, CryptEncrypt, CryptDecrypt, etc.
- **File I/O** -- CreateFile, ReadFile, WriteFile, DeleteFile, etc.

### Interesting Strings

Scans the PE for ASCII strings matching patterns relevant to exploit
development and malware analysis:

- URLs (`http://`, `https://`, `ftp://`)
- Executables (`cmd.exe`, `calc.exe`, `powershell`)
- Sensitive keywords (`password`, `license`, `serial`, `admin`, `backdoor`)
- File extensions (`.dll`, `.exe`, `.bat`, `.ps1`)

### Version Resources

Dumps the PE version info when present: company, product, version,
description, copyright, original filename.

### Gadget Pre-Enumeration

Byte-pattern scans executable sections for common exploitation primitives:

| Gadget                 | Use case                                 |
|------------------------|------------------------------------------|
| RET                    | ROP chain terminator                     |
| POP r32; RET           | Single-pop gadgets for register control   |
| POP r32; POP r32; RET  | SEH overwrites (POP POP RET)             |
| JMP ESP                | Classic stack pivot / shellcode redirect  |
| CALL ESP               | Alternative shellcode redirect           |
| CALL r32               | Indirect call gadgets                    |
| PUSH ESP; RET          | Stack pivot                              |
| PUSHAD; RET            | Register preservation before shellcode   |
| XCHG EAX, ESP; RET     | Stack pivot via EAX                      |
| ADD ESP, imm; RET      | Stack adjustment                         |

This is a triage pass using byte patterns, not a full disassembly-validated
gadget search.  Use `gadgetfind.py` (live-process, PyKD) or a dedicated
ROP tool for validated gadgets with bad-character filtering.

### Exploitability Summary

Scores the binary as an ROP candidate based on a weighted combination of:

- Fixed image base (no DYNAMIC_BASE)
- NX_COMPAT absent
- No relocations
- No SafeSEH
- No CFG
- No GS cookie
- Available gadgets (RET count, JMP ESP presence)
- Useful imports (VirtualProtect, VirtualAlloc)

Reports both favorable factors and obstacles.

---

## Programmatic use

```python
from Tools.peinfo import PEAnalyzer

with PEAnalyzer("target.exe") as analyzer:
    report = analyzer.analyze()

print(report.mitigations.nx_compat)        # False
print(report.mitigations.dynamic_base)     # False
print(report.memory_layout["image_base"])  # 0x00400000
print(report.gadget_counts.jmp_esp)        # 2
print(report.exploitability.rop_candidate) # True

for reason in report.exploitability.reasons:
    print(f"  + {reason}")
```

The full `PEReport` dataclass serializes to JSON via `dataclasses.asdict()`.

---

## Portable bundle (air-gapped / exam machines)

peinfo can be packaged into a self-contained zip that runs on a Windows
machine with nothing but Python installed -- no pip, no internet.

**On your Linux/macOS prep machine (with internet):**

```bash
python -m Tools.peinfo.bundle -o peinfo_portable.zip
```

**On the target Windows machine:**

1. Copy `peinfo_portable.zip` over
2. Extract it
3. Run:

```
python peinfo_portable\peinfo.py target.exe
```

The bundle vendors `pefile` (pure Python, ~77 KB total zip).  If `rich` happens
to be installed on the target, you get colored output; otherwise it falls back
to plain text automatically.  No configuration, no install step.

---

## Dependencies

- `pefile` -- PE parsing (core dependency, installed automatically; vendored in portable bundle)
- `capstone` -- disassembly (optional, `pip install osed-toolkit[disasm]`)
- `lief` -- richer PE parsing and editing (optional, `pip install osed-toolkit[peinfo]`)
- `rich` -- terminal formatting (optional -- graceful fallback to plain text if absent)

---

## Design principle: static vs. runtime

This tool deliberately reports only what can be determined from the PE file
on disk.  It uses the term **NX_COMPAT** (a PE flag) rather than **DEP**
(an OS enforcement policy) because:

- A binary with NX_COMPAT set can still run with DEP disabled (system policy)
- A binary without NX_COMPAT can still have DEP enforced (OptIn/AlwaysOn policy)
- The actual DEP state is a runtime property of the process, not the file

The same distinction applies to ASLR (DYNAMIC_BASE is a PE flag; actual
randomized load addresses are a runtime property) and CFG (GUARD_CF is a
PE flag; enforcement depends on the OS and process state).

For runtime mitigation analysis, use a debugger (`!exploit`, process
mitigation queries, or the `@$osed().modules()` dx command).
