# OSED Toolkit

A personal workspace for Windows x86 exploit development, built around the
EXP-301 (OSED) curriculum. This repo is a work in progress. Some areas are
polished; others are experiments, dead ends, or early drafts that have not been
revisited. Expect rough edges.

## What is here

### Tools that work

**`Tools/emitter/`** -- The shellcode emitter. Generates position-independent
x86 assembly for common payloads (reverse shell, bind shell, file copy, command
execution) by resolving Win32 API hashes at runtime via PEB walking. This is
the tool that gets actual use.

**`osed-windbg/`** -- A WinDbg JavaScript extension for exploit development
triage. Module/mitigation enumeration, cyclic pattern generation, bad-character
comparison, ROP gadget scanning with semantic classification, IAT resolution,
and format-string offset calculation, all from the `dx` evaluator. Has its own
[README](osed-windbg/README.md) and is published as a standalone project.

**`shellforge/`** -- CLI for shellcode analysis: disassembly, bad-character
detection, entropy measurement, PE export walking, XOR/alphanumeric encoding,
and multiple output formats (Python, C array, hex dump, raw).

### Tools in various states

**`Tools/`** contains several subsystems at different levels of completeness:

| Directory | What it does | Status |
|---|---|---|
| `emitter/` | Shellcode emitter (see above) | Active |
| `exploit/` | Exploit framework (layout builder, transport, constraint engine) | Partially built |
| `badchars/` | Bad-character detection and automated WinDbg comparison | Works |
| `pattern/` | Cyclic pattern create/offset | Works |
| `crashtriage/` | Crash dump parser and exploitability ranker | Works |
| `egghunter/` | Egghunter stub generator | Works |
| `rop/` | ROP chain model, gadget DB, validator | Early |
| `shellcode/` | Shellcode parsing, formatting, encoding | Works |
| `rawlayout/` | Raw payload layout builder | Early |
| `target_profile/` | Binary semantics extraction for automated triage | Early |

**`asm_lab/`** -- An x86 assembly teaching environment with fixture-based
validation, explanation engine, and CPU executor. Functional but not integrated
into a larger workflow.

### Learning materials

**`Learning/`** -- Lab walkthroughs organized by topic. The most developed is
`Win32_X86/07_dep_bypass/`, which has a full walkthrough from reconnaissance
through three DEP-bypass APIs (VirtualProtect, VirtualAlloc,
WriteProcessMemory), plus an SEH+DEP variant. Earlier modules (setup, fuzzing,
WinDbg basics, IDA basics, mitigations, network overflow) are shorter.

**`Documentation/`** -- Reference material including an x86 assembly guide for
reverse engineers, emitter documentation, and IAT resolution technique notes.

**`DRILLS/`** -- Structured exercise templates for practising reverse
engineering, crash analysis, ROP construction, and related skills.

**`Notes/`** -- Personal notes on stack mechanics, exploit control flow,
egghunters, and protocol bad characters.

### Everything else

**`Experiments/`** -- Throwaway scripts and proof-of-concept code. Some of
this informed tools that now live elsewhere; most of it is abandoned.

**`Exploits/`** -- Exploit templates and example shellcode scripts.

**`Examples/`** -- Sample emitter usage (calc, reverse shell, bind shell,
custom functions, file copy).

**`Modules/`**, **`emitter_out/`**, **`output/`**, **`tmp/`** -- Build
artifacts, scratch output, and module exercises at various stages of
completion.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

The WinDbg extension requires no Python environment. Copy `osed-windbg/dist/osed.js`
to your Windows target and load it with `.scriptload`.

## Status

This is a learning repo, not a product. The emitter, the WinDbg extension, and
shellforge are the most reliable pieces. Everything else ranges from "works but
untested" to "abandoned experiment." Contributions are not expected, but if you
are working through EXP-301 and find something useful, that is the intent.
