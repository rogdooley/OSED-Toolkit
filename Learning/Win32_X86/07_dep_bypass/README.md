# VulnSvc — 32-bit Windows Stack-Overflow & DEP-Bypass Lab

A deliberately vulnerable 32-bit Windows TCP service, its companion DLLs, and a
complete from-source exploit-development walkthrough. Built to teach the
*decisions* behind a DEP bypass — module selection, bug triage, gadget choice —
not just to hand over a finished script.

**Original, independent educational material** teaching public, decades-old
techniques (ROP, DEP bypass, IAT API resolution) with a purpose-built target and
its own addresses. Not affiliated with or derived from any commercial course or
vendor. MIT-licensed (`LICENSE`). Read `DISCLAIMER.md` before use.

> **Lab use only.** `service.exe` is intentionally insecure and its bug is
> remotely reachable. Build and run it **only** inside a throwaway, isolated
> Windows VM that is not on any network you care about. Do not use these
> techniques against systems you do not own or lack written authorization to
> test.

## What this is

You compile the target yourself (Windows + MSVC x86), so every WinDbg
observation is reproducible on *your* binary and you rederive the ROP gadgets
from *your* build. That is the point: on a real target the addresses are always
yours to find.

## Start here

1. **`BUILD.md`** — compile all five modules with the exact mitigation profile
   (`build.bat` does it in one shot), then verify with `dumpbin`/Narly.
2. **`WALKTHROUGH.md`** — the tutorial. 14 chapters + 3 appendices, from recon to
   a working VirtualProtect chain, then VirtualAlloc and WriteProcessMemory, then
   what ASLR would break.
3. **`exploit/exploit.py`** — staged PoC scaffold; fill the gadget table from
   your build and drive it `trigger → pattern → eip → badchars → rop`.

## The five modules (and the lesson each carries)

| Module | Profile | Role |
|---|---|---|
| `service.exe` | base `0x00400000`, DEP on, no ASLR/SafeSEH/GS | Vulnerable target. Its own addresses all carry `0x00` → unusable for gadgets. |
| `compression.dll` | base `0x61500000`, no ASLR, `/O2`, imports VA+VP | **The correct gadget source.** You derive this, not get told it. |
| `helper.dll` | **ASLR on**, great gadgets | The trap: quality never beats predictability. |
| `crypto.dll` | no ASLR, `/Od`, no useful imports | Noise: thin, no API to resolve. |
| `network.dll` | no ASLR, `/O2`, no VA/VP import | Viable but inferior: good gadgets, wrong imports. |

## The bug

Reachable only via `OP_CONFIG_SET`, and only after `OP_AUTH`. Buried in
`parser.c`:

```c
sscanf(body, "%31s %63s %s", command, name, value);   /* third %s has no width */
```

Two sibling parsers look just as suspicious and are perfectly safe — the
walkthrough teaches you to tell them apart by *following the bytes*, not by
grepping for `sscanf`.

## Layout

```
vulnsvc-lab/
├── README.md  BUILD.md  WALKTHROUGH.md  build.bat
├── LICENSE  DISCLAIMER.md
├── exploit/exploit.py
├── solutions/SOLUTIONS.md  solutions/exploit_virtualalloc.py
└── src/{service,compression,helper,crypto,network}/...
```
