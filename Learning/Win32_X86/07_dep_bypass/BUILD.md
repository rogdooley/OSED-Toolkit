# Building the VulnSvc Lab

A deliberately vulnerable 32-bit Windows TCP service plus companion DLLs, for
practising stack-overflow / DEP-bypass exploit development. **Lab use only.**

The mitigation profile is chosen deliberately per module so that *module
selection* becomes a real decision (see `WALKTHROUGH.md`, Chapter 3). Build
exactly as specified or the lesson changes.

---

## 1. Prerequisites

- Windows 10 x86/x64 VM (a throwaway you can crash and restart).
- **Visual Studio bulid tools** with the **x86** toolset. Everything is 32-bit.
- Open the **"x86 Native Tools Command Prompt for VS"** (not x64). Verify:

```
cl
Microsoft (R) C/C++ Optimizing Compiler ... for x86
```

- WinDbg (from the Windows SDK / "Debugging Tools for Windows").
- Optional but recommended: `rp++` (rp-win-x86.exe), the Narly WinDbg extension.

---

## 2. Target mitigation profile (what we are building)

| Module | ImageBase | ASLR (`/DYNAMICBASE`) | DEP (`/NXCOMPAT`) | SafeSEH | `/GS` | Opt | Role |
|---|---|---|---|---|---|---|---|
| **service.exe** | `0x00400000` | **OFF** | **ON** | **OFF** | **OFF** | `/Od` | Vulnerable target. Base has a `0x00` high byte → its own gadgets are unusable. |
| **compression.dll** | `0x61500000` | **OFF** | ON | n/a | off | **`/O2`** | **Correct gadget source.** No ASLR, bad-char-free base, imports VirtualAlloc + VirtualProtect, dense gadgets. |
| **helper.dll** | `0x62000000` | **ON** | ON | n/a | off | `/O2` | **Trap.** Beautiful gadgets, but ASLR randomizes its base → reject. |
| **crypto.dll** | `0x63000000` | OFF | ON | n/a | off | `/Od` | Noise. No ASLR but poor gadget density and imports no useful API. |
| **network.dll** | `0x64000000` | OFF | ON | n/a | off | `/O2` | Noise. No ASLR, good gadgets, but does **not** import VirtualAlloc/VirtualProtect. |

Key flags explained:

- **`/DYNAMICBASE:NO`** — disables ASLR; the module loads at its preferred base.
- **`/NXCOMPAT`** — sets the NX-compatible bit → **DEP is enabled and permanent**
  for the process. This is why you do not need EMET/WDEG here (though the
  walkthrough shows how you *would* enable it externally if it were missing).
- **`/SAFESEH:NO`** — no SafeSEH table (the bug is a straight stack smash, not
  an SEH overwrite; a later exercise covers the SEH path).
- **`/GS-`** — no stack cookie on the vulnerable function. `/GS` is a *separate*
  mitigation; disabling it here isolates the DEP lesson. Bypassing `/GS` is its
  own module.
- **`/O2` on the gadget DLL** — optimization is what *creates* gadgets. A debug
  (`/Od`) build has terrible gadget density. This is a real-world lesson.
- **`/MT`** — static CRT, so the process module list stays clean (no extra
  `vcruntime`/`ucrtbase` DLLs cluttering your `lm` output).

---

## 3. One-shot build

From the repo root in the **x86** VS command prompt:

```bat
build.bat
```

`build.bat` (also included) does the following, in order (DLLs first so their
import libraries exist for the EXE link):

```bat
@echo off
setlocal
if not exist bin mkdir bin
pushd bin

echo === compression.dll (CORRECT gadget source) ===
cl /nologo /O2 /MT /GS- /TC /I..\src\compression ..\src\compression\compression.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x61500000 ^
   /OUT:compression.dll /IMPLIB:compression.lib

echo === helper.dll (TRAP: ASLR ON) ===
cl /nologo /O2 /MT /GS- /TC ..\src\helper\helper.c ^
   /link /DLL /DYNAMICBASE /NXCOMPAT /BASE:0x62000000 ^
   /OUT:helper.dll /IMPLIB:helper.lib

echo === crypto.dll (noise: poor density, no useful imports) ===
cl /nologo /Od /MT /GS- /TC ..\src\crypto\crypto.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x63000000 ^
   /OUT:crypto.dll /IMPLIB:crypto.lib

echo === network.dll (noise: good gadgets, no VA/VP import) ===
cl /nologo /O2 /MT /GS- /TC ..\src\network\netlib.c ^
   /link /DLL /DYNAMICBASE:NO /NXCOMPAT /BASE:0x64000000 ^
   /OUT:network.dll /IMPLIB:network.lib ws2_32.lib

echo === service.exe (VULNERABLE TARGET) ===
cl /nologo /Od /MT /GS- /TC /I..\src\service ^
   ..\src\service\main.c ..\src\service\net.c ..\src\service\dispatch.c ^
   ..\src\service\handlers.c ..\src\service\parser.c ..\src\service\config.c ^
   ..\src\service\logging.c ^
   /link /DYNAMICBASE:NO /NXCOMPAT /SAFESEH:NO /BASE:0x00400000 ^
   compression.lib helper.lib crypto.lib network.lib ws2_32.lib ^
   /OUT:service.exe

popd
echo Done. Binaries in bin\
endlocal
```

> If a DLL fails to load at runtime because its preferred base is occupied,
> pick a different free base in the `0x6xxx0000` range and rebuild — just keep
> the high byte non-zero and bad-char-free.

---

## 4. Run the service

```bat
cd bin
service.exe
```

It listens on TCP **9999** (override: `service.exe 9998`). Leave the console
open; it logs each connection and request. Keep the VM offline.

Confirm all five modules are present in one process (from WinDbg once attached,
or Process Explorer): `service.exe`, `compression.dll`, `helper.dll`,
`crypto.dll`, `network.dll`.

---

## 5. Verify the mitigation profile before you start

This step *is* the first exercise. Do not skip it.

### 5.1 dumpbin (static, from disk)

```
dumpbin /headers bin\service.exe        | findstr /i "base dynamic nx"
dumpbin /headers bin\compression.dll    | findstr /i "base dynamic nx"
dumpbin /headers bin\helper.dll         | findstr /i "base dynamic nx"
dumpbin /imports  bin\compression.dll   | findstr /i "Virtual"
```

Expect:
- `service.exe`: image base `400000`, **no** "Dynamic base" in DLL
  characteristics, **NX compatible** present.
- `compression.dll`: image base `61500000`, no Dynamic base, imports
  `VirtualAlloc` and `VirtualProtect`.
- `helper.dll`: **"Dynamic base"** present (ASLR on).

### 5.2 Narly (runtime, in WinDbg)

Attach WinDbg to `service.exe`, then:

```
.load narly
!nmod
```

You should see ASLR flagged on `helper.dll` and absent on `compression.dll`,
`crypto.dll`, `network.dll`, and `service.exe`. This is the raw material for the
module-selection decision in Chapter 3.

### 5.3 Prove DEP is live

```
0:000> lm m service
0:000> !vprot esp
    Protect:  00000004  PAGE_READWRITE          <- stack is writable, not exec
```

Then simulate the classic stack execution and watch it fault (Chapter 5 walks
this in detail):

```
0:000> ed esp 90909090
0:000> r eip = esp
0:000> p
(xxxx.xxxx): Access violation - code c0000005   <- DEP working as intended
```

---

## 5.4 Troubleshooting

**`winsock.h` / `winsock2.h` redefinition errors** (`C2011 'sockaddr'`,
`C2059`, `FD_SET`/`timeval` redefinitions, dozens of `C4005` macro warnings):
this means `<windows.h>` pulled in the legacy Winsock 1 header before
`<winsock2.h>`. The sources define `WIN32_LEAN_AND_MEAN` up front to prevent it,
and `build.bat` also passes `/DWIN32_LEAN_AND_MEAN` globally. If you compile by
hand, include that define (or `#include <winsock2.h>` before `<windows.h>`).

**`C4996` deprecation warnings** for `sscanf`, `strcpy`, `fopen`, `localtime`,
etc. are expected — this is deliberately old-style code. `build.bat` passes
`/D_CRT_SECURE_NO_WARNINGS` to quiet them. They are warnings, not errors; the
build still succeeds without the define.

**`LNK2019 unresolved external`** for a DLL export (e.g. `ComputeChecksum`)
means the EXE was linked before the DLL import libs existed. Always build the
DLLs first (as `build.bat` does) so `compression.lib` etc. are present for the
`service.exe` link.

**A DLL fails to load at runtime** (`0xC000007B` / "side-by-side"): its preferred
`/BASE` is occupied. Pick another free `0x6xxx0000` base (non-zero, bad-char-free
high byte) and rebuild that DLL.

## 6. File map

```
vulnsvc-lab/
├── BUILD.md                 <- you are here
├── WALKTHROUGH.md           <- the tutorial
├── build.bat                <- one-shot build
├── exploit/
│   └── exploit.py           <- PoC scaffold (fill in YOUR gadget addresses)
└── src/
    ├── service/             <- service.exe
    │   ├── protocol.h  service.h  main.c  net.c  dispatch.c
    │   ├── handlers.c  parser.c   config.c  logging.c
    ├── compression/         <- compression.dll  (gadget source)
    │   ├── compression.h  compression.c
    ├── helper/helper.c      <- helper.dll   (ASLR trap)
    ├── crypto/crypto.c      <- crypto.dll   (noise)
    └── network/netlib.c     <- network.dll  (noise)
```

Proceed to `WALKTHROUGH.md`.
