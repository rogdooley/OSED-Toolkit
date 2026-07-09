# DEP-Bypass Variants & the Road to ASLR — Companion Guide

Companion to the Module 10 study guide. Covers the two API alternatives to `VirtualAlloc`, when each is worth choosing, and a forward look at why DEP alone is only half the battle once **ASLR** enters.

---

## 1. VirtualProtect — the closest cousin

### Prototype
```c
BOOL WINAPI VirtualProtect(
  _In_  LPVOID lpAddress,       // page holding your shellcode
  _In_  SIZE_T dwSize,          // >=1, per-page granularity
  _In_  DWORD  flNewProtect,    // PAGE_EXECUTE_READWRITE = 0x40
  _Out_ PDWORD lpflOldProtect   // pointer to a WRITABLE dword (receives old prot)
);
```

### How it differs from VirtualAlloc
Same end state (RW → RWX on the shellcode page), same 4-argument skeleton, same patch-in-place methodology. **One trap that VirtualAlloc doesn't have:** the 4th argument `lpflOldProtect` is an `_Out_` pointer — VirtualProtect **writes** the previous protection there. It must point at a **valid, writable** address you don't care about clobbering. If you pass junk (e.g. a leftover `0x51515151`), the call faults on the write and you lose the shell.

**Standard fix:** point `lpflOldProtect` at a scratch stack slot. A convenient choice is a location inside your own buffer/skeleton that is no longer needed by the time VirtualProtect runs — or simply a dword a bit further down the stack. You resolve its address the same way you resolve the shellcode address: copy ESP/ESI and offset.

### Argument recipe (analogue of the VirtualAlloc chain)
| Slot | Value | How to build (null-free) |
|---|---|---|
| lpAddress | shellcode stack addr | ESI + offset, patch in place |
| dwSize | `0x01` | `pop 0xFFFFFFFF ; neg eax` |
| flNewProtect | `0x40` | `0x80808080 + 0x7F7F7FC0` |
| lpflOldProtect | writable scratch ptr | ESI/ESP + offset to a throwaway dword |
| return addr | shellcode | patch in place |

### When to prefer VirtualProtect over VirtualAlloc
- The public exploit / gadget set already resolves `VirtualProtect` in the IAT and not `VirtualAlloc` (check the Imports tab in IDA / `dps` the IAT).
- You want to flip an **existing** page and never care about "allocation" semantics — VirtualProtect states intent more directly.
- Slightly fewer conceptual moving parts *except* for the writable-pointer requirement, which is the one thing to get right.

> **Signal vs. Noise.** *Signal:* whichever of VirtualAlloc/VirtualProtect your chosen module actually **imports** is the one to use — don't force an API that isn't in the IAT. *Noise:* agonising over which is "better"; they're equivalent. The only real differentiator is remembering VirtualProtect's writable `lpflOldProtect`.

---

## 2. WriteProcessMemory (WPM) — "follow the rules" instead of bending them

### Prototype
```c
BOOL WINAPI WriteProcessMemory(
  _In_  HANDLE  hProcess,               // -1 = pseudo-handle to current process
  _In_  LPVOID  lpBaseAddress,          // an ALREADY-EXECUTABLE dest (e.g. .text)
  _In_  LPCVOID lpBuffer,               // source: your shellcode (on the stack)
  _In_  SIZE_T  nSize,                  // bytes to copy
  _Out_ SIZE_T  *lpNumberOfBytesWritten // writable scratch ptr (like OldProtect)
);
```

### The core idea (Spencer Pratt, 2010)
You never change any page's protection. Instead you **hot-patch existing executable memory** — copy your shellcode over a chunk of the process's own `.text` (code you don't need, e.g. a rarely-hit function), then redirect execution there. WPM internally calls `NtProtectVirtualMemory`, so the OS makes the destination temporarily writable *for you*, honouring DEP the whole time. You are obeying DEP, not defeating it.

### Why/when it shines
- **DEP-agnostic:** works even where flipping stack pages is awkward, because the destination is *already* executable.
- Great when the shellcode is small enough to fit in an unused code cave in a non-ASLR module.

### The costs (why it's not the default)
- **`hProcess = -1`** — that's `0xFFFFFFFF`, conveniently null-free (a small mercy).
- **`lpBaseAddress`** must be a real, stable, executable, expendable address — you need a code cave in a non-ASLR module, which is extra recon.
- **`lpBuffer`** is your shellcode's current (stack) address — same runtime-resolution problem as before.
- **`lpNumberOfBytesWritten`** is another `_Out_` writable pointer (same trap as VirtualProtect's 4th arg).
- After the copy, you must **jump to `lpBaseAddress`** yourself — the call doesn't transfer control to it like the VirtualAlloc "return address" trick does.

> **Signal vs. Noise.** *Signal:* reach for WPM when protection-flipping is blocked or when a clean code cave exists in a non-ASLR module. *Noise:* choosing WPM by default — it has more moving parts (destination cave, manual jump, two runtime pointers) than VirtualAlloc/VirtualProtect. Learn it, keep it in reserve.

---

## 3. Side-by-side decision table

| | VirtualAlloc | VirtualProtect | WriteProcessMemory |
|---|---|---|---|
| Mechanism | commit-on-committed flips prot | flips prot in place | copies into already-exec mem |
| Fights DEP? | no (uses OS API) | no | no (fully within rules) |
| # args to fake | 4 | 4 | 5 |
| `_Out_` writable ptr gotcha | none | yes (`lpflOldProtect`) | yes (`lpNumberOfBytesWritten`) |
| Extra recon | none | none | executable code cave |
| Control transfer to shellcode | via faked return addr | via faked return addr | manual jump after call |
| Default pick? | ✔ if imported | ✔ if imported | reserve |

**Selection heuristic:** open the module's Imports (IDA) or dump the IAT; use whichever protection API is present. Only go to WPM when neither protection API is usable or a code-cave approach is cleaner.

---

## 4. The catch that motivates ASLR

Every chain above hardcodes gadget and IAT addresses from a **non-ASLR** module (`CSFTPAV6.dll`, base fixed at `0x50500000`). That is the load-bearing assumption. **ASLR (Address Space Layout Randomization)** breaks it by randomising module base addresses each boot/load, so:

- Hardcoded gadget addresses point at garbage → immediate crash.
- The IAT slot offset is still valid *relative to the module base*, but you no longer know the base.

DEP + ASLR together are the real modern baseline, and defeating them jointly is the goal of the later modules. Preview of the standard approaches:

### 4.1 Find a non-ASLR module (the cheapest win)
Exactly what Module 10 already relied on. If *any* loaded module lacks ASLR (`!nmod` won't flag `*ASLR`), source **all** gadgets and IAT references from it and ASLR is effectively sidestepped. Real targets frequently ship one poorly-linked DLL. **Always check this first** — it turns a hard problem back into the Module 10 problem.

### 4.2 Information leak → compute base at runtime
When everything is ASLR'd, you need a **memory-disclosure primitive**: leak one pointer into a known module (a return address, a vtable ptr, a leaked IAT entry), subtract its known static offset to recover the module base, then compute every gadget/IAT address as `base + offset` on the fly. This is where format-string bugs and OOB-read primitives become the linchpin of the whole exploit.

### 4.3 Partial overwrite / low-entropy corners
- **Partial EIP overwrite:** ASLR randomises high bytes but the low 12 bits (page offset) are fixed; overwriting only the low 2 bytes can redirect within the same module without knowing its base. Fragile, situational.
- **Non-randomised regions:** some allocations or legacy structures historically sat at predictable addresses. Increasingly rare; don't rely on it on modern Windows.

### 4.4 Brute force (32-bit only, and only sometimes)
32-bit ASLR entropy is low (often ~8 bits of module base randomness). For a service that **auto-restarts** on crash, repeated attempts can land. Useless on 64-bit (entropy too high) and noisy — a detection magnet.

> **Signal vs. Noise.** *Signal:* the first question against DEP+ASLR is always "is there a non-ASLR module I can pin to?" — check `!nmod` before designing an info leak. If not, your exploit's centre of gravity shifts to acquiring a **leak primitive**; the ROP part is unchanged once you can compute `base+offset`. *Noise:* betting on partial-overwrite or brute force on 64-bit modern targets — corner cases, not a plan. Don't build an info-leak pipeline before confirming you actually need one.

---

## 5. Combined-mitigation checklist (DEP + ASLR)
1. `!nmod` — enumerate DEP **and** ASLR per module.
2. **Any non-ASLR module?** → source all gadgets + IAT from it; proceed exactly as Module 10. Done.
3. **Fully ASLR'd?** → identify/obtain a **leak primitive** (format string, OOB read, uninitialised ptr).
4. Leak a pointer into a known module → recover base → derive gadget/IAT addresses as `base + static_offset`.
5. Build the *same* VirtualAlloc/VirtualProtect ROP chain, now with runtime-computed addresses.
6. Watch bad chars in the *computed* addresses too — a leak doesn't exempt you from `sscanf`/parser constraints.

---

*Scope note: defensive exploit-development coursework in a controlled lab. Techniques generalise; specific addresses and module names do not.*
