# Appendix C — Worked Solutions

Read these *after* attempting the challenges in `WALKTHROUGH.md`. Where a
solution needs concrete gadget addresses, it stays symbolic (matching Appendix
A) because those come from your build — the reasoning is the transferable part.

All 32-bit arithmetic below is verified: a value is "null-free" iff none of its
four bytes is `0x00` (and, for values that travel through the `%s` sink, none is
in the bad-char set `00 09 0a 0b 0c 0d 20`).

---

## Challenge 1 — Build `0x1000` with no null bytes

`MEM_COMMIT = 0x00001000`. As a literal it has three `0x00` bytes, so it cannot
be popped directly. Three independent constructions:

### Method A — split-add (recommended)

Find two null-free values that sum to `0x1000` with 32-bit wraparound:

```
0x80808080 + 0x7F7F8F80 = 0x1_00001000  →  low dword 0x00001000
         both operands are null-free (every byte 0x7F–0x80)
```

```python
G_POP_EAX ; 0x80808080
G_POP_ECX ; 0x7F7F8F80
G_ADD_EAX_ECX          ; eax = 0x1000
```

Cost: 3 gadgets. This is the method used in Chapter 12. It generalises: to build
any constant `K`, pick a null-free `A` and use `B = (K - A) & 0xFFFFFFFF`, then
check `B` is null-free. E.g. `A=0x11223344 → B=0xEEDDDCBC`, both clean, sum
`0x1000`. If `B` has a bad byte, nudge `A` and retry.

### Method B — `neg` of the two's complement (REJECTED here — instructive)

The `neg` trick worked beautifully for `0x201` and `0x40`. Try it for `0x1000`:

```
-0x1000 = 0xFFFFF000
```

`0xFFFFF000` contains two `0x00` bytes. You cannot pop it. **`neg` only helps
when the two's complement is itself null-free** — true for small values like
`0x40` (`0xFFFFFFC0`) and `0x201` (`0xFFFFFDFF`), false for `0x1000`. Knowing
*when* a trick fails is the lesson; don't reach for `neg` reflexively.

### Method C — shift a small value

`0x1000 = 1 << 12`. If your module yields a shift gadget:

```
G_POP_EAX ; 0x00000001    ← still has nulls; use a null-free carrier instead
```

The naive `pop 1` reintroduces nulls, so build the `1` first (e.g. `xor eax,eax
; inc eax`) then `shl eax, 0x0C`:

```
G_XOR_EAX_EAX          ; eax = 0
G_INC_EAX              ; eax = 1
G_SHL_EAX_0C           ; eax = 0x1000   (shl eax, 0Ch ; ret)
```

Cost: 3 gadgets, but depends on a `shl`-by-imm gadget existing, which is less
common than `add`. Prefer Method A unless a shift gadget is right there.

> **Takeaway.** Constants are a search problem, not a lookup. Enumerate: can I
> `neg` it (is the complement clean)? Can I split it into two clean addends? Can
> I shift/build it? Pick the shortest that uses gadgets you actually have.

---

## Challenge 2 — An alternative stack-copy for P0

Goal: get ESP into a working register (ESI) ending in a clean `ret`. The
walkthrough used `push esp ; push eax ; pop edi ; pop esi ; ret`. Alternatives
to hunt for, in rough order of preference:

```
findstr /C:": mov esi, esp ; " rop.txt
findstr /C:"push esp ; pop"    rop.txt
findstr /C:": mov eax, esp ; " rop.txt
```

Candidate families and how to judge them:

```
A)  mov esi, esp ; pop ebp ; ret          ✓ cleanest; ESI=ESP, only dirties EBP (throwaway here)
B)  push esp ; pop esi ; ret               ✓ two-instruction, ideal if present
C)  mov eax, esp ; ... ; ret               ✓ then move EAX→ESI later (extra gadget)
D)  lea esi, [esp+X] ; ret                 ✓ usable — just fold the +X into your offset math
E)  push esp ; pop esi ; leave ; ret       ✗ REJECT: LEAVE overwrites ESP/EBP after the copy
F)  mov esi, esp ; jmp eax                  ✗ REJECT: jmp leaves the chain
G)  xchg esi, esp ; ret                     ✗ DANGEROUS: this *replaces* ESP with old ESI —
                                              you lose the chain pointer. Only usable if you
                                              immediately restore ESP; almost never worth it.
```

Rejection rule, restated: the gadget must (1) leave a copy of ESP in a register
you can mangle, (2) **not** destroy ESP itself, and (3) end in a controlled
`ret`. `lea esi,[esp+X]` (D) is a hidden gem — the constant offset just changes
the `-0x1C` you use in P2. Whatever you pick, verify:

```
bp <gadget> ; g ; (single-step to ret) ; r esi     → ESI == entry ESP
dds esi L2                                          → shows your controllable filler
```

---

## Challenge 3 — Retarget the chain to VirtualAlloc

`VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)` — 4 args, **no
`_Out_` pointer**, so primitive **P7 disappears** entirely. Diff vs. the
VirtualProtect chain:

| Frame slot | VirtualProtect | VirtualAlloc |
|---|---|---|
| 0 | `&VirtualProtect` | `&VirtualAlloc` (resolve `IAT_VIRTUALALLOC`) |
| 1 | return addr (shellcode) | return addr (shellcode) — unchanged |
| 2 | `lpAddress` (shellcode) | `lpAddress` (shellcode) — unchanged |
| 3 | `dwSize` `0x201` | `dwSize` `0x201` — unchanged |
| 4 | `flNewProtect` `0x40` | `flAllocationType` `MEM_COMMIT` `0x1000` (split-add, Ch.1) |
| 5 | `lpflOldProtect` (writable) | `flProtect` `0x40` (split-add) |

So: swap the IAT slot (P1), change P6 to build `0x1000`, and replace P7's
"writable scratch pointer" with a sixth store of `0x40`. The pivot (P8) is
identical — VirtualAlloc is also stdcall/4-args (`ret 0x10`).

Why it still bypasses DEP: calling `VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READWRITE)`
on a page that is *already committed* (your stack) just re-protects it — same net
effect as VirtualProtect. `!vprot` shows `PAGE_READWRITE → PAGE_EXECUTE_READWRITE`
exactly as before.

A runnable variant is in `solutions/exploit_virtualalloc.py` (same structure as
`exploit/exploit.py`, with the frame and P5–P7 adjusted). Fill the same gadget
table plus `IAT_VIRTUALALLOC`.

> **The point of doing both.** ~90% of the chain is byte-identical. That is the
> abstraction from Chapter 12: the workflow (resolve import → patch placeholders
> → pivot → return) is the skill; the API is a swappable detail. DEP only
> observes `RW → api → RWX → ret → execute`.

---

## Challenge 4 — WriteProcessMemory: find a code cave

WPM needs an already-executable destination (`lpBaseAddress`) big enough for your
shellcode, at a stable address. Method to find one in `compression.dll`:

1. **Locate the executable range.** `!vprot` across the module, or read the
   section headers: `dumpbin /headers compression.dll | findstr /i ".text"`
   gives the `.text` RVA + virtual size. Add the (non-ASLR) image base
   `0x61500000` to get the executable address window.

2. **Scan for filler between functions.** The linker pads inter-function gaps
   with `0xCC` (int3) or `0x90` (nop). In WinDbg:

   ```
   s -b 61500000 6155ffff cc cc cc cc cc cc cc cc cc cc cc cc   ; runs of int3
   ```

   A run of ≥ your shellcode length (staged calc ≈ 200+ bytes) is a candidate.
   Alternatively look at the tail padding of `.text` before the next section
   boundary — often a sizeable zero/`int3` gap.

3. **Confirm it is executable and stable.**

   ```
   !vprot <cave>            → Protect: PAGE_EXECUTE_READ (or _WRITECOPY)
   ```

   Restart the service and re-check the address — because `compression.dll` is
   `/DYNAMICBASE:NO`, the cave address must be identical across restarts. That
   stability is exactly why you use a *non-ASLR* module for the cave, just like
   for gadgets.

4. **Wire the WPM frame.** `hProcess = 0xFFFFFFFF` (null-free), `lpBaseAddress =
   cave`, `lpBuffer = shellcode-on-stack` (resolve like lpAddress), `nSize =
   len` (build null-free), `lpNumberOfBytesWritten = writable scratch` (like
   VP's OldProtect). After WPM returns, you need **one more gadget** to transfer
   control into the cave — e.g. a `push <cave> ; ret`, or set a register to the
   cave and `jmp`/`ret` into it. WPM does not jump there for you.

> **Why this is the "advanced" chapter.** You added recon (cave hunting), one
> more `_Out_` pointer, and a manual control transfer — three extra moving parts
> versus VP/VA. But you never changed a page's permissions. DEP is a
> *page-permission* mitigation; put your bytes where execution is already legal
> and there is nothing to bypass.

---

## Challenge 5 — Turn ASLR on and watch it break

Rebuild only the gadget source with ASLR enabled:

```
cl /nologo /O2 /MT /GS- /TC /I..\src\compression ..\src\compression\compression.c ^
   /link /DLL /DYNAMICBASE /NXCOMPAT /BASE:0x61500000 ^
   /OUT:compression.dll /IMPLIB:compression.lib
```

Run the existing `exploit.py` unchanged and debug the crash.

**What fails first, and why.** The very first ROP dword — the EIP overwrite
itself — is `G_STACKPTR`, a hardcoded `0x615xxxxx` address. With ASLR on,
`compression.dll` no longer loads at `0x61500000`; say it lands at `0x009A0000`.
Your `G_STACKPTR` value now points into unmapped or unrelated memory. So the
sequence is:

```
parse_config_set returns → pops your G_STACKPTR value into EIP
    → EIP = 0x6150XXXX, but nothing valid is mapped there now
    → immediate access violation on the FIRST gadget fetch
```

You never even reach P1. Confirm in WinDbg: at the fault, `eip` equals your
hardcoded `G_STACKPTR` constant, and `lm m compression` shows the module at a
*different* base than `0x61500000`. Every subsequent gadget and the
`IAT_VIRTUALPROTECT` slot are equally stale — but the first one is where it dies.

**The fix requires a base-discovery stage** (Chapter 14): either pin to a
still-non-ASLR module, or leak one pointer into `compression.dll`, recover its
base (`leaked_ptr - known_static_offset`), and compute every gadget/IAT address
as `base + offset` at runtime. The chain body is unchanged once you can do that
arithmetic live — ASLR adds a stage *in front of* the ROP you already know how to
build, it doesn't invalidate it.

---

## Solution files in this directory

- `SOLUTIONS.md` — this file.
- `exploit_virtualalloc.py` — Challenge 3, the VirtualAlloc variant, runnable
  once you fill the gadget table.
