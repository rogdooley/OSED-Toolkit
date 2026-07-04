# Chapter 1 — The x86 Register Model

## 1. Objective

After this chapter you can name every general-purpose x86 register, explain what
role the ABI and the hardware assign to it, read the sub-register aliasing
(`EAX`/`AX`/`AL`/`AH`) correctly, and reason about EFLAGS well enough to predict
which way a conditional branch goes. You will stop treating registers as
interchangeable scratch space and start reading the *conventions* that make code
legible.

## 2. Background

x86 has very few general-purpose registers — eight, and a couple are effectively
reserved. Because registers are scarce, the compiler reuses them aggressively: the
same physical register holds a loop counter, then a pointer, then a return value,
all within a few instructions. There is no type on a register; `EAX` is just 32
bits. Meaning comes entirely from *what the code does with it*, which is why you
must track a register's role as it changes rather than assign it a fixed identity.

Two layers of "convention" govern register use, and you must keep them separate:

- **Hardware convention** — things the CPU itself enforces. `ESP` is *the* stack
  pointer: `push`, `pop`, `call`, and `ret` all read and write it implicitly. The
  string instructions (`movs`, `stos`, `scas`) implicitly use `ESI`, `EDI`, and
  `ECX`. You cannot opt out of these.
- **ABI convention** — things the compiler *chooses* consistently. In the Windows
  x86 ABI, `EAX` returns values, `ECX` is the `this` pointer under `__thiscall`,
  and `EBX/ESI/EDI/EBP` are callee-saved. The CPU doesn't care; the compiler is
  just self-consistent, and that consistency is what you read.

## 3. Mental model

Think of the eight GPRs in two tiers by *how strongly convention pins them*:

```
   Strongly role-bound (hardware + ABI)      Weakly bound (general scratch)
   ------------------------------------      -----------------------------
   ESP  the stack pointer (never a temp)     EAX  scratch + return value
   EBP  the frame pointer (by convention)    EBX  scratch (callee-saved)
   ESI  source ptr for string ops            ECX  scratch + counter + this
   EDI  dest ptr for string ops              EDX  scratch + high half of mul/div
```

`E` = "extended," the 32-bit form. Each of the original four (A/B/C/D) exposes its
low 16 bits and then the low two bytes:

```
   31            16 15      8 7       0
   +---------------+---------+---------+
   |               |   AH    |   AL    |   <- AL = low byte, AH = next byte
   +---------------+---------+---------+
   |               |        AX         |   <- AX = low 16 bits
   +---------------+-------------------+
   |                EAX                |   <- EAX = full 32 bits
   +-----------------------------------+
```

The alias is the *same storage*, so writing `AL` changes the low byte of `EAX`.
This is not cosmetic — it is a frequent source of subtle behavior:

- Writing `AL` leaves the upper 24 bits of `EAX` **unchanged** (classic partial
  register). So `mov al, [esi]` reads a byte but the top of `EAX` still holds
  whatever was there — which is why byte loops often do `movzx`/`xor eax,eax`
  first.
- `movzx eax, al` zero-extends (upper bits cleared); `movsx eax, al`
  sign-extends (upper bits = sign). The choice tells you whether the source C type
  was `unsigned char` or `signed char`. That is a *type recovery* signal, derived
  purely from the mnemonic.

### The role of each register, and how to read it

- **EAX** — the accumulator. Default target of arithmetic, and the **return
  value** register by ABI. If a `call` is followed by code that uses `EAX`, the
  callee returned something and you're seeing it consumed. 64-bit results
  (`mul`, `div`) put the high half in `EDX`.
- **ECX** — the counter. `rep`-prefixed string ops and `loop` decrement it
  implicitly. Under `__thiscall`, it's the object pointer. Seeing `ECX` loaded
  with a count right before `rep movs` is a strong signal you're looking at a
  block copy (Chapter 9).
- **EDX** — the "D" partner of EAX. Holds the high dword of a 64-bit product or
  the remainder of a division. Otherwise general scratch.
- **EBX** — general scratch, but **callee-saved**, so the compiler tends to park
  a value in it that must survive across calls (e.g., a base pointer used
  throughout a function).
- **ESI / EDI** — source/destination index. In string ops they're mandatory; in
  ordinary code the compiler favors them for pointers that live across a loop,
  precisely because they're callee-saved and survive calls.
- **EBP** — frame pointer by convention (Chapter 3). When frame pointers are
  omitted (`/Oy`, common at `-O2`), EBP becomes just another scratch register and
  this landmark disappears.
- **ESP** — the stack pointer. Never a general temp. Every `push`/`pop`/`call`/
  `ret` touches it.
- **EIP** — the instruction pointer. Not directly writable by `mov`; changed only
  by control-flow instructions (`jmp`, `call`, `ret`, conditional jumps).
  Redirecting EIP is, ultimately, the whole game in exploitation.

### EFLAGS — where branches actually come from

Comparisons don't "return" anything. `cmp a, b` computes `a - b`, throws the
result away, and keeps only the *flags* it set. The conditional jump that follows
reads those flags. The flags you care about:

- **ZF** (zero) — set if the result was zero (i.e., `a == b`).
- **SF** (sign) — set if the result's top bit is 1 (negative, in two's complement).
- **CF** (carry) — unsigned overflow/borrow. Drives *unsigned* comparisons.
- **OF** (overflow) — signed overflow. Drives *signed* comparisons together with SF.

The critical reading skill: **`ja`/`jb` are unsigned, `jg`/`jl` are signed.** The
compiler chose the signed or unsigned jump based on the C *type* of the operands.
So the jump mnemonic leaks type information you can't see any other way:

- `cmp eax, 10h` then `jb short loc_X` → `eax` was treated as **unsigned** (`<`
  as `unsigned`). Likely a `size_t`, a length, or an index.
- Same `cmp` then `jl short loc_X` → `eax` was **signed** (`int`).

## 4. Assembly examples

```asm
; Example A: return value flows out of EAX
    call    sub_401200          ; suppose this returns an int in EAX
    test    eax, eax            ; test eax,eax sets ZF iff eax == 0
    jz      short loc_401080    ; jump if EAX was zero  -> "if (r == 0)"
    mov     [ebp-4], eax        ; else store the nonzero return into a local
```

`test eax, eax` is `and eax, eax` without storing — it sets ZF/SF from `eax`
itself. `test reg,reg` / `jz` is the idiomatic "is it zero / is it NULL" check.
Reading it as such is derivation, not pattern-matching: AND of a value with itself
is the value, so ZF reflects whether the value is zero.

```asm
; Example B: byte load and the partial-register trap
    xor     eax, eax            ; EAX = 0  (clears the WHOLE register)
    mov     al, [esi]           ; load one byte; upper 24 bits stay 0 because of the xor
    cmp     eax, 41h            ; now a clean unsigned/zero-extended compare against 'A'
```

Without the `xor eax, eax`, the `cmp` would include stale high bytes and the
comparison would be wrong. The compiler emitted the `xor` *because* it needed a
clean zero-extended byte — evidence the C source read a `char`/`unsigned char`
and promoted it to `int`.

```asm
; Example C: signedness leaks through the jump
    cmp     [ebp+len], 100h
    jbe     short loc_ok        ; jbe = unsigned <=  ->  len is unsigned (size_t)
    ; ... error path ...
loc_ok:
```

## 5. Equivalent C

```c
// Example A
int r = sub_401200();
if (r != 0) {
    local = r;
}

// Example B
unsigned char c = *esi_ptr;   // xor+mov al + later compare-as-int
if (c == 'A') { ... }

// Example C
size_t len = ...;             // jbe => unsigned comparison
if (len <= 0x100) { /* ok */ }
```

## 6. Reverse engineering methodology

To read a register correctly, track its *role over its live range*, not its name:

1. **Find where the value is born** — the instruction that first writes it
   (`mov`, `lea`, a `call` returning into `EAX`, a load from memory).
2. **Follow it forward** until it is overwritten. Between those points it holds
   one logical value; annotate it (IDA: `n` to rename, even a register-holding
   local).
3. **Classify by use, not by identity.** Is it dereferenced (`[reg]`)? It's a
   pointer. Is it decremented and used by `rep`/`loop`? It's a counter. Is it the
   thing returned or moved into `EAX` before `ret`? It's the result.
4. **Read signedness from the jumps**, not from the data. The mnemonic
   (`jb`/`ja` vs `jl`/`jg`) tells you the C type.
5. **Watch for partial-register writes** (`al`, `ax`); they change type semantics
   and often pair with `movzx`/`movsx` that reveal `unsigned`/`signed`.

## 7. Common compiler idioms

- `xor reg, reg` — set a register to 0. Shorter and faster than `mov reg, 0`, and
  it breaks the dependency chain. **This is zeroing, not XOR-as-logic.**
- `test reg, reg` + `jz`/`jnz` — "is it zero / NULL?" without a `cmp #0`.
- `movzx` / `movsx` — widen a byte/word to a dword; reveals source signedness.
- `lea` used for arithmetic (Chapter 2) — not a memory access at all.
- `mov edi, edi` at a function's very first instruction — hot-patch padding on
  system DLLs, not logic. Skip it.

## 8. Common mistakes

- **Assuming `EAX` after a `call` is meaningful when the callee is `void`.** Not
  every function sets a return value; if the following code ignores `EAX`, don't
  invent one.
- **Ignoring partial-register writes.** `mov al, ...` does not clear the upper
  bytes. Reading it as a full 32-bit assignment gives wrong values.
- **Reading `xor eax, eax` as an XOR operation.** It's a zero. Reserve the
  "encryption/obfuscation" reading for `xor reg, otherreg` or `xor reg, imm` with
  distinct operands.
- **Guessing signedness from the data instead of the jump.** The bytes `0xFFFFFFFF`
  are `-1` or `4294967295` depending only on the instruction that interprets them.
  The jump tells you which.

## 9. Exercises

1. `mov al, 0xFF` executes with `EAX = 0x11223344` beforehand. What is `EAX`
   after? Now instead `movzx eax, byte ptr [x]` where `[x] = 0xFF`. What is `EAX`?
   And `movsx`? Explain each from the definition of the mnemonic.
2. You see `cmp eax, ebx` / `jg loc_X`. What C type were `eax` and `ebx`? What if
   it were `ja` instead?
3. A function ends with `xor eax, eax` / `pop ebp` / `ret`. What does it return,
   and what's the likely C return type?
4. Explain why `test eax, eax` / `jz` is preferred over `cmp eax, 0` / `je`, even
   though both work.

## 10. Summary

- Eight GPRs, few of them, heavily reused; meaning comes from *use over time*, not
  from the register's identity.
- Some roles are hardware-forced (ESP, string-op ESI/EDI/ECX), others are ABI
  conventions the compiler follows consistently (EAX = return value, callee-saved
  set).
- Sub-registers alias the same storage; partial writes (`al`/`ax`) don't clear the
  top, and `movzx`/`movsx` reveal source signedness.
- Comparisons set EFLAGS; the *conditional jump* is where the decision lives, and
  its signed/unsigned flavor leaks the C type of the operands.
- Track each value from birth to overwrite and classify it by what the code does
  to it.
