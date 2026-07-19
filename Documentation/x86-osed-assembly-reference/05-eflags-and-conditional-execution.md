# 5. EFLAGS and Conditional Execution

## Flags Relevant to Reverse Engineering

| Flag | Bit | Set when |
|------|-----|----------|
| ZF (Zero) | 6 | Result is zero |
| CF (Carry) | 0 | Unsigned overflow/borrow |
| SF (Sign) | 7 | Result has MSB set (negative in signed interpretation) |
| OF (Overflow) | 11 | Signed overflow |
| PF (Parity) | 2 | Low byte of result has even number of 1-bits |
| DF (Direction) | 10 | String ops decrement (DF=1) or increment (DF=0) ESI/EDI |

## CMP and TEST

`cmp a, b` computes `a - b`, sets flags, discards the result.

`test a, b` computes `a AND b`, sets flags, discards the result. CF and OF are
always cleared by `test`.

Common patterns:

```asm
cmp eax, 0        ; is EAX zero? (ZF=1 if yes)
test eax, eax     ; same check, shorter encoding, preferred by compilers
test al, al       ; same for 8-bit
cmp eax, ebx      ; compare two registers
```

## Signed vs. Unsigned Conditional Jumps

The same flag state has different meanings depending on whether the comparison
is signed or unsigned. The jump mnemonic tells you which interpretation applies:

### Unsigned Comparisons (use CF and ZF)

| Mnemonic | Condition | Flags |
|----------|-----------|-------|
| `JA` / `JNBE` | above (unsigned >) | CF=0 and ZF=0 |
| `JAE` / `JNB` / `JNC` | above or equal | CF=0 |
| `JB` / `JNAE` / `JC` | below (unsigned <) | CF=1 |
| `JBE` / `JNA` | below or equal | CF=1 or ZF=1 |

### Signed Comparisons (use SF, OF, and ZF)

| Mnemonic | Condition | Flags |
|----------|-----------|-------|
| `JG` / `JNLE` | greater (signed >) | ZF=0 and SF=OF |
| `JGE` / `JNL` | greater or equal | SF=OF |
| `JL` / `JNGE` | less (signed <) | SF!=OF |
| `JLE` / `JNG` | less or equal | ZF=1 or SF!=OF |

### Equality (same for signed and unsigned)

| Mnemonic | Condition | Flags |
|----------|-----------|-------|
| `JE` / `JZ` | equal / zero | ZF=1 |
| `JNE` / `JNZ` | not equal / not zero | ZF=0 |

### Other

| Mnemonic | Condition | Flags |
|----------|-----------|-------|
| `JS` | sign (negative) | SF=1 |
| `JNS` | not sign (non-negative) | SF=0 |
| `JO` | overflow | OF=1 |
| `JNO` | no overflow | OF=0 |

## Why This Matters

After `cmp eax, 0x80`:

- `ja target` treats EAX as **unsigned**. If EAX = 0xFFFFFFFF, that is
  4294967295 unsigned, which is above 0x80, so the jump is taken.
- `jg target` treats EAX as **signed**. If EAX = 0xFFFFFFFF, that is -1
  signed, which is less than 0x80, so the jump is NOT taken.

The jump mnemonic leaks the programmer's intended signedness of the comparison.

## SETcc and CMOVcc

`SETcc` sets a byte register to 1 if the condition is true, 0 otherwise:

```asm
cmp eax, ebx
setg al          ; AL = 1 if EAX > EBX (signed), else 0
```

`CMOVcc` conditionally moves without branching:

```asm
cmp eax, ebx
cmovg ecx, edx   ; ECX = EDX if EAX > EBX (signed), else ECX unchanged
```

Both use the same condition codes as `Jcc`.
