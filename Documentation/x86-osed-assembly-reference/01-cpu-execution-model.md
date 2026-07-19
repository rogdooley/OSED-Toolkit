# 1. CPU Execution Model

## Registers, Memory, and Instructions

The x86 CPU operates on **registers** (fast named storage inside the CPU) and
**memory** (byte-addressable RAM). Instructions read state, transform it, and
write results back. The CPU fetches the next instruction from the address in
**EIP**, decodes it, executes it, then advances EIP to the next instruction
(unless the instruction itself changes EIP).

Key registers for OSED work:

| Register | Width | Role |
|----------|-------|------|
| EAX | 32 | Accumulator; return values; implicit operand for mul/div |
| EBX | 32 | General purpose; base register in some addressing |
| ECX | 32 | Counter for loops and string ops; arg1 in fastcall |
| EDX | 32 | Data; high half of mul/div results; arg2 in fastcall |
| ESI | 32 | Source index for string ops |
| EDI | 32 | Destination index for string ops |
| ESP | 32 | Stack pointer -- always points to the top of the stack |
| EBP | 32 | Frame pointer (by convention, not by hardware) |
| EIP | 32 | Instruction pointer -- address of the next instruction |
| EFLAGS | 32 | Status and control flags (ZF, CF, SF, OF, PF, DF, etc.) |

## Sub-Register Aliasing

Each 32-bit general-purpose register has 16-bit and 8-bit aliases that refer to
the same physical storage:

```
EAX (bits 31..0)
 AX (bits 15..0)
  AH (bits 15..8)   AL (bits 7..0)
```

Writing AL changes bits 7..0 of EAX without clearing bits 31..8. Writing AX
changes bits 15..0 without clearing bits 31..16. This matters when shellcode
uses `mov al, 0x30` to avoid null bytes -- the upper 24 bits of EAX retain
whatever value they held.

The same pattern applies to EBX/BX/BH/BL, ECX/CX/CH/CL, EDX/DX/DH/DL.
ESI, EDI, ESP, and EBP have 16-bit aliases (SI, DI, SP, BP) but no 8-bit
aliases on x86-32.

## Little-Endian Byte Order

x86 stores multi-byte values with the least significant byte at the lowest
address:

```
Value:   0x41424344
Address: 0x0012FF80

Memory layout:
0x0012FF80: 44   (LSB)
0x0012FF81: 43
0x0012FF82: 42
0x0012FF83: 41   (MSB)
```

## Value vs. Address vs. Contents

These are three different things:

```
EAX = 0x41424344
```

EAX holds the integer value `0x41424344`.

```
EAX = 0x0012FF80
[0x0012FF80] = 0x41424344
```

EAX holds the address `0x0012FF80`. The memory at that address contains
`0x41424344`. EAX is a pointer.

The bracket notation `[expr]` means "the value stored in memory at address
`expr`":

| Expression | Meaning |
|------------|---------|
| `EAX` | The value in register EAX |
| `[EAX]` | The DWORD in memory at the address held in EAX |
| `[EAX+4]` | The DWORD in memory at address EAX+4 |
| `DWORD PTR [EAX+4]` | Same, with explicit size qualifier |
