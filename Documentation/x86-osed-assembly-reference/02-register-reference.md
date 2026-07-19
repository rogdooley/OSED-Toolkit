# 2. Register Reference

## General-Purpose Registers

### EAX -- Accumulator

Return value for functions (all x86 calling conventions). Implicit destination
for `mul`, `imul` (one-operand form), `div`, `idiv`, `cdq`, `cwde`, `lodsb/d`,
`xlat`. Commonly used as a scratch register by compilers.

### EBX -- Base

No implicit use in most instructions (except `xlat`, which reads `[EBX+AL]`).
Callee-saved in all Windows calling conventions. Often used to hold a base
address (module base, structure pointer) across function calls.

### ECX -- Counter

Implicit count for `loop`, `rep` prefix, `shl`/`shr`/`rol`/`ror` (CL form).
First integer argument in `__fastcall`. `this` pointer in `__thiscall`.
Caller-saved.

### EDX -- Data

High 32 bits of the 64-bit result from `mul`/`imul` (one-operand). High 32
bits of the 64-bit dividend for `div`/`idiv`. Receives sign extension from
`cdq` (EAX sign-extended into EDX:EAX). Second argument in `__fastcall`.
Caller-saved.

### ESI -- Source Index

Source pointer for string instructions (`movsb/d`, `lodsb/d`, `cmpsb/d`).
Callee-saved. Auto-incremented or decremented after string ops depending on DF.

### EDI -- Destination Index

Destination pointer for string instructions (`movsb/d`, `stosb/d`, `cmpsb/d`,
`scasb/d`). Callee-saved. Auto-incremented or decremented after string ops
depending on DF.

### ESP -- Stack Pointer

Points to the top of the stack (the most recently pushed value). Modified
implicitly by `push`, `pop`, `call`, `ret`, `enter`, `leave`, `pushad`,
`popad`, `int`. Manipulated explicitly by `sub esp, N` / `add esp, N` for
frame allocation and cleanup.

### EBP -- Frame Pointer (by convention)

In framed functions, holds a snapshot of ESP taken during the prologue.
Arguments are at positive offsets from EBP; locals at negative offsets. Not all
functions use EBP as a frame pointer -- optimized code with frame-pointer
omission (FPO) uses EBP as a general register and references locals via
ESP-relative offsets.

### EIP -- Instruction Pointer

Cannot be read or written directly by `mov`. Changed by `call`, `ret`, `jmp`,
`jcc`, `int`, and exceptions. When you "overwrite EIP" in an exploit, you
overwrite the saved return address on the stack; `ret` then loads that value
into EIP.

### EFLAGS

Status flags set by arithmetic and comparison instructions, read by conditional
jumps and `setcc`/`cmovcc`. See Section 5 for details.

## Segment Registers

| Register | OSED relevance |
|----------|----------------|
| CS | Code segment; defines current privilege level (ring 3 in user mode) |
| DS | Default data segment; implicit for most memory references |
| SS | Stack segment; implicit for ESP/EBP-based references |
| ES | Extra segment; implicit destination for string ops (EDI) |
| FS | Points to the Thread Environment Block (TEB); `FS:[0x30]` = PEB pointer |
| GS | Unused in 32-bit Windows user mode (used in x64 for TEB) |

FS is the most operationally important segment register for OSED. The TEB
(Thread Environment Block) is located at the base address of the FS segment.
`FS:[0x00]` is the head of the SEH chain. `FS:[0x30]` is the pointer to the
PEB (Process Environment Block).

## Implicit Register Usage Summary

| Instruction | Implicit registers |
|-------------|-------------------|
| `mul reg` | EDX:EAX = EAX * reg |
| `imul reg` | EDX:EAX = EAX * reg (signed) |
| `div reg` | EAX = EDX:EAX / reg, EDX = remainder |
| `idiv reg` | EAX = EDX:EAX / reg (signed), EDX = remainder |
| `cdq` | EDX = sign-extend(EAX) |
| `loop label` | ECX = ECX - 1; jump if ECX != 0 |
| `rep movsb` | Copy ECX bytes from [ESI] to [EDI] |
| `rep stosd` | Fill ECX dwords at [EDI] with EAX |
| `lodsb` | AL = [ESI]; ESI += 1 |
| `scasb` | Compare AL with [EDI]; EDI += 1 |
| `call target` | push EIP_next; EIP = target |
| `ret` | EIP = [ESP]; ESP += 4 |
| `xlat` | AL = [EBX + AL] |
