# 6. Core Instruction Reference

## Data Movement

### MOV -- Move

```asm
mov dst, src        ; dst = src
```

Copies src to dst. Does not affect flags. The most common instruction. Cannot
move memory to memory -- at least one operand must be a register.

### MOVZX -- Move with Zero-Extend

```asm
movzx eax, bl       ; EAX = zero-extend(BL)  -- upper 24 bits cleared
movzx eax, WORD PTR [esi]  ; EAX = zero-extend(16-bit value at [ESI])
```

Loads a smaller value into a larger register, filling upper bits with zero.
Indicates unsigned interpretation.

### MOVSX -- Move with Sign-Extend

```asm
movsx eax, bl       ; EAX = sign-extend(BL)
movsx eax, WORD PTR [esi]  ; EAX = sign-extend(16-bit value at [ESI])
```

Fills upper bits with the sign bit of the source. Indicates signed
interpretation. If BL = 0xFF, then EAX = 0xFFFFFFFF (-1).

### XCHG -- Exchange

```asm
xchg eax, ecx       ; swap EAX and ECX
```

Atomic swap. Common as a ROP gadget (`xchg eax, esp; ret` = stack pivot). Does
not affect flags.

### LEA -- Load Effective Address

```asm
lea eax, [ebp-0x40]     ; EAX = EBP - 0x40  (compute address, no memory read)
lea eax, [ecx+ecx*2]    ; EAX = ECX * 3
```

Computes the address expression and stores the result. Does NOT read memory.
Does NOT affect flags. Compilers use it for multi-operand arithmetic.

### PUSH -- Push onto Stack

```asm
push eax             ; ESP -= 4; [ESP] = EAX
push 0x41414141      ; ESP -= 4; [ESP] = 0x41414141
push DWORD PTR [eax] ; ESP -= 4; [ESP] = [EAX]
```

Decrements ESP by the operand size (4 on x86-32), then writes the operand to
[ESP]. Does not affect flags.

### POP -- Pop from Stack

```asm
pop eax              ; EAX = [ESP]; ESP += 4
```

Reads [ESP] into the destination, then increments ESP by 4. Does not affect
flags.

### PUSHAD -- Push All General Registers

```asm
pushad               ; pushes EAX, ECX, EDX, EBX, original-ESP, EBP, ESI, EDI
```

Pushes all 8 GPRs in the order listed above (EAX first, EDI last). ESP
decreases by 32 (8 * 4). The "original ESP" pushed is the value ESP had before
PUSHAD began.

After PUSHAD, the stack looks like (top = lowest address):

```
[ESP+0x00] = EDI    (pushed last = on top)
[ESP+0x04] = ESI
[ESP+0x08] = EBP
[ESP+0x0C] = original ESP
[ESP+0x10] = EBX
[ESP+0x14] = EDX
[ESP+0x18] = ECX
[ESP+0x1C] = EAX    (pushed first = deepest)
```

The CPU pushes in EAX-first order, but because the stack grows downward, the
result in memory has EDI at the top. This distinction matters when using PUSHAD
in ROP chains.

### POPAD -- Pop All General Registers

```asm
popad                ; pops EDI, ESI, EBP, (skip ESP), EBX, EDX, ECX, EAX
```

Reverse of PUSHAD. ESP increases by 32. The saved ESP value is discarded (not
loaded into ESP).

### PUSHFD / POPFD -- Push/Pop EFLAGS

```asm
pushfd               ; ESP -= 4; [ESP] = EFLAGS
popfd                ; EFLAGS = [ESP]; ESP += 4
```

## Arithmetic

### ADD

```asm
add eax, 4           ; EAX = EAX + 4
add eax, ecx         ; EAX = EAX + ECX
```

Sets OF, SF, ZF, AF, CF, PF.

### SUB

```asm
sub esp, 0x40         ; ESP = ESP - 0x40 (allocate 64 bytes of stack space)
sub eax, ecx          ; EAX = EAX - ECX
```

Sets OF, SF, ZF, AF, CF, PF.

### INC / DEC

```asm
inc eax               ; EAX = EAX + 1
dec ecx               ; ECX = ECX - 1
```

Set OF, SF, ZF, AF, PF. Do NOT modify CF. This matters: `inc` followed by
`jc` tests a carry from a *previous* instruction, not from the increment.

### NEG -- Two's Complement Negate

```asm
neg eax               ; EAX = 0 - EAX  (= ~EAX + 1)
```

Sets CF=1 unless operand was 0. Useful for converting between positive and
negative values without null bytes: `mov eax, 0x1C` encodes nulls
(`B8 1C 00 00 00`), but `mov eax, 0xFFFFFFE4` followed by `neg eax` does not.

### MUL -- Unsigned Multiply

```asm
mul ecx               ; EDX:EAX = EAX * ECX (unsigned)
```

One-operand form only. Result is always 64 bits in EDX:EAX. Sets CF and OF if
the high half (EDX) is non-zero. ZF, SF, PF are undefined.

### IMUL -- Signed Multiply

```asm
imul ecx              ; EDX:EAX = EAX * ECX (signed, one-operand)
imul eax, ecx         ; EAX = EAX * ECX (signed, two-operand)
imul eax, ecx, 12     ; EAX = ECX * 12 (signed, three-operand)
```

Two-operand and three-operand forms store only the low 32 bits. CF and OF set
if the result was truncated.

### DIV -- Unsigned Divide

```asm
div ecx               ; EAX = EDX:EAX / ECX, EDX = EDX:EAX % ECX
```

Before `div`, EDX must be set up. For 32-bit dividends, `xor edx, edx`
(unsigned) or `cdq` (signed, but use `idiv`). Division by zero or quotient
overflow raises `#DE` (divide error exception).

### IDIV -- Signed Divide

```asm
cdq                   ; sign-extend EAX into EDX:EAX
idiv ecx              ; EAX = EDX:EAX / ECX (signed), EDX = remainder
```

### ADC -- Add with Carry

```asm
adc eax, 0            ; EAX = EAX + 0 + CF
```

Adds source + CF to destination. Used for multi-precision arithmetic.

### SBB -- Subtract with Borrow

```asm
sbb eax, eax          ; EAX = EAX - EAX - CF = 0 - CF = -CF
```

The `sbb eax, eax` idiom produces 0 (CF=0) or -1 (CF=1). Occasionally seen
in branchless code.

## Logic and Bit Manipulation

### AND

```asm
and eax, 0x0F         ; EAX = EAX & 0x0F  (mask low nibble)
and esp, 0xFFFFFFF0   ; align ESP to 16-byte boundary
```

Clears CF and OF. Sets SF, ZF, PF.

### OR

```asm
or eax, ecx           ; EAX = EAX | ECX
```

Clears CF and OF. `or eax, eax` sets ZF if EAX is zero (same as `test eax, eax`
but also writes to EAX).

### XOR

```asm
xor eax, eax          ; EAX = 0  (smallest encoding for zeroing a register)
xor eax, ecx          ; EAX = EAX ^ ECX
```

Clears CF and OF. `xor eax, eax` is the standard null-free way to zero a
register.

### NOT -- Bitwise Complement

```asm
not eax               ; EAX = ~EAX  (flip all bits)
```

Does NOT affect any flags.

### TEST

```asm
test eax, eax         ; compute EAX & EAX, set flags, discard result
test al, 0x01         ; check if bit 0 is set
```

Like AND but does not store the result. Clears CF and OF. Sets SF, ZF, PF.
Preferred over `cmp eax, 0` for zero checks because it has a shorter encoding.

### SHL / SAL -- Shift Left

```asm
shl eax, 1            ; EAX = EAX << 1  (multiply by 2)
shl eax, cl           ; EAX = EAX << CL
```

SHL and SAL are identical (both shift left, filling with zeros). CF receives
the last bit shifted out. OF set on single-bit shifts if the sign bit changed.

### SHR -- Shift Right (Logical)

```asm
shr eax, 4            ; EAX = EAX >> 4  (unsigned divide by 16)
```

Fills vacated high bits with zero. Unsigned shift.

### SAR -- Shift Right (Arithmetic)

```asm
sar eax, 1            ; signed divide by 2 (preserves sign bit)
```

Fills vacated high bits with the original sign bit. Signed shift.

### ROL / ROR -- Rotate Left / Right

```asm
ror eax, 0x0D         ; rotate EAX right by 13 bits
```

Circular rotation. Common in API hash algorithms (rotate-right-13-add is a
widely used hash).

### RCL / RCR -- Rotate Through Carry

```asm
rcl eax, 1            ; rotate left through CF (33-bit rotation)
```

Rarely seen outside crypto or multi-precision code.

### BSWAP -- Byte Swap

```asm
bswap eax             ; reverse byte order of EAX
```

Converts between big-endian and little-endian. If EAX = 0x41424344, after
BSWAP EAX = 0x44434241. Does not affect flags.

## Control Flow

### CALL -- Call Procedure

```asm
call 0x00401000       ; push EIP_next; EIP = 0x00401000
call eax              ; push EIP_next; EIP = EAX
call [eax]            ; push EIP_next; EIP = [EAX]
```

Pushes the address of the instruction following CALL onto the stack (ESP -= 4),
then transfers control to the target. Does not affect flags.

### RET -- Return

```asm
ret                   ; EIP = [ESP]; ESP += 4
ret 0x10              ; EIP = [ESP]; ESP += 4 + 0x10
```

`ret` pops the return address into EIP. `ret N` additionally adds N to ESP
after popping EIP (callee stack cleanup, used by `__stdcall`). Does not affect
flags.

`ret N` does NOT pop N bytes before reading EIP. It pops EIP first, then adds N
to ESP. The value N cleans up the arguments that the caller pushed.

### JMP -- Unconditional Jump

```asm
jmp 0x00401000        ; EIP = 0x00401000
jmp eax               ; EIP = EAX
jmp [eax]             ; EIP = [EAX]
jmp short label       ; relative jump, 8-bit offset
```

### Jcc -- Conditional Jumps

See Section 5 for the full table. Each Jcc instruction checks EFLAGS and
transfers control if the condition is met.

### LOOP

```asm
loop label            ; ECX -= 1; if ECX != 0, jump to label
```

Decrements ECX and jumps if ECX is not yet zero. Does not affect flags. Rarely
emitted by optimizing compilers but sometimes useful in shellcode.

### JECXZ

```asm
jecxz label           ; if ECX == 0, jump to label (no flag check)
```

### INT -- Software Interrupt

```asm
int 3                 ; breakpoint trap (0xCC)
int 0x2E              ; system call (Windows, legacy)
```

`int 3` is a single-byte instruction (opcode 0xCC) used for breakpoints.

### NOP -- No Operation

```asm
nop                   ; single-byte NOP (opcode 0x90 = xchg eax, eax)
```

NOP sleds in shellcode use sequences of 0x90. Multi-byte NOPs exist
(`0F 1F 00`, etc.) but the single-byte form is standard for sleds.

### LEAVE

```asm
leave                 ; ESP = EBP; POP EBP
```

Equivalent to `mov esp, ebp` followed by `pop ebp`. Tears down a stack frame.
Common epilogue instruction.

## String and Memory Operations

All string instructions use ESI (source), EDI (destination), ECX (count for
`rep`), and the DF flag (0 = increment, 1 = decrement). Size suffixes: `b` =
byte (1), `w` = word (2), `d` = dword (4).

### MOVSB / MOVSD -- Move String

```asm
rep movsb             ; copy ECX bytes from [ESI] to [EDI]
rep movsd             ; copy ECX dwords from [ESI] to [EDI]
```

After each element: ESI += size, EDI += size (or -= if DF=1). ECX decremented
by `rep`. Implements `memcpy` when DF=0.

### STOSB / STOSD -- Store String

```asm
rep stosb             ; fill ECX bytes at [EDI] with AL
rep stosd             ; fill ECX dwords at [EDI] with EAX
```

Implements `memset`. EDI advances; ECX decremented by `rep`.

### LODSB / LODSD -- Load String

```asm
lodsb                 ; AL = [ESI]; ESI += 1
lodsd                 ; EAX = [ESI]; ESI += 4
```

Loads from [ESI] into the accumulator. Advances ESI. No `rep` prefix is
typical -- used in loops for byte-by-byte processing (hash computation).

### SCASB / SCASD -- Scan String

```asm
repne scasb           ; scan [EDI] for AL, stop when found or ECX=0
repe scasd            ; scan [EDI] for mismatch with EAX
```

Compares AL/EAX with [EDI], sets flags, advances EDI. `repne scasb` is the
core of `strlen` (scan for null byte).

### CMPSB / CMPSD -- Compare Strings

```asm
repe cmpsb            ; compare [ESI] with [EDI] byte by byte while equal
```

Compares [ESI] with [EDI], sets flags, advances both. `repe cmpsb` is the core
of `memcmp`/`strcmp`.

### REP Prefixes

| Prefix | Meaning |
|--------|---------|
| `rep` | Repeat ECX times |
| `repe` / `repz` | Repeat while equal (ZF=1) and ECX > 0 |
| `repne` / `repnz` | Repeat while not equal (ZF=0) and ECX > 0 |

### CLD / STD -- Clear/Set Direction Flag

```asm
cld                   ; DF = 0 (string ops increment ESI/EDI)
std                   ; DF = 1 (string ops decrement ESI/EDI)
```

The Windows ABI requires DF=0 on function entry and exit. Shellcode should
execute `cld` before string operations to ensure forward direction. Forgetting
this is a common shellcode bug.

## Other Commonly Encountered

### CMP

```asm
cmp eax, 0x80         ; compute EAX - 0x80, set flags, discard result
```

Sets flags as if SUB were performed. The most common comparison instruction.
See Section 5 for flag interpretation.

### CDQ -- Convert Double to Quad

```asm
cdq                   ; EDX = (EAX < 0) ? 0xFFFFFFFF : 0x00000000
```

Sign-extends EAX into EDX:EAX. Required before `idiv`. If EAX is non-negative,
EDX becomes 0. Shellcode uses `cdq` after `xor eax, eax` to zero EDX in one
byte (opcode 0x99).

### CWD -- Convert Word to Double

```asm
cwd                   ; DX = sign-extend(AX)
```

### CWDE -- Convert Word to Double Extended

```asm
cwde                  ; EAX = sign-extend(AX)
```

### XLAT -- Table Lookup

```asm
xlat                  ; AL = [EBX + AL]
```

Single-byte lookup table instruction. Rarely seen in compiled code.

### ENTER

```asm
enter 0x40, 0         ; push EBP; mov EBP,ESP; sub ESP,0x40
```

Equivalent to the standard prologue but slower. Modern compilers do not emit it.

### LEAVE

```asm
leave                 ; ESP = EBP; pop EBP
```

Standard epilogue instruction. Equivalent to `mov esp, ebp; pop ebp`.
