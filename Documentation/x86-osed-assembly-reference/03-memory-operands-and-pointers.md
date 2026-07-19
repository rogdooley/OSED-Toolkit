# 3. Memory Operands and Pointers

## Intel Operand Syntax

All examples use Intel syntax (destination, source):

```asm
mov eax, ebx            ; register to register: EAX = EBX
mov eax, [ebx]          ; memory to register: EAX = DWORD at address EBX
mov eax, [ebx+4]        ; EAX = DWORD at address EBX+4
mov eax, [ebx+ecx*4+8]  ; EAX = DWORD at address EBX + ECX*4 + 8
lea eax, [ebx+ecx*4+8]  ; EAX = EBX + ECX*4 + 8  (address calculation, no memory read)
```

## MOV vs. LEA

This is one of the most commonly confused distinctions:

```asm
mov eax, [ebx+4]   ; reads memory: EAX = the DWORD stored at address (EBX+4)
lea eax, [ebx+4]   ; computes address: EAX = EBX + 4  (no memory access)
```

`MOV` with brackets dereferences -- it goes to memory and fetches the value.
`LEA` never touches memory -- it computes the effective address and stores the
result. Compilers use `LEA` as a fast multi-operand add/multiply:

```asm
lea eax, [ecx+ecx*2]    ; EAX = ECX * 3
lea eax, [ecx*4+0x10]   ; EAX = ECX * 4 + 16
```

## Effective Address Components

The general form is `[base + index*scale + displacement]`:

| Component | Allowed values |
|-----------|---------------|
| base | Any GPR |
| index | Any GPR except ESP |
| scale | 1, 2, 4, or 8 |
| displacement | Signed 8-bit or 32-bit immediate |

The scale encodes element size: `*4` = dword array, `*2` = word array,
`*1` (or omitted) = byte array.

## Size Qualifiers

When the assembler cannot infer operand size from context, a PTR qualifier is
required:

```asm
mov BYTE PTR [eax], 0        ; write 1 byte
mov WORD PTR [eax], 0        ; write 2 bytes
mov DWORD PTR [eax], 0       ; write 4 bytes
mov byte ptr [eax], cl       ; size inferred from CL (8-bit), PTR is documentation
```

| Qualifier | Size | Bytes |
|-----------|------|-------|
| BYTE PTR | 8-bit | 1 |
| WORD PTR | 16-bit | 2 |
| DWORD PTR | 32-bit | 4 |

## Pointer Chains

Structures containing pointers to other structures create chains:

```asm
mov eax, [eax+0x0C]     ; follow pointer at offset 0x0C
mov eax, [eax+0x14]     ; follow pointer at offset 0x14 of the result
mov eax, [eax+0x08]     ; read value at offset 0x08
```

Each `mov reg, [reg+offset]` dereferences one level. This is the pattern used
in PEB walking (Section 17).

## Arrays

```asm
mov eax, [esi+ecx*4]    ; EAX = array[ecx], where elements are DWORDs
```

The scale factor `*4` encodes the element size. `ECX` is the index. `ESI` is
the base address of the array.

## Structures

Structure field access appears as a fixed displacement from a base register:

```asm
mov eax, [ebx+0x08]     ; read field at offset 0x08
mov [ebx+0x20], ecx     ; write field at offset 0x20
```

Multiple accesses to the same base with different fixed offsets indicate
structure field access.

## Memory Permissions

Not all memory is readable, writable, or executable. When the CPU attempts an
operation that violates a page's protection, it raises an access violation:

- **Read from non-readable page** -- access violation
- **Write to read-only page** -- access violation
- **Execute from non-executable page** -- access violation (DEP/NX)

Use `!address` or `!vprot` in WinDbg to check page protections.
