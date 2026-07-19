# 19. Position-Independent Shellcode

## Core Constraints

Position-independent shellcode must work at any load address:

- **No absolute code addresses** -- cannot reference labels with fixed addresses
- **No absolute data addresses** -- cannot use global string pointers
- **No import table** -- must resolve APIs at runtime (PEB walking)

## Self-Location: JMP-CALL-POP

The standard technique to discover the shellcode's own address:

```asm
    jmp short get_addr     ; forward jump over the call
execute:
    pop esi                ; ESI = address of "data" below
    ; ... shellcode body using ESI as base ...

get_addr:
    call execute           ; pushes address of next instruction onto stack
    ; "data" starts here (strings, encoded payloads, etc.)
    db "cmd.exe", 0
```

`call execute` pushes the address of the byte after the call instruction (the
start of "data") onto the stack. `pop esi` captures that address.

## Stack Strings

Build strings on the stack to avoid embedding them at a fixed data address:

```asm
xor eax, eax              ; EAX = 0
push eax                   ; null terminator
push 0x636C6163            ; "calc" (little-endian, reversed)
mov ebx, esp               ; EBX = pointer to "calc\0" on the stack
```

Byte-by-byte: `push 0x636C6163` places bytes `63 61 6C 63` in memory
(little-endian), which reads as the ASCII string `calc`.

## Null-Byte Avoidance

Null bytes (`0x00`) terminate C strings and are bad characters in most buffer
overflows. Techniques:

```asm
; Instead of: mov eax, 0         (encodes 0x00000000)
xor eax, eax                     ; same result, no null bytes

; Instead of: push 0             (encodes 0x00000000 as immediate)
xor eax, eax
push eax                          ; push the zeroed register

; Instead of: mov eax, 0x00401000  (contains 0x00)
; Use arithmetic or encoding to avoid the null byte
```

## Direction Flag

The Windows ABI expects DF=0 (forward direction for string ops). If DF might
be set from prior execution, clear it at the start of the shellcode:

```asm
cld                       ; DF = 0
```

Forgetting `cld` can cause `rep movsb` to copy backward, corrupting the
destination or segfaulting.

## Register Preservation

Some shellcode contexts (SEH handlers, egghunters) require specific registers
to be preserved or set to particular values on entry. Document assumptions
about register state at the start of your shellcode.

## Stack Safety

Shellcode runs on the thread's existing stack. If the shellcode's stack usage
overlaps with the ROP chain or the exploit payload sitting on the stack, it
will corrupt its own data. Solutions:

- `sub esp, N` at the start to create clearance below
- Use registers instead of the stack where possible
- Be aware of how deep API calls push before returning
