# 9. Calling Conventions

## cdecl (C Declaration)

- **Arguments:** pushed right-to-left
- **Stack cleanup:** caller (add esp, N after call)
- **Return value:** EAX (or EDX:EAX for 64-bit)
- **Callee-saved:** EBX, ESI, EDI, EBP
- **Caller-saved:** EAX, ECX, EDX

```asm
; Calling: int result = func(1, 2, 3);
push 3
push 2
push 1
call func
add esp, 0x0C         ; caller cleans 3 args * 4 bytes
; result in EAX
```

Default for C functions. Supports variadic arguments because the caller knows
the argument count and cleans up.

## stdcall (Standard Call)

- **Arguments:** pushed right-to-left
- **Stack cleanup:** callee (`ret N`)
- **Return value:** EAX
- **Callee-saved:** EBX, ESI, EDI, EBP

```asm
; Calling: VirtualProtect(addr, size, prot, &old);
push offset old_prot  ; arg4
push 0x40             ; arg3 = PAGE_EXECUTE_READWRITE
push 0x400            ; arg2 = size
push eax              ; arg1 = address
call VirtualProtect
; no add esp -- callee cleaned up with ret 0x10
; result in EAX
```

Used by all Windows API functions (WINAPI = stdcall). The callee executes
`ret 0x10` (4 args * 4 bytes = 0x10).

## fastcall

- **Arguments:** first two in ECX, EDX; remainder pushed right-to-left
- **Stack cleanup:** callee
- **Return value:** EAX

```asm
; Calling: fastcall_func(1, 2, 3, 4);
push 4                ; arg4
push 3                ; arg3
mov edx, 2            ; arg2 in EDX
mov ecx, 1            ; arg1 in ECX
call fastcall_func
; callee cleans stack args with ret 0x08
```

## thiscall (MSVC C++)

- **Arguments:** `this` in ECX; rest pushed right-to-left
- **Stack cleanup:** callee
- **Return value:** EAX

```asm
; Calling: obj->method(arg1, arg2);
push arg2
push arg1
mov ecx, obj_ptr      ; this pointer
call method
```

Looks like stdcall but with ECX loaded before the call. Recognizable by ECX
being set to a pointer (not a small integer) immediately before the call.

## On Entry to the Callee

Regardless of convention, when execution reaches the first instruction of the
called function:

```
ESP   ->  return address
ESP+4 ->  arg1 (or first stack arg after register args)
ESP+8 ->  arg2
ESP+C ->  arg3
...
```

After the prologue (`push ebp; mov ebp, esp`):

```
EBP+0x04 = return address
EBP+0x08 = arg1
EBP+0x0C = arg2
EBP+0x10 = arg3
```

The function does not know or care whether it was reached through a `call`
instruction, a ROP gadget, or an overwritten return address. It consumes state
according to the ABI.
