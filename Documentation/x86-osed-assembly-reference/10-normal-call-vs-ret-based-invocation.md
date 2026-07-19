# 10. Normal CALL vs. RET-Based Invocation

## Normal CALL

```asm
push offset old_prot    ; arg4: lpflOldProtect
push 0x40               ; arg3: flNewProtect
push 0x400              ; arg2: dwSize
push eax                ; arg1: lpAddress
call VirtualProtect     ; pushes return address, jumps to VirtualProtect
```

After `call`, the stack seen by VirtualProtect:

```
ESP   -> return address   (pushed by CALL)
ESP+4 -> lpAddress
ESP+8 -> dwSize
ESP+C -> flNewProtect
ESP+10-> lpflOldProtect
```

## RET-Based Invocation (ROP)

Instead of pushing arguments and using `call`, arrange the stack so that a
preceding gadget's `ret` loads the function address into EIP:

```
ESP -> VirtualProtect     (will become EIP via ret)
+04   ReturnToShellcode   (VirtualProtect's "return address")
+08   ShellcodeAddress    (arg1: lpAddress)
+0C   0x00000400          (arg2: dwSize)
+10   0x00000040          (arg3: flNewProtect)
+14   WritableAddress     (arg4: lpflOldProtect)
```

When the preceding gadget executes `ret`:

1. `EIP = [ESP]` = VirtualProtect address
2. `ESP += 4` (now points at ReturnToShellcode)

VirtualProtect now sees exactly the same stack layout it would see after a
normal `call`:

```
ESP   -> ReturnToShellcode  (its "return address")
ESP+4 -> ShellcodeAddress   (arg1)
ESP+8 -> 0x400              (arg2)
ESP+C -> 0x40               (arg3)
ESP+10-> WritableAddress    (arg4)
```

VirtualProtect executes, changes page protections, then does `ret 0x10`
(stdcall cleanup):

1. `EIP = [ESP]` = ReturnToShellcode
2. `ESP += 4 + 0x10` = skips past the 4 arguments

Execution lands at the shellcode with the page now marked executable.

The CPU does not distinguish how VirtualProtect was reached. It follows the ABI
mechanically: arguments are at fixed offsets from ESP, and `ret N` cleans them.
