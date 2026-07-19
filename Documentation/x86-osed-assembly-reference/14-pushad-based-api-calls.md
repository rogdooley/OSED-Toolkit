# 14. PUSHAD-Based API Calls

## PUSHAD Push Order and Memory Layout

PUSHAD pushes registers in this CPU-defined order:

1. EAX (pushed first, ends up deepest in memory)
2. ECX
3. EDX
4. EBX
5. original ESP (value before PUSHAD)
6. EBP
7. ESI
8. EDI (pushed last, ends up on top of stack)

Because the stack grows downward, the resulting memory layout is:

```
ESP+0x00 -> EDI     (top of stack -- lowest address)
ESP+0x04 -> ESI
ESP+0x08 -> EBP
ESP+0x0C -> orig ESP
ESP+0x10 -> EBX
ESP+0x14 -> EDX
ESP+0x18 -> ECX
ESP+0x1C -> EAX     (deepest -- highest address)
```

## Using PUSHAD to Build a Call Frame

For a `pushad; ret` gadget to invoke VirtualProtect via ROP, arrange registers
before PUSHAD so the stack afterward looks like a valid stdcall frame:

```
Target stack layout after pushad:

ESP+0x00 -> EDI = VirtualProtect address   <-- ret pops this into EIP
ESP+0x04 -> ESI = return address           <-- VP's return address
ESP+0x08 -> EBP = arg1 (lpAddress)
ESP+0x0C -> orig ESP = arg2 (dwSize)       <-- cannot control directly
ESP+0x10 -> EBX = arg3 (flNewProtect)
ESP+0x14 -> EDX = arg4 (lpflOldProtect)
```

The `ret` after PUSHAD pops EDI into EIP, so EDI must hold the function
address. ESI becomes the return address. EBP becomes arg1. EBX and EDX become
args 3 and 4. The original ESP value occupies the arg2 slot and may need to be
set to a useful value (often a large-enough size works because ESP typically
points within the stack region being marked executable).
