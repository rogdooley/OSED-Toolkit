# 13. ROP Gadget Semantics

A gadget is a short instruction sequence ending in `ret` (or equivalent). The
`ret` at the end pops the next address from the stack, chaining execution to
the next gadget. Each gadget performs one small state change.

## Register Load

```asm
pop eax ; ret
```

```
Before:               After:
ESP -> 0x11111111     EAX = 0x11111111
       NextGadget     EIP = NextGadget
                      ESP = old_ESP + 8
```

Loads an immediate value from the stack into a register. Consumes 8 bytes of
stack (4 for the value, 4 for the return address used by `ret`).

## Register Exchange

```asm
xchg eax, ecx ; ret
```

```
Before:               After:
EAX = A, ECX = C      EAX = C, ECX = A
ESP -> NextGadget      EIP = NextGadget
                       ESP = old_ESP + 4
```

## Dereference (Memory Read)

```asm
mov eax, [eax] ; ret
```

```
Before:               After:
EAX = 0x76300000      EAX = [0x76300000]  (value at that address)
ESP -> NextGadget      EIP = NextGadget
```

Used to read IAT entries, data pointers, or structure fields. Precondition: EAX
must hold a valid readable address.

## Memory Write

```asm
mov [edi], eax ; ret
```

```
Before:               After:
EDI = target_addr     [target_addr] = EAX
EAX = value_to_write  EIP = NextGadget
ESP -> NextGadget
```

The fundamental store primitive for building a fake stack frame. Precondition:
EDI must hold a valid writable address.

## Arithmetic

```asm
add eax, ecx ; ret
```

```
Before:               After:
EAX = X, ECX = Y      EAX = X + Y
                       EIP = NextGadget
```

Used to compute values that cannot be loaded directly (e.g., because they
contain null bytes).

## Stack Adjustment

```asm
add esp, 0x20 ; ret
```

```
Before:               After:
ESP -> 0x1000          ESP = 0x1000 + 0x20 + 4 = 0x1024
                       (skip 0x20 bytes, then ret pops next 4)
```

Skips over unwanted stack data. Common when gadgets have trailing pops or when
aligning to a specific stack location.

## Stack Pivot

```asm
xchg eax, esp ; ret
```

```
Before:               After:
EAX = 0x0C0C0C0C      ESP = 0x0C0C0C0C
                       EIP = [0x0C0C0C0C]  (first gadget at pivoted stack)
```

Redirects the entire ROP chain to a different memory region. Precondition: EAX
must point to controlled data structured as a ROP chain.

```asm
mov esp, ebp ; pop ebp ; ret
```

Uses EBP as the pivot source. The `pop ebp` consumes one DWORD, so aim EBP
4 bytes before the API address so the stray pop eats a dummy value and ESP
lands on the target.

## PUSHAD in ROP

```asm
pushad ; ret
```

Pushes all 8 registers (32 bytes) then `ret` pops the next address. The
pre-PUSHAD register arrangement determines the fake call frame on the stack.
Because PUSHAD pushes EAX first (deepest) and EDI last (on top), and `ret`
pops from the top, EDI's value becomes the next EIP.

To use PUSHAD for a VirtualProtect call, arrange registers so the resulting
stack frame contains the correct arguments at the correct offsets.

## Conditional Gadgets

Some gadgets contain conditional logic:

```asm
test eax, eax
jne skip
pop ecx
skip:
ret
```

These are fragile and version-specific. Prefer unconditional gadgets where
possible.

## Side Effects

Every gadget may clobber registers or flags beyond its intended operation.
Document the full before/after state, including which registers are destroyed.
A gadget like `mov [edi], eax ; pop esi ; ret` clobbers ESI -- if ESI was
holding a needed value, it must be reloaded.
