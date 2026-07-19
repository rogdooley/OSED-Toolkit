# Lesson Capture 005 — Runtime Pointer Arithmetic and Chain Design

## Why arithmetic appears everywhere

Ideal gadgets are rare. The binary may not contain `SUB ESI,1C; RET`, a direct `ADD ESI,4; RET`, or a clean constant without bad bytes. ROP therefore computes values at runtime from safe inputs.

The recurring algorithm is:

```text
known pointer
    + safe correction
    = desired pointer
```

and:

```text
safe nearby value
    + arithmetic correction
    = desired API/constant
```

## Two's-complement corrections

The desired subtraction is `S - 0x1C`. The transmitted value `0x0000001C` contains null bytes. In 32-bit arithmetic:

```text
0xFFFFFFE4 = -0x1C
S + 0xFFFFFFE4 = S - 0x1C (mod 2^32)
```

The CPU does not need a signed type annotation. It adds bit patterns modulo 32 bits.

## Bad-character correction

The IAT slot is `0x5054A220`, but byte `0x20` is forbidden by the protocol. Send `0x5054A221`, then load `0xFFFFFFFF` and add:

```text
0x5054A221 + 0xFFFFFFFF = 0x5054A220
```

The value in the IAT slot is then read:

```asm
mov eax, [eax]
```

This is a general pattern, not a VirtualAlloc-specific trick.

## Pointer versus value ledger

Maintain two columns whenever writing a field:

| Role | Register/value |
|---|---|
| Destination pointer | `ESI = &field` |
| Source value | `EAX = desired DWORD` |
| Write | `[ESI] = EAX` |

If a gadget needed for arithmetic clobbers the destination register, copy the destination pointer to a second register or recompute it later. Do not silently assume the pointer survived.

## Stack consumption ledger

Every `POP` consumes one DWORD in addition to the gadget address. A gadget such as:

```asm
mov eax, esi
pop esi
ret
```

requires:

```text
gadget address
junk for POP ESI
next gadget address
```

The junk is not optional alignment decoration; it is data consumed by the gadget.

Record each gadget as:

```text
Address:
Instructions:
Registers changed:
Memory changed:
DWORDs consumed:
Next EIP:
Required preserved state:
```

## Constructing the final frame

The conceptual `VirtualAlloc` frame is:

```text
SKELETON+00  VirtualAlloc
SKELETON+04  shellcode address       ; return address
SKELETON+08  shellcode address       ; lpAddress
SKELETON+0C  0x00000001              ; dwSize
SKELETON+10  0x00001000              ; MEM_COMMIT
SKELETON+14  0x00000040              ; PAGE_EXECUTE_READWRITE
```

When the final ROP `RET` consumes `SKELETON+00`:

```text
EIP = VirtualAlloc
ESP -> shellcode address
       shellcode address
       0x1
       0x1000
       0x40
```

The API sees a valid call frame. After it returns, the first shellcode address becomes `EIP`.

## Exploit buffer sizing

The EIP offset does not change when the total exploit buffer grows. If saved EIP begins at byte 276:

```text
bytes 0..275  padding
bytes 276..279 saved EIP
bytes 280+    ROP, frame, padding, shellcode
```

Increasing a chosen buffer from `0x400` to `0x600` adds workspace after the overwrite. It does not move the saved return address. The original function is not expected to return normally once EIP is controlled.

## Reliability over shortest length

A practical chain is selected using constraints:

- stable module addresses;
- no bad bytes in transmitted DWORDs;
- predictable side effects;
- enough controlled stack space;
- preservation of previously computed pointers;
- known API calling convention;
- verifiable intermediate states.

The shortest chain can be fragile. A longer chain that uses clean arithmetic and has isolated objectives is often superior.

## How to verify in WinDbg

Do not begin by asking whether `calc` launched. Verify state transitions:

1. Break on the copy-ESP gadget.
2. Step each instruction; inspect `ESP`, `ESI`, and memory at the stack.
3. Break on the arithmetic gadget; confirm `ECX=-0x1C` and `EAX=S-0x1C`.
4. Dump `[ESI]` before and after `mov [esi],eax`.
5. Break on IAT dereference; confirm `EAX` changes from slot address to API pointer.
6. At final `RET`, dump the five DWORDs the API will consume.
7. At API entry, verify `ESP` points to the intended return address.
8. After API return, verify `EIP` reaches the payload.

## Exercises

### Exercise A — arithmetic

Given `S=0x0D67E31C`, calculate `S + 0xFFFFFFE4`.

### Exercise B — field selection

If `ESI=&SKELETON+00`, what additions produce the return slot, `lpAddress`, and `flProtect` fields?

### Exercise C — source and destination

Explain why `mov [esi],eax` is correct when `ESI` is the field address and `EAX` is the desired value, while `mov esi,eax` is not.

### Exercise D — chain audit

Take any gadget sequence and fill the ledger. Mark every unexpected register clobber before deciding whether it is safe.

## Durable conclusions

- Runtime arithmetic replaces unavailable ideal gadgets.
- Bad-character avoidance is part of chain design, not a final cleanup step.
- A ROP chain is a constrained state-construction program.
- The final proof is the API-entry stack and register state, not merely a successful process launch.
