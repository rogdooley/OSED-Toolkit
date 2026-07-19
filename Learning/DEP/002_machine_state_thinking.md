# Lesson Capture 002 — Thinking in Machine State

## The change in method

The first approach treated a ROP chain as a list of mysterious gadget addresses. That produced the exact failure mode the lesson was meant to prevent: seeing instructions without knowing what question each one answered.

The replacement question is:

> What machine state must exist when execution reaches the next important function?

Gadgets are implementations of that state transition. They are not the objective.

## Three layers

Keep these separate:

1. **Objective** — for example, patch the `VirtualAlloc` slot.
2. **Algorithm** — compute a pointer, compute a value, write the value.
3. **Gadgets** — the available instructions used to implement the algorithm.

The course often presents layers 2 and 3 together. The worksheet method deliberately solves layer 1 first.

## State ledger

For the first DEP objective, the ledger is:

| Objective | Required state |
|---|---|
| Find frame | `ESI = &VirtualAllocPlaceholder` |
| Resolve API | `EAX = VirtualAlloc` |
| Patch frame | `[ESI] = EAX` |
| Find return slot | `ESI = &ReturnAddress` |
| Compute payload | `EAX = &Shellcode` (or another source register) |
| Patch return | `[ESI] = EAX` |

Everything else is temporary state, stack consumption, or side effect.

## Pointer versus pointee

If:

```text
ESI = 0x0012FF40
[ESI] = 0x45454545
EAX = 0x77C11120
```

then:

```asm
mov esi, eax
```

changes the pointer:

```text
ESI = 0x77C11120
[0x0012FF40] remains 0x45454545
```

Whereas:

```asm
mov [esi], eax
```

writes through the pointer:

```text
ESI remains 0x0012FF40
[0x0012FF40] becomes 0x77C11120
```

This was a key correction during the lesson.

## Gadget as state transformer

Consider:

```asm
pop eax
ret
```

If the stack begins with `ValueForEAX`, then the gadget transforms:

```text
Before:
EAX = ?
ESP -> ValueForEAX
```

into:

```text
After:
EAX = ValueForEAX
EIP = next DWORD on the stack
ESP -> data after next address
```

The gadget has a useful effect and a stack cost. Both belong in the ledger.

## Two-gadget execution exercise

Stack:

```text
ESP ---> 0x11111111
         POP ECX; RET
         0x22222222
         VirtualProtect
         ReturnToShellcode
         ShellcodeAddress
         0x400
         0x40
         WritableAddress
```

Execute `POP EAX; RET`:

```text
EAX = 0x11111111
EIP = POP ECX; RET
ESP -> 0x22222222
```

Execute `POP ECX; RET`:

```text
ECX = 0x22222222
EIP = VirtualProtect
ESP -> ReturnToShellcode
```

At that point the API sees the expected call frame. The stack is both control-flow data and function-call data.

## Register planning is not register worship

Some registers are required by a later gadget; others are scratch. Write `don't care` where a value has no downstream consumer. A shorter chain is not automatically better if it destroys a pointer that must be preserved.

For each candidate gadget record:

```text
Inputs required:
Registers changed:
Memory read/write:
DWORDs consumed:
Next EIP source:
Registers that must survive:
```

## Why a perfect gadget is unnecessary

The desired semantic operation may be:

```text
ESI = ESI + 4
```

A direct `ADD ESI,4; RET` is convenient but not required. A composition such as:

```asm
pop ecx ; ret       ; ECX = 4
add esi, ecx ; ret
```

implements the same state transition. Search for capabilities, not spellings.

## Efficiency question

The lesson asked how developers choose an efficient chain. The answer is constrained optimization, not simply shortest length.

Priorities:

1. Reliability and predictable modules.
2. No bad bytes in transmitted addresses or constants.
3. Preservation of state already calculated.
4. Low stack consumption.
5. Short length, when the above remain equal.

A longer chain with clean side effects is preferable to a short chain that clobbers `ESI` or depends on an unstable module.

## Exercise: write the transformation

For each goal, write the desired state before searching for gadgets:

```text
Goal: patch API pointer
Destination pointer:
Source value:
Write operation:
```

```text
Goal: move to return slot
Current pointer:
Offset:
Desired pointer:
```

```text
Goal: follow an IAT entry
Register before dereference:
Instruction:
Register after dereference:
```

## Conclusions

- Design the target state before opening RP++.
- Treat each gadget as a small state transition.
- Track stack consumption and clobbers explicitly.
- Separate destination pointers from values written through them.
- Equivalent semantic results can have many gadget implementations.
