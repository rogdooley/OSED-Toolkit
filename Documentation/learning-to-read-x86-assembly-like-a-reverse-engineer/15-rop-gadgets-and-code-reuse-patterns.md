# ROP Gadgets and Code-Reuse Patterns

## Learning objectives

- Read individual ROP gadgets as primitive operations on registers and the stack.
- Identify stack pivot gadgets and explain why they matter.
- Recognize mid-instruction gadgets and unintended instruction boundaries.
- Trace a short ROP chain through the stack to recover its intent.
- Connect gadget analysis to the broader exploit strategy (DEP bypass, API calls).

## Concept discussion

When DEP prevents execution of attacker-supplied code on the stack or heap, the
attacker reuses fragments of existing executable code. Each fragment ends with
`ret` (or `ret N`), which pops the next address from the stack and transfers
control there. By chaining these fragments through a controlled stack, the
attacker builds arbitrary computation from existing code.

A ROP gadget is a short instruction sequence ending in `ret`. The reverse
engineer reads gadgets differently from normal functions:

- There is no calling convention. The stack is the program.
- Each gadget consumes stack slots: one for the return address, plus any that
  `pop` instructions or `ret N` consume.
- Side effects on registers and memory are the gadget's purpose.
- The gadget may start at an aligned instruction boundary (intended gadget) or
  at an offset within a longer instruction (unintended/mid-instruction gadget).

## Common gadget patterns

### Register control

- `pop eax; ret`: load EAX from the stack. Consumes one slot for the value
  and one for the next gadget address.
- `pop ecx; pop ecx; ret`: load two values (or skip one and load one).
- `xchg eax, esp; ret`: dangerous stack pivot if EAX is controlled.
- `mov eax, ecx; ret`: transfer between registers.

### Memory operations

- `mov [eax], ecx; ret`: write-what-where primitive.
- `mov [ecx], eax; ret`: write-what-where (reversed operands).
- `mov eax, [eax]; ret`: dereference and load.
- `add [eax], ecx; ret`: additive write primitive.
- `inc dword ptr [eax]; ret`: increment primitive.

### Arithmetic and flag manipulation

- `add eax, ecx; ret`: register addition.
- `sub eax, ecx; ret`: register subtraction.
- `neg eax; ret`: negate.
- `xor eax, eax; ret`: zero a register.

### Stack pivots

- `xchg eax, esp; ret`: pivot ESP to attacker-controlled address in EAX.
- `mov esp, ebp; pop ebp; ret`: standard epilogue reused as pivot if EBP is
  controlled.
- `add esp, offset; ret`: skip stack slots (useful for alignment or jumping
  over bad characters).
- `pop esp; ret`: direct ESP control from the stack.
- `leave; ret`: equivalent to `mov esp, ebp; pop ebp; ret`.

### API call setup

- `push eax; call [ebx]`: call through import pointer with argument.
- `pushad; ret`: push all registers, then continue chain. Useful for setting
  up a complex API call frame.
- `mov edx, [eax]; call [edx+offset]`: virtual-call gadget reused for
  controlled dispatch.

## Fully annotated example

### Reading a single gadget

```asm
; At address 0x7C345678 inside a system DLL:
    pop     eax
    pop     ebx
    ret
```

Annotated:

```asm
pop eax
; Load the next stack slot into EAX.

pop ebx
; Load the following stack slot into EBX.

ret
; Pop the next address and transfer control.
```

Stack layout when this gadget executes:

```text
ESP+00: value for EAX
ESP+04: value for EBX
ESP+08: address of next gadget
```

This gadget consumes three stack slots: two data values and one return address.

### Reading a short ROP chain

```text
Stack layout (controlled by attacker after overflow):

ESP+00: 0x7C345678   ; pop eax; pop ebx; ret
ESP+04: 0x00000040   ; -> EAX = PAGE_EXECUTE_READWRITE
ESP+08: 0x7C349ABC   ; -> EBX = (consumed/don't care)
                      ;    also: address of next gadget
        ... wait, that's wrong. Let me re-layout:
```

Corrected chain with proper slot accounting:

```text
ESP+00: 0x7C345678   ; gadget: pop eax; pop ebx; ret
ESP+04: 0x00000040   ; -> EAX (PAGE_EXECUTE_READWRITE)
ESP+08: 0xDEADBEEF   ; -> EBX (unused placeholder)
ESP+0C: 0x7C341234   ; gadget: pop ecx; ret
ESP+10: 0x00401000   ; -> ECX (target address)
ESP+14: 0x7C34ABCD   ; gadget: mov [ecx], eax; ret
ESP+18: ...          ; next gadget or payload
```

Annotated chain:

```text
Step 1: pop eax; pop ebx; ret
  EAX = 0x40 (PAGE_EXECUTE_READWRITE)
  EBX = 0xDEADBEEF (don't care)
  ret -> 0x7C341234

Step 2: pop ecx; ret
  ECX = 0x00401000 (target address for write)
  ret -> 0x7C34ABCD

Step 3: mov [ecx], eax; ret
  Write 0x40 to address 0x00401000
  ret -> next gadget
```

The chain writes a protection constant to a known address. This might be part
of setting up arguments for `VirtualProtect` on the stack before calling it.

## Reverse engineering thought process

### Identifying gadgets in a binary

Gadgets exist wherever a `ret` instruction appears. Scan backward from each
`ret` to find useful instruction sequences:

```text
1. Find all ret (0xC3) and ret N (0xC2 xx xx) bytes.
2. Disassemble backward 1-6 bytes from each ret.
3. Check whether the preceding bytes form valid, useful instructions.
4. Record the gadget address, instructions, and stack slot consumption.
```

### Mid-instruction gadgets

x86 is variable-length. A `ret` byte (`0xC3`) inside a longer instruction's
encoding can be the start of an unintended gadget:

```text
Intended instruction at 0x7C345670:
    68 C3 50 90 7C    push 7C9050C3h

Unintended gadget at 0x7C345671:
    C3                ret

Unintended gadget at 0x7C345671 with prefix:
    Starting at 0x7C345670:
    ...

Better example:
Intended instruction at 0x7C345670:
    8B 45 C3          mov eax, [ebp-3Dh]

Unintended: starting at 0x7C345672:
    C3                ret

Or:
    B8 5B 5D C3 90    mov eax, 90C35D5Bh

Unintended at offset +1:
    5B                pop ebx
    5D                pop ebp
    C3                ret
```

The last example is important: the intended instruction `mov eax, 90C35D5Bh`
contains the bytes `5B 5D C3` at an offset. Disassembling from that offset
yields `pop ebx; pop ebp; ret`, a valid and useful gadget that never appears
in the source code or compiler output.

### Evaluating gadget quality

Not every gadget is usable:

```text
Good gadget:
  - Minimal side effects (only changes target registers)
  - No conditional branches
  - Predictable stack consumption
  - Located in a non-ASLR module or ASLR-bypassed module

Bad gadget:
  - Clobbers registers needed by later gadgets
  - Contains memory accesses that may fault
  - Has conditional branches that change stack consumption
  - Located in an ASLR module without an info leak
```

### Chain analysis template

```text
Gadget address:
Instructions:
Stack slots consumed: (pops + 1 for ret, or pops + 1 + N/4 for ret N)
Registers modified:
Registers clobbered (unwanted side effects):
Memory reads:
Memory writes:
Preconditions (registers/memory that must be valid):
```

## Common mistakes

- Forgetting that `ret` itself consumes a stack slot (the next gadget address).
- Miscounting stack consumption when `ret N` is used. `ret 8` pops the return
  address *and* removes 8 additional bytes from the stack.
- Assuming gadgets only exist at function boundaries. Mid-instruction gadgets
  are often the most useful.
- Ignoring register clobber. A gadget that sets ECX but also clobbers EAX may
  break a chain that depends on EAX from a prior gadget.
- Treating `pushad` as pushing to the ROP chain stack. `pushad` pushes onto
  ESP at the time it executes, which may or may not be the chain stack.
- Confusing intended code semantics with gadget semantics. A gadget is used
  for its side effect, not its original purpose.

## Exercises

Given this stack layout after a buffer overflow:

```text
ESP+00: 0x10015442   ; pop eax; ret
ESP+04: 0x00000040   ; -> EAX (PAGE_EXECUTE_READWRITE)
ESP+08: 0x10017753   ; pop ecx; ret
ESP+0C: 0x1002A148   ; -> ECX (writable address in .data)
ESP+10: 0x1001AABB   ; mov [ecx], eax; ret
ESP+14: 0x10015442   ; pop eax; ret
ESP+18: 0x7C801D7B   ; -> EAX (address of VirtualProtect)
ESP+1C: 0x10012345   ; push eax; ret
```

Questions:

- What value is written, and where?
- What does the chain do after the write?
- Why is `push eax; ret` useful at the end?
- How many total stack slots does this chain consume?

## Challenge problems

```text
Overflow payload in hex, starting at saved return address:

44 55 01 10    ; ESP+00
40 00 00 00    ; ESP+04
53 77 01 10    ; ESP+08
48 A1 02 10    ; ESP+0C
BB AA 01 10    ; ESP+10
42 54 01 10    ; ESP+14
7B 1D 80 7C    ; ESP+18
CC CC CC CC    ; ESP+1C
```

Given the following gadget catalog (all from a non-ASLR module at `0x1001xxxx`):

```text
0x10015544: pop eax; ret
0x10015442: pop eax; ret          (duplicate at different address)
0x10017753: pop ecx; ret
0x1001AABB: mov [ecx], eax; ret
0x10015442: pop eax; ret
```

And: `0x7C801D7B` is the address of `kernel32!VirtualProtect`.

Trace the chain step by step. What is the attacker trying to accomplish? What
is missing from this chain for a complete DEP bypass?

## Solutions with reasoning

Exercise solution:

Step-by-step trace:

1. `pop eax; ret` at `0x10015442`: EAX = `0x40`, ret to `0x10017753`.
2. `pop ecx; ret` at `0x10017753`: ECX = `0x1002A148`, ret to `0x1001AABB`.
3. `mov [ecx], eax; ret` at `0x1001AABB`: write `0x40` to address
   `0x1002A148`, ret to `0x10015442`.
4. `pop eax; ret` at `0x10015442`: EAX = `0x7C801D7B` (VirtualProtect), ret
   to `0x10012345`.
5. `push eax; ret` at `0x10012345`: push `0x7C801D7B` onto the stack, then
   `ret` pops it and transfers control to `VirtualProtect`.

The chain writes `0x40` (`PAGE_EXECUTE_READWRITE`) to a writable .data
address, staging it as an argument for `VirtualProtect`, then redirects
execution to `VirtualProtect`. The
`push eax; ret` pattern is a standard way to call an API whose address is in a
register: pushing it makes it the next return address, and `ret` "calls" it.

The chain consumes 8 stack slots (ESP+00 through ESP+1C).

Challenge solution:

The payload bytes are little-endian dword addresses. Reading them:

```text
ESP+00: 0x10015544   pop eax; ret
ESP+04: 0x00000040   -> EAX = 0x40 (PAGE_EXECUTE_READWRITE)
ESP+08: 0x10017753   pop ecx; ret
ESP+0C: 0x1002A148   -> ECX = writable .data address
ESP+10: 0x1001AABB   mov [ecx], eax; ret
ESP+14: 0x10015442   pop eax; ret
ESP+18: 0x7C801D7B   -> EAX = VirtualProtect address
ESP+1C: 0xCCCCCCCC   -> padding / int3 marker
```

The chain writes the `PAGE_EXECUTE_READWRITE` constant to a .data address, then
loads VirtualProtect's address into EAX. At ESP+1C the chain has `0xCCCCCCCC`
(int3 breakpoints), suggesting the chain is incomplete or the attacker is
debugging.

For a complete DEP bypass via `VirtualProtect(address, size, newProtect,
&oldProtect)`, the chain still needs to:

- Set up the four arguments on the stack (or in the right locations).
- Point the return address of `VirtualProtect` to the shellcode.
- Provide a writable address for the `lpflOldProtect` output parameter.
- Actually transfer control to `VirtualProtect` (the current chain loads it
  into EAX but does not call it yet).

The `0x40` value written to `.data` is likely being staged for later use as the
`flNewProtect` argument when the full `VirtualProtect` call frame is assembled.

---
