# Lesson Capture 001 — CPU Execution Model

## Purpose

This capture preserves the foundational work that preceded the ROP walkthrough. The goal was not to memorize exploit instructions. It was to make the CPU's treatment of registers, memory, and the thread stack predictable.

## Starting problem

The recurring confusion was treating a register name as if it were the value stored at the address in that register. In particular, `ESP` and `[ESP]` were being blended together. That distinction is the basis of `POP`, `RET`, stack pivots, and almost every ROP chain.

## Register versus memory

Assume:

```text
ESP = 0x1000

Address       Value
0x1000        0x41414141
0x1004        0x42424242
0x1008        0x43434343
```

`ESP` is the pointer value `0x1000`. It answers “where is the current stack location?”

`[ESP]` means dereference the pointer: read memory at `0x1000`, producing `0x41414141`.

`[ESP+4]` first computes `0x1004`, then reads `0x42424242`.

The equivalent C model is:

```c
uint32_t *p = (uint32_t *)0x1000;
// p      == ESP
// *p     == [ESP]
// *(p+1) == [ESP+4]
```

### Rule

```text
ESP      = where the pointer is
[ESP]    = the value at that location
```

## `POP` as two operations

For:

```asm
pop eax
```

the CPU performs the conceptual sequence:

```asm
EAX = [ESP]
ESP = ESP + 4
```

Given:

```text
ESP = 0x3000
0x3000 -> 0xAAAAAAAA
0x3004 -> 0xBBBBBBBB
```

after `pop eax`:

```text
EAX  = 0xAAAAAAAA
ESP  = 0x3004
[ESP] = 0xBBBBBBBB
```

Nothing is erased. The bytes at `0x3000` remain in memory; only the pointer advances.

## `PUSH` as two operations

For:

```asm
push eax
```

the conceptual sequence is:

```asm
ESP = ESP - 4
[ESP] = EAX
```

If `EAX = 0x12345678` and `ESP = 0x4000`, then:

```text
ESP      = 0x3FFC
[0x3FFC] = 0x12345678
```

The stack grows toward lower addresses on 32-bit x86.

## `RET` as a programmable jump

For:

```asm
ret
```

the useful model is:

```asm
EIP = [ESP]
ESP = ESP + 4
```

Suppose:

```text
ESP = 0x2000
0x2000 -> 0x401000
0x2004 -> 0xDEADBEEF
```

After `ret`:

```text
EIP = 0x401000
ESP = 0x2004
```

The expression `EIP = [0x401000]` would be a second dereference and is not what `RET` does. `RET` reads one DWORD from the address currently held in `ESP`.

## `push eax; ret`

Starting with `EAX = 0x12345678` and `ESP = 0x4000`:

```asm
push eax       ; ESP=0x3FFC, [ESP]=0x12345678
ret            ; EIP=[ESP], ESP=ESP+4
```

The final state is:

```text
EIP = 0x12345678
ESP = 0x4000
```

For ROP reasoning, this behaves like an indirect jump through `EAX`, with temporary stack use.

## `CALL` does not push EBP

The confusion between `CALL` and a function prologue was explicitly corrected.

`CALL target` does two relevant things:

```text
push address of the next instruction
EIP = target
```

It does not push `EBP`. A callee may later begin with:

```asm
push ebp
mov  ebp, esp
```

That prologue is separate from `CALL`.

## One thread, one stack

Functions do not receive private stacks when called. A thread owns one stack region. `ESP` moves through that region as callers push arguments, `CALL` pushes a return address, and callees allocate locals.

The code address can jump from one module to another while the stack remains the same thread-owned memory.

```text
caller code  -> callee code -> API code
       \          |             /
        \---------same stack---/
```

The callee finds its arguments through the current `ESP`/`EBP` convention, not because the arguments were copied into the callee's code section.

## Stack reservation and commitment

Windows commonly reserves a larger virtual range for a thread stack than is initially committed. Pages are committed as the stack approaches a guard page. This makes ordinary growth cheap while preserving a finite bound.

Repeated pushes or recursion can eventually cross the reserved region and produce a stack-overflow exception. The stack is not infinite, and it is not necessarily physically committed in its entirety at process start.

## Overflow as ordinary memory writes

A local array and a saved return address are both bytes in memory. The CPU does not mark one as “buffer” and another as “return address.” If a copy writes beyond the array, the sequential bytes can overwrite saved state, including the return address.

Once control reaches an exploit-controlled address, the original function is no longer expected to unwind normally. The bytes after the EIP offset become controlled workspace for a ROP chain, call frame, and payload.

## Exercises preserved

### Exercise 1

Given `ESP=0x2000`, memory values `0x11111111`, `0x22222222`, `0x33333333`, identify `ESP`, `[ESP]`, `[ESP+4]`, and the state after one `RET`.

### Exercise 2

Given `ESP=0x3000` and `0xAAAAAAAA` at `[ESP]`, execute `POP EAX` and report `EAX`, `ESP`, and `[ESP]`.

### Exercise 3

Given `EAX=0x12345678`, `ESP=0x4000`, execute `PUSH EAX; RET` and report final `EIP` and `ESP`.

## Durable conclusions

1. A register is not the memory it points to.
2. Brackets mean dereference.
3. `POP` reads then advances; `PUSH` decrements then writes.
4. `RET` loads `EIP` from `[ESP]` and advances `ESP`.
5. `CALL` supplies a return address; the callee supplies its own prologue.
6. ROP works on one continuous thread stack.
