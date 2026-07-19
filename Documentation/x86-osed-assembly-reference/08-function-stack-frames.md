# 8. Function Stack Frames

## Standard Prologue

```asm
push ebp              ; save caller's frame pointer
mov ebp, esp          ; establish this function's frame pointer
sub esp, 0x40         ; allocate 64 bytes for local variables
```

## Standard Epilogue

```asm
mov esp, ebp          ; deallocate locals (restore ESP to frame pointer)
pop ebp               ; restore caller's frame pointer
ret                   ; return to caller
```

Or equivalently:

```asm
leave                 ; mov esp, ebp; pop ebp
ret
```

## Frame Layout

```
Higher addresses (toward stack base)
+-------------------+
| ...               |
| arg2              |  [EBP+0x0C]
| arg1              |  [EBP+0x08]
| return address    |  [EBP+0x04]  <-- pushed by CALL
| saved EBP         |  [EBP+0x00]  <-- pushed by prologue
| local var 1       |  [EBP-0x04]
| local var 2       |  [EBP-0x08]
| ...               |
| local buffer      |  [EBP-0x40]
+-------------------+  <-- ESP (after sub esp, N)
Lower addresses (toward stack limit)
```

Arguments are at positive EBP offsets (+0x08, +0x0C, ...). The gap at +0x04
is the return address. Locals are at negative EBP offsets.

## Frame-Pointer Omission (FPO)

Optimized builds may not use EBP as a frame pointer. Instead:

- EBP is used as a general-purpose register
- All locals and arguments are accessed via ESP-relative offsets
- The frame is harder to read because ESP changes throughout the function
  (every `push`/`pop`/`call` shifts all offsets)

IDA handles FPO by tracking ESP at each instruction. WinDbg's `k` command
may need symbols or `.frame` to reconstruct the call stack in FPO code.

## Inlined Functions

Small functions may be inlined by the compiler -- their code is inserted
directly into the caller, with no `call`/`ret` overhead. There is no stack
frame for an inlined function.

## Tail Calls

When a function's last action is calling another function and returning the
result, the compiler may replace `call target; ret` with `jmp target`. The
callee reuses the caller's return address. This looks like a `jmp` to another
function at the end of a function body.
