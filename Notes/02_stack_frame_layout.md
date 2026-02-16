Below are the two requested Markdown documents, clean and diagram-focused.

⸻

02_stack_frame_layout.md

# OSED Notes — Stack Frame Layout (x86, 32-bit)

This document focuses strictly on how a function’s stack frame is structured in memory.

No exploit steps.
No debugger commands.
Just layout and offsets.

---

# 1. Function Prologue

Typical compiled function (cdecl/stdcall style):

push ebp
mov ebp, esp
sub esp, 0x20

We will analyze this mechanically.

---

# 2. Before Function Is Called

Caller state:

Registers:

ESP = 0x2000
EIP =

After CALL executes:

ESP = 0x1FFC
[0x1FFC] = return_address
EIP = function_address

Stack now contains:

0x1FFC → return address

---

# 3. After `push ebp`

ESP = ESP - 4
[ESP] = old EBP

If ESP was `0x1FFC`, now:

ESP = 0x1FF8
[0x1FF8] = old EBP

Stack:

0x1FF8 → saved EBP
0x1FFC → return address

---

# 4. After `mov ebp, esp`

EBP = ESP

So:

EBP = 0x1FF8

Now:

[EBP] → saved EBP
[EBP+4] → return address

This relationship is critical.

---

# 5. After `sub esp, 0x20`

Allocate 32 bytes of local storage.

ESP = ESP - 0x20

If ESP was `0x1FF8`, now:

ESP = 0x1FD8

Final layout:

Higher memory addresses

0x1FFC → Return Address [EBP+4]
0x1FF8 → Saved EBP [EBP]

0x1FD8 → Local Variables

Lower memory addresses

---

# 6. Visual Memory Diagram

Assume:

EBP = 0x1000

Layout becomes:

Address Meaning

0x1004 Return Address
0x1000 Saved EBP
0x0FE0 Local Buffer (32 bytes)

Local variables exist at:

[EBP - 4]
[EBP - 8]
…

---

# 7. Accessing Data via EBP

Inside function:

[EBP+4] → return address
[EBP+8] → first function argument
[EBP-4] → first local variable

Why use EBP?

Because ESP moves during pushes/pops.
EBP remains stable for referencing locals and arguments.

---

# 8. Overflow Direction

Stack grows downward.

So local buffer at:

0x0FE0 → 0x0FFF

If overflow writes beyond 0x0FFF:

Next overwritten areas:

0x1000 → saved EBP
0x1004 → return address

Order of corruption:

1. Local variables
2. Saved EBP
3. Return address

---

# 9. Why Saved EBP Exists

Saved EBP allows:

mov esp, ebp
pop ebp
ret

to restore caller’s stack frame cleanly.

If saved EBP is corrupted:

- Stack unwinding breaks
- But control of EIP comes from return address overwrite

---

# 10. Mechanical Summary

Stack frame consists of:

| Offset       | Meaning         |
| ------------ | --------------- |
| `[EBP+4]`    | Return Address  |
| `[EBP]`      | Saved EBP       |
| `[EBP-4...]` | Local Variables |

Understanding this layout allows you to:

- Calculate offset to EIP
- Predict overwrite order
- Identify injection boundaries

⸻
