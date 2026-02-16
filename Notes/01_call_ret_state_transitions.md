Good. Below is a diagram-focused, state-transition document.
This is designed to make CALL/RET and stack pivots visually mechanical.

Drop this into:

OSED-Notes/01_call_ret_state_transitions.md

⸻

# OSED Notes — CALL / RET State Transitions (Before / After)

This document focuses purely on **mechanical register and memory transitions**.

No debugger noise.
No exploit payload discussion.
Just CPU state changes.

---

# 1. PUSH — Before / After

## Initial State

Registers:

ESP = 0x1000

Memory:

0x1000 → ????
0x0FFC → ????

---

## Instruction

push 0x41414141

---

## After Execution

Registers:

ESP = 0x0FFC

Memory:

0x0FFC → 41414141 ← ESP
0x1000 → ????

Transition rule:

ESP = ESP - 4
[ESP] = value

---

# 2. POP — Before / After

## Initial State

Registers:

ESP = 0x0FFC

Memory:

0x0FFC → 41414141
0x1000 → 42424242

---

## Instruction

pop eax

---

## After Execution

Registers:

EAX = 41414141
ESP = 0x1000

Memory unchanged:

0x0FFC → 41414141
0x1000 → 42424242

Transition rule:

reg = [ESP]
ESP = ESP + 4

---

# 3. CALL — Before / After

Code:

00401000 call 00402000
00401005 mov eax, 1

## Initial State

Registers:

EIP = 00401000
ESP = 0x2000

Memory:

0x2000 → ????
0x1FFC → ????

---

## CALL Executes

### Step 1 — Push Return Address

Return address = `00401005`

ESP = 0x1FFC
[0x1FFC] = 00401005

### Step 2 — Jump

EIP = 00402000

---

## After CALL

Registers:

EIP = 00402000
ESP = 0x1FFC

Memory:

0x1FFC → 00401005 ← return address
0x2000 → ????

Transition rule:

push next_instruction
EIP = target

---

# 4. RET — Before / After

## Initial State (inside function)

Registers:

EIP = 00402050
ESP = 0x1FFC

Memory:

0x1FFC → 00401005 ← return address

---

## Instruction

ret

---

## After Execution

EIP = 00401005
ESP = 0x2000

Transition rule:

EIP = [ESP]
ESP = ESP + 4

RET is literally:

pop eip

---

# 5. Full Function Frame (Visual Layout)

After:

push ebp
mov ebp, esp
sub esp, 0x20

Assume:

EBP = 0x1000

Memory:

Higher addresses

0x1004 → Return Address
0x1000 → Saved EBP

0x0FE0 → Local buffer start

Lower addresses

Key offsets:

[EBP] → saved EBP
[EBP+4] → return address
[EBP-4] → first local

---

# 6. Overflow Transition (Critical)

Assume:

buffer[32]

Buffer range:

0x0FE0 → 0x0FFF

If 40 bytes written:

| Bytes Written | Overwrites     |
| ------------- | -------------- |
| 0–31          | buffer         |
| 32–35         | saved EBP      |
| 36–39         | return address |

Before RET:

[EBP+4] = 42424242

After RET:

EIP = 42424242

Control achieved.

---

# 7. JMP ESP Redirection

If:

[EBP+4] = 625011AF

And:

625011AF → FF E4 → jmp esp

Then execution:

ret → EIP = 625011AF
jmp esp → EIP = ESP

Since ESP points into buffer:

EIP → attacker-controlled memory

---

# 8. Complete Exploit Transition Timeline

### Step 1 — CALL

Return address pushed
EIP → function

### Step 2 — Overflow

Return address overwritten

### Step 3 — RET

EIP = overwritten value

### Step 4 — JMP ESP

EIP = ESP

### Step 5 — Execute shellcode

Stack memory executed

---

# 9. Stack Pivot (Preview)

Normal RET:

EIP = [ESP]
ESP += 4

If we change ESP first (pivot):

ESP = attacker_controlled_location
ret

Now:

EIP = [attacker_location]

Stack pivot lets you:

- Relocate execution stack
- Build fake stack frames
- Launch ROP chains

---

# Core Mechanical Truth

Everything reduces to:

- Stack pointer arithmetic
- Memory dereferencing
- Instruction pointer reassignment

There is no special logic in CALL/RET.

Just:

push
pop
jump
