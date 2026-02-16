# OSED Notes — JMP ESP and Execution Redirection

This document focuses on how execution is redirected to attacker-controlled stack memory.

---

# 1. The Core Problem

After overwriting the return address:

[EBP+4] = attacker_value

When `ret` executes:

EIP = attacker_value

But:

- Stack addresses change between runs.
- We cannot hardcode the exact stack location reliably.

So we need an intermediate redirection.

---

# 2. The JMP ESP Strategy

We overwrite the return address with the address of:

jmp esp

Opcode for `jmp esp` (x86):

FF E4

If located at:

0x625011AF

We overwrite return address with:

0x625011AF

(little-endian: `\xAF\x11\x50\x62`)

---

# 3. Execution Timeline

## Step 1 — RET

EIP = 625011AF

## Step 2 — Execute `jmp esp`

Instruction:

jmp esp

Effect:

EIP = ESP

Now execution moves to wherever ESP points.

---

# 4. Why ESP Works

Immediately after RET:

ESP → first byte after overwritten return address

That location is fully attacker-controlled.

Example payload layout:

“A” \* offset

After RET:

ESP → NOP sled

After JMP ESP:

EIP → NOP sled

Execution continues into shellcode.

---

# 5. Why We Don't Jump Directly to Stack

Stack addresses:

- Vary per execution
- May shift slightly
- Cannot be reliably predicted

But:

- Module addresses (without ASLR) are stable.

So we:

1. Jump to fixed module address.
2. That instruction redirects dynamically to ESP.

---

# 6. Finding JMP ESP

Search for opcode:

FF E4

Inside a module:

- Without ASLR
- With executable permissions
- No bad chars in its address

Example:

625011AF ffe4 jmp esp

---

# 7. Why Little-Endian Matters

Address:

0x625011AF

Must be written as:

AF 11 50 62

Because x86 is little-endian.

---

# 8. Full Redirection Chain

ret
↓
EIP = jmp_esp_address
↓
jmp esp
↓
EIP = ESP
↓
Execute NOP sled
↓
Execute shellcode

Everything is:

- Stack dereference
- Register reassignment
- Direct jump

No hidden behavior.

---

# 9. Alternative Redirection Gadgets

Other useful instructions:

| Instruction         | Opcode | Use                    |
| ------------------- | ------ | ---------------------- |
| `call esp`          | FF D4  | Similar to jmp esp     |
| `jmp eax`           | FF E0  | When eax holds pointer |
| `push esp; ret`     | 54 C3  | Manual redirection     |
| `mov esp, eax; ret` | pivot  | Stack pivot            |

All are variations of redirecting execution flow.

---

# 10. Mental Model

You are not "executing shellcode directly."

You are building a chain of:

1. Return address overwrite
2. Controlled jump
3. Stack-based execution

Exploit development is controlled redirection of EIP.

---

# 11. Key Concept

The stack is not special memory.

If execution is redirected there, it behaves like any executable region (assuming DEP is not blocking it).

JMP ESP is simply a reliable bridge from fixed memory to dynamic stack memory.
