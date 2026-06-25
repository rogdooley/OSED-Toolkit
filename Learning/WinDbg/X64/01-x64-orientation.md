# Module 01 — x64 Orientation

## Registers

x64 extends all eight x86 general-purpose registers to 64 bits and adds eight
more:

| x86 | x64 (low 32) | x64 full 64 | Purpose |
|---|---|---|---|
| eax | eax | rax | accumulator / return value |
| ebx | ebx | rbx | callee-saved |
| ecx | ecx | rcx | arg 1 (x64) |
| edx | edx | rdx | arg 2 (x64) |
| esi | esi | rsi | callee-saved |
| edi | edi | rdi | callee-saved |
| ebp | ebp | rbp | frame pointer (optional) |
| esp | esp | rsp | stack pointer |
| — | r8d | r8 | arg 3 (x64) |
| — | r9d | r9 | arg 4 (x64) |
| — | r10d | r10 | caller-saved |
| — | r11d | r11 | caller-saved |
| — | r12d | r12 | callee-saved |
| — | r13d | r13 | callee-saved |
| — | r14d | r14 | callee-saved |
| — | r15d | r15 | callee-saved |

Writing to `eax` in a 64-bit context zeroes the upper 32 bits of `rax`.
Writing to `ax` or `al` does not zero the upper bits (potential for stale
data bugs).

---

## The x64 calling convention (Microsoft ABI)

x86 cdecl: all arguments on the stack, caller cleans up.

x64 Windows ABI:
- First 4 integer/pointer args: `rcx`, `rdx`, `r8`, `r9` (left to right)
- Floating-point args 1–4: `xmm0–xmm3`
- Args 5+: on the stack (right to left, same as cdecl from there)
- **Shadow space**: caller allocates 32 bytes (4 slots × 8 bytes) of "home
  space" above the return address, even if the callee has only 0–4 args. The
  callee may use these slots to spill register args.
- Return value: `rax` (integer/pointer), `xmm0` (float/double)
- Stack alignment: 16-byte aligned at the point of the `call` instruction

**No `push` arguments:** for the first four args, no push. Just set the
register. For args 5+: `mov [rsp+0x28], arg5` (past the shadow space).

---

## Reading the stack in x64

x86:

```
[esp + 0]   return address
[esp + 4]   arg1
[esp + 8]   arg2
```

x64 (at the call instruction entry, before prologue):

```
[rsp + 0]   return address
[rsp + 8]   shadow space slot 0 (callee may write rcx here)
[rsp + 0x10] shadow space slot 1
[rsp + 0x18] shadow space slot 2
[rsp + 0x20] shadow space slot 3
[rsp + 0x28] arg5 (if exists)
```

Args 1–4 are in registers, not on the stack — unless the callee spills them
into the shadow space. When stepping through a callee, the shadow space slots
may contain the original register values of rcx/rdx/r8/r9 (or garbage if
the callee didn't spill).

---

## WinDbg commands: x64 vs x86

Most commands are identical. A few differences:

| Task | x86 | x64 |
|---|---|---|
| Read register | `r eax` | `r rax` |
| Read stack | `dd esp L10` | `dq rsp L10` (64-bit = `dq`) |
| Read DWORD | `dd addr L1` | `dd addr L1` (still valid) |
| Read QWORD | n/a | `dq addr L1` |
| Follow pointer | `poi(addr)` | `poi(addr)` (works for 8-byte ptrs too) |
| Show regs | `r` | `r` (shows 64-bit values) |

`dq` = display QWORDs (8 bytes each). Use `dq` anywhere you would use `dd`
in x86 when reading pointer-sized values in x64.

---

## Exercise: x64 function call inspection

Launch a 64-bit process in WinDbg. Any will do: `notepad.exe`, `calc.exe`,
or a custom target.

Break on any function and run:

```
0:000> r
0:000> dq rsp L8
0:000> k
```

Observe:
- `rip` instead of `eip`
- `rsp` instead of `esp`
- Register values are 16 hex digits (64 bits)

Look for the shadow space above the return address. If you break at the
function entry before the prologue, `[rsp+8]` through `[rsp+0x20]` are the
four shadow space slots. The callee has not written to them yet; they hold
garbage from the caller's stack.

---

## Calling convention proof

Break at the entry of any Windows API function that takes known arguments
(e.g., `bp kernel32!CreateFileW`). When it fires, the first argument is in
`rcx`:

```
0:000> r rcx
0:000> du @rcx        ; if it's a filename pointer
```

The second arg is in `rdx`, third in `r8`, fourth in `r9`.

The argument in `rcx` is the filename string. `du` reads a Unicode string at
that address.

---

## No pushad/popad in x64

x86 has `pushad` (push all 8 general-purpose registers) and `popad` (pop
them all). These don't exist in x64. Shellcode for x64 must save and restore
registers individually:

```asm
; x64 equivalent of pushad (manually):
push rbx
push rsi
push rdi
push r12
push r13
push r14
push r15
```

This affects shellcode design: x64 shellcode tends to be more verbose in its
register save/restore sections.

---

## Checkpoint

1. On x64, where does the first argument to a function go?
2. What is shadow space and who allocates it?
3. `dq rsp L4` — what does this show?
4. Why doesn't x64 have `pushad`/`popad`?
5. You see `mov [rsp+0x28], rcx` in a function. What is being stored?
