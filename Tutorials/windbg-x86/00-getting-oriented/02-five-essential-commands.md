# Exercise 02 — Five Essential Commands

## The question

For each of the five commands below, state: what it answers, and give one
example of the wrong conclusion you would draw if you didn't use it.

- `r`
- `k`
- `u` / `ub`
- `db` / `dd` / `dps`
- `lm` / `!address`

Write your answers before reading on.

---

## Setup

Same target as Exercise 01: `hello_args_x86.exe alpha beta gamma` under
WinDbg. Break on `print_arg` — the function inside the binary that has two
arguments and a local buffer.

```
0:000> bp hello_args_x86!print_arg
0:000> g
```

---

## Command 1: `r` — Register state

`r` prints all general-purpose and segment registers. It answers: **what will
the next instruction operate on?**

At the entry of `print_arg`:

```
0:000> r
eax=00000000 ebx=00780000 ecx=003cfabc edx=01234567
esi=00000000 edi=00000000
eip=00401040 esp=003cf980 ebp=003cf9a0
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
```

Three things to notice every time you run `r`:

1. `eip` — where you are. If this is inside a DLL you didn't expect, something
   unusual is happening.
2. `esp` and `ebp` — where the current frame is. `esp` is the current stack
   top. `ebp` is (usually) the frame pointer.
3. `efl` (EFLAGS) — if you just ran a `cmp` or `test`, the flags tell you
   which branch the code is about to take.

**The wrong conclusion you would draw without `r`:** "I think I'm inside
`print_arg`" — but you're actually inside `add_numbers` which `print_arg`
called, because you pressed `p` one too many times.

---

## Command 2: `k` — Call stack

`k` prints the call chain: the sequence of return addresses on the stack that
describes how execution arrived at `eip`.

At the entry of `print_arg`:

```
0:000> k
 # ChildEBP RetAddr
00 003cf97c 00401090  hello_args_x86!print_arg
01 003cf9a0 00401020  hello_args_x86!main+0x50
02 003cf9c0 77ab8474  KERNEL32!BaseThreadInitThunk+0x24
03 003cf9dc 77ab8444  ntdll!__RtlUserThreadStart+0x2f
```

Row 00 is where you are. Row 01 is the return address of `print_arg` — the
instruction in `main` that will run when `print_arg` returns. Row 02 and 03
are the standard thread startup boilerplate.

`ChildEBP` is the saved `ebp` for each frame. The `RetAddr` is the saved
return address.

**Cross-check with `ub`:** The return address in row 01 (`main+0x50`) should
be the instruction *after* the `call print_arg` in `main`. Verify:

```
0:000> ub hello_args_x86!main+0x50 3
```

You should see a `call` instruction immediately before `main+0x50`.

**The wrong conclusion you would draw without `k`:** "I have no idea how
execution got here." That question is exactly what `k` answers in three
seconds.

---

## Command 3: `u` and `ub` — Disassembly

`u` disassembles forward from an address. `ub` disassembles backward.

Forward from `eip`:

```
0:000> u eip L10
```

Backward to see the call that brought you here:

```
0:000> ub eip
```

**Important difference:** `u` starts at the exact address you give it and
decodes forward, one instruction at a time, using instruction length. It is
always accurate. `ub` has to guess where instructions start when working
backward, because x86 has variable-length instructions. It can land on the
wrong byte boundary. If `ub` output looks garbled, try `ub <addr>-N` where N
is 1, 2, or 3 to shift the start.

**`uf` — disassemble an entire function:**

```
0:000> uf hello_args_x86!print_arg
```

This is the most useful version for reading a complete function. WinDbg
follows jumps and shows all branches.

**The wrong conclusion you would draw without `u`:** "I don't know what
instruction caused the crash." The crash address is `eip`. `u eip` shows you
the faulting instruction. You always know.

---

## Command 4: `db`, `dd`, `dps` — Memory reads

These display memory. They differ in how they format each unit:

- `db` — bytes (hex + ASCII sidebar). Best for strings and raw shellcode.
- `dd` — DWORDs (4 bytes, little-endian interpreted). Best for pointers
  and stack layout.
- `dps` — DWORDs + symbol lookup for each value. Best for the stack.

**Read the arguments to `print_arg`:**

Arguments are on the stack relative to `esp`. At the entry of a function
(before the prologue runs `mov ebp, esp`), the layout is:

```
[esp + 0x00]  return address
[esp + 0x04]  first argument  (index)
[esp + 0x08]  second argument (arg pointer)
```

```
0:000> dd esp L4
003cf980  00401090 00000000 003cf9bc ...
```

`00401090` — return address (verify it matches `main+0x50` from `k`).
`00000000` — first arg: `index = 0`.
`003cf9bc` — second arg: pointer to the arg string. Follow it:

```
0:000> db 003cf9bc
```

You should see the program name or `alpha` depending on which call you
intercepted.

**`dps` on the stack:**

```
0:000> dps esp L8
```

This is the most readable view for stack analysis. Each DWORD that happens to
be a known address gets a symbol label. Critical for quickly identifying which
stack slots hold return addresses vs data.

**The wrong conclusion you would draw without `db/dd`:** "I don't know what
argument was passed to this function." Two seconds with `dd esp L4` and you do.

---

## Command 5: `lm` and `!address` — Memory ownership

`lm` lists all loaded modules with their base addresses and sizes.
`!address <addr>` tells you what region a specific address belongs to and what
permissions it has.

```
0:000> lm
start    end      module name
00400000 00408000   hello_args_x86   C (export symbols)
77ab0000 77c20000   KERNEL32   (export symbols)
77d20000 77f10000   ntdll      (export symbols)
```

Now check an address you saw in the stack:

```
0:000> !address 00401090
...
Type             00020000MEM_IMAGE
State            00001000MEM_COMMIT
Protect          00000020PAGE_EXECUTE_READ
...
```

`PAGE_EXECUTE_READ` — this is code. It is readable and executable, but not
writable. An address with `PAGE_READWRITE` is data. An address with
`PAGE_EXECUTE_READWRITE` is suspicious (writable code — usually shellcode
staging).

**The two critical questions `lm` and `!address` answer for exploit work:**

1. Is this return address inside a module that will survive a reboot? (ASLR
   question — if the module base is randomized per boot, an absolute address
   won't work across reboots. If it's a non-ASLR module, it's reliable.)
2. Does my shellcode land in a page with execute permission? (DEP question.)

**The wrong conclusion you would draw without `!address`:** "I'll use
`0x77ab1234` as my return address — it worked yesterday." It won't work if the
module rebases on reboot. Check `lm` first.

---

## Checkpoint

In your notes, fill in this table:

| Command | Answers what question? | Classic mistake if skipped |
|---|---|---|
| `r` | | |
| `k` | | |
| `u` | | |
| `dd esp` | | |
| `lm` | | |

The table should be fillable without looking at these notes. If it isn't, run
through the exercise once more.

---

## Quick reference cheat sheet

```
r                         ; all registers
r eip                     ; single register
k                         ; call stack with frame pointers
kp                        ; call stack with parameters (if symbols)
u eip L10                 ; 16 instructions forward
ub eip                    ; ~8 instructions backward
uf <func>                 ; entire function disassembly
db <addr> L20             ; 32 bytes as hex+ASCII
dd <addr> L10             ; 16 DWORDs
dps esp L10               ; 16 DWORDs + symbol names
lm                        ; all modules
lm m kernel32             ; filter to one module
!address <addr>           ; region type, state, permissions
? <addr> - <addr>         ; arithmetic (e.g., distance between two addresses)
poi(<addr>)               ; dereference a pointer in an expression
```

These nine patterns cover 90% of what you will type in OSED scenarios.
