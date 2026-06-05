# Exercise 03 — Pointers and Dereferences

## The question

You see an address on the stack or in a register. You need to follow it. How
many levels of indirection are there, and what is at each level?

This is the core mechanic of reading Windows structures: every interesting
data structure is reached by following a chain of pointers. If you cannot
follow a chain mechanically in the debugger, every later module will stall.

---

## Setup

```
windbgx -o stack_lab_x86.exe HelloWorld
```

Break on `run_and_print`:

```
0:000> bp stack_lab_x86!run_and_print
0:000> g
```

---

## Part A — Following `argv`

### Step A.1 — What is `argv`?

In `main`, `argv` is a `char **` — a pointer to an array of `char *` pointers,
each of which points to a null-terminated string.

The chain:

```
argv ──► argv[0] ──► "stack_lab_x86.exe\0"
         argv[1] ──► "HelloWorld\0"
         argv[2] ──► NULL (sentinel)
```

Every `──►` is a dereference.

### Step A.2 — Find `argv` in `main`

Break on `main`:

```
0:000> bp stack_lab_x86!main
0:000> g
```

Step past the prologue (two `p`s). Now `argv` is at `[ebp+0x0c]` (second
argument, after `argc` at `[ebp+0x08]`).

Read `argv`:

```
0:000> dd ebp+0x0c L1
```

Call that value `ARGV_PTR`.

### Step A.3 — First level: array of pointers

```
0:000> dd ARGV_PTR L4
```

You should see four DWORDs. Each DWORD is a pointer to one argument string.
`argv[0]`, `argv[1]`, `argv[2]`, `argv[3]` — and `argv[4]` should be `0`
(the null sentinel).

### Step A.4 — Second level: the strings

Follow `argv[1]` (second DWORD in the array):

```
0:000> db poi(ARGV_PTR + 4) L20
```

`poi(X)` dereferences X as a pointer: it reads the DWORD at address X and
returns that value as an address. `poi(ARGV_PTR + 4)` = value at `[argv + 4]`
= pointer to the second string = address of `"HelloWorld"`.

Confirm you see `HelloWorld` in ASCII.

### Step A.5 — The `poi()` idiom

`poi` is WinDbg's dereference operator in expressions. The equivalent
manual approach is `dd ADDR L1` to read the pointer value, then `db VALUE` to
follow it. `poi` chains both steps:

```
; Manual two-step:
0:000> dd ARGV_PTR+4 L1      ; shows: 00401234 (hypothetically)
0:000> db 00401234 L20       ; shows the string

; Equivalent with poi:
0:000> db poi(ARGV_PTR+4) L20
```

For multiple levels:

```
0:000> db poi(poi(ARGV_PTR + 4)) L10     ; follow pointer-to-pointer
```

---

## Part B — The `BufferStats` struct pointer chain

### Step B.1 — Find the struct in `run_and_print`

`run_and_print` allocates `BufferStats result` on its stack and passes a
pointer to it as a hidden argument to `process_buffer`. Find it:

```
0:000> bp stack_lab_x86!run_and_print
0:000> g
0:000> uf eip
```

Look for the `lea` instruction before the call to `process_buffer`. The `lea`
computes the address of `result` on `run_and_print`'s stack and pushes it.
Note the offset — call it `RESULT_OFFSET`. `result` lives at
`[run_and_print_ebp - RESULT_OFFSET]`.

### Step B.2 — Read the raw struct bytes

Step to after `process_buffer` returns (break on the instruction after the
`call process_buffer`). The struct is now filled.

```
0:000> dd ebp-RESULT_OFFSET L4
```

You should see four DWORDs. Map them to the struct definition:

```c
typedef struct {
    int  length;      // [ebp - RESULT_OFFSET + 0x00]
    char first_char;  // [ebp - RESULT_OFFSET + 0x04]  (1 byte in 4-byte slot)
    char last_char;   // [ebp - RESULT_OFFSET + 0x08]  (1 byte in 4-byte slot)
    int  checksum;    // [ebp - RESULT_OFFSET + 0x0c]
} BufferStats;
```

(Char fields are padded to 4 bytes by the compiler in this configuration.
The actual padding depends on `#pragma pack` and the struct field alignment.)

Verify each field matches the program output you observed.

### Step B.3 — Reading a struct with `dt` and `dp`

WinDbg can display typed structures if you have matching symbols (PDB file).
For production binaries you usually won't. But for ntdll and kernel32 (which
always have public symbols loaded), `dt` is enormously useful:

```
0:000> dt ntdll!_TEB
```

This prints the entire TEB layout with field names and offsets. Keep this
command in mind — Module 02 uses it constantly.

Without symbols, you read structs manually as DWORDs as you just did.

---

## Part C — Pointer arithmetic in `? ` expressions

### Step C.1 — Offset calculation

Given a base address and a field offset, compute the field address:

```
0:000> ? ebp - 0x8c          ; absolute address of buf[0] in process_buffer
0:000> ? ebp + 4              ; absolute address of return address slot
0:000> ? poi(ebp+8)           ; value of the first argument
```

### Step C.2 — Distance between two addresses

In exploit work you often need to know how many bytes separate two addresses:

```
0:000> ? address_A - address_B
```

For example, to find the distance from the start of a buffer to the saved
return address:

```
0:000> ? (ebp+4) - (ebp - 0x8c)
Evaluate expression: 144 = 00000090
```

That `0x90` = 144 bytes is the overflow offset for that hypothetical buffer.

---

## Checkpoint

Answer in your notes:

1. What does `poi(X)` do in a WinDbg expression?
2. `argv` is a `char **`. How many pointer dereferences to reach the string?
3. You see `dd ebp+0x0c L1` returns `0x00b5f900`. What is `0x00b5f900`?
4. How do you read a C struct at a known address without symbols?
5. Given the start of a buffer at `ebp-0x8c` and the saved return address at
   `ebp+4`, what is the minimum overflow length to reach the return address?

---

## Writeup prompt

Write a paragraph titled **"Following a pointer chain in WinDbg."** Use the
`argv → argv[1] → "HelloWorld"` chain as the example. Show the two-command
approach and the `poi()` shorthand. Do not look at these notes while writing.
