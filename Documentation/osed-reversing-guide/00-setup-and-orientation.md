# Chapter 0 — Setup and Orientation

## 1. Objective

After this chapter you will understand *what kind of object* an x86 Windows binary
is, what IDA Pro and WinDbg each show you, and why reverse engineering is a loop
between a **static** model (what the code *could* do) and a **dynamic** model
(what it *did* do on one run). You will also know the vocabulary the rest of the
guide assumes.

## 2. Background

A compiled program is the *result* of a translation, and translation is lossy.
The C you wrote had variable names, types, comments, and structure. The compiler
threw almost all of that away and emitted a stream of x86 instructions plus a few
tables the loader needs. Reverse engineering is the attempt to run that
translation backwards: from instructions, recover *intent*.

Two facts make this possible at all:

- **The CPU is deterministic and simple.** Each instruction does one well-defined
  thing. There is no hidden behavior. If you know the state before an instruction,
  you know the state after.
- **The compiler is systematic.** It does not invent a new way to call a function
  every time. It follows an ABI (Application Binary Interface) and a small set of
  code-generation patterns. Once you know the patterns, the noise separates from
  the logic.

The thing that makes it *hard* is that the compiler optimizes for the machine,
not for you. It reorders code, reuses registers, folds constants, turns
multiplication into shifts, and deletes variables that only existed for your
convenience. So the mapping from assembly back to C is many-to-one, and your job
is to find *a* correct source, not *the* original one.

### What a Win32 x86 binary actually is

For OSED you are almost always looking at a 32-bit (x86) Windows PE file — an
`.exe` or `.dll`. Key properties that shape everything downstream:

- **32-bit flat address space.** Pointers are 4 bytes. A "word" in x86 tradition
  is 16 bits, a "dword" is 32 bits, a "qword" is 64 bits — this terminology is
  baked into instruction names (`movsd` = move dword) and never changes.
- **Little-endian.** The dword `0x41424344` is stored in memory as the bytes
  `44 43 42 41`. This matters constantly when you read a stack dump: the bytes are
  "backwards" relative to how you write the number.
- **Stack grows down.** `push` *decreases* ESP. Higher addresses are older data.
  This one fact is the source of most confusion for newcomers, so it gets its own
  chapter.

## 3. Mental model

Hold two pictures side by side:

```
   STATIC MODEL (IDA)                     DYNAMIC MODEL (WinDbg)
   "everything the code could do"         "what the code did this run"

   +---------------------------+          +---------------------------+
   |  disassembly, xrefs,      |          |  live registers,          |
   |  call graph, string list, |   <--->  |  actual memory contents,  |
   |  every branch present     |          |  ONE path through branches|
   +---------------------------+          +---------------------------+
        reason about it                        observe it
```

Static analysis sees *all* branches but knows the value of *none* of them. Dynamic
analysis knows every value but only along the single path this particular input
drove. Neither alone is enough:

- Static alone: you can misjudge which branch is taken, or miss that a register
  holds attacker data because you can't see the value.
- Dynamic alone: you see numbers but not *why*; you can't tell which of them you
  control or what an unexercised branch would do.

**The loop:** form a hypothesis statically → set a breakpoint and check it in
WinDbg → the observed values sharpen your static reading → repeat. Every serious
finding in this guide is produced by that loop.

## 4. Assembly examples

You don't need to fully parse this yet — it's a first look so the shapes are
familiar when they return with explanations.

```asm
sub_401000 proc near                 ; a function IDA auto-named by its address
    push    ebp                      ; prologue: save caller's frame pointer
    mov     ebp, esp                 ; establish our frame pointer
    sub     esp, 40h                 ; reserve 0x40 bytes for locals
    mov     eax, [ebp+8]             ; read the first argument
    ...
    mov     esp, ebp                 ; epilogue: discard locals
    pop     ebp                      ; restore caller's frame pointer
    retn                             ; return to caller
sub_401000 endp
```

Three things to notice now, to be explained later:

- `sub_401000` is **not** a name from the program. IDA invented it from the
  address `0x401000`. A `sub_` or `loc_` prefix means "the tool guessed."
- The `push ebp / mov ebp, esp / sub esp, N` opening is a **prologue** — a
  fingerprint of "a function starts here." You will learn to see it as one unit.
- `[ebp+8]` is memory *at* the address `ebp+8`, not the register. Brackets are
  dereference.

## 5. Equivalent C

The skeleton above is roughly:

```c
int sub_401000(int arg1 /* , ... */) {
    char locals[0x40];
    // ... body ...
    return /* eax */;
}
```

We can't name `arg1` or type it precisely yet — that's what later chapters teach.
The point here is that the *frame* (arguments above EBP, locals below it) is
recoverable structure, not noise.

## 6. Reverse engineering methodology

A first-pass triage procedure you will refine as the guide continues:

1. **Load and let IDA finish its auto-analysis.** Don't touch anything until the
   progress bar stops.
2. **Find the entry points that matter.** For a target with input, that's usually
   a network handler, a file parser, or a command dispatcher — not `main`. Use the
   Strings window (`Shift+F12`) and Imports to find where input is read
   (`recv`, `ReadFile`, `fread`) and work outward.
3. **Read at the function granularity.** Pick one function. Identify its prologue,
   its arguments, its locals, its calls, and its return. Write a one-line summary
   of what it does before moving on.
4. **Build the call graph in your head (or with IDA's).** Which function feeds
   which? Where does input flow?
5. **Drop into WinDbg to confirm anything you're unsure of.** Break on the
   function, dump the arguments, single-step the confusing part.

## 7. Common compiler idioms

The single most important idiom to internalize on day one: **the standard
frame-pointer prologue/epilogue.** MSVC debug (`/Od`) builds emit it almost
universally:

```asm
push    ebp
mov     ebp, esp
sub     esp, <size>
...
mov     esp, ebp        ; or: add esp, <size>  /  leave
pop     ebp
retn
```

When you see it, you have found a function boundary and an EBP-based frame. When
it's *absent* (optimized code, `/O2`), the function uses ESP-relative addressing
and you fall back to Chapter 11's techniques.

## 8. Common mistakes

- **Trusting IDA's auto-names as facts.** `sub_401000`, `loc_40105A`,
  `dword_40A000` are addresses in disguise. They carry zero semantic information.
- **Reading top to bottom like C.** Assembly is a graph, not a script. Follow
  the jumps.
- **Confusing a register with the memory it points to.** `eax` vs `[eax]` is the
  difference between a pointer and the thing it points to — the most common
  beginner error, and it silently corrupts your whole reading.
- **Believing the debugger's one run is the whole story.** The path you observed
  is input-dependent. A different input takes a different branch.

## 9. Exercises

1. In your own words, why can two *different* C functions compile to *identical*
   assembly? Give one concrete example (hint: unused variables, or `a*2` vs
   `a+a`).
2. The dword `0xDEADBEEF` is written to memory at address `0x0018FF00`. List the
   four bytes in address order `0x0018FF00..0x0018FF03`. (Answer by applying
   little-endian, not memorization.)
3. Open any small Win32 exe in IDA. Find one function. Identify its prologue and
   its epilogue by shape alone, without reading the body.

## 10. Summary

- A binary is a lossy translation; RE runs the translation backwards to recover
  intent, not the exact original source.
- x86 Win32 is 32-bit, little-endian, stack-grows-down. These three facts underlie
  everything.
- IDA gives you the static model (all branches, no values); WinDbg gives the
  dynamic model (all values, one path). Real analysis loops between them.
- Auto-generated names are addresses, not meaning. Derive meaning from
  instructions.
- The frame-pointer prologue/epilogue is your first and most reliable landmark.
