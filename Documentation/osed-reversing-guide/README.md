# Reversing x86 Windows Binaries — A Study Guide

> A textbook for deriving program behavior from x86 assembly using IDA Pro and
> WinDbg, written for an experienced programmer preparing for OSED (EXP-301).

## How to use this guide

This is **not** a cheat sheet. The goal is to build the mental models that let
you *derive* what a binary does from its instructions, rather than pattern-match
against a table of "this looks like `strcpy`." Every conclusion in this guide is
justified from the instructions that produce it. When you finish, you should be
able to sit in front of an unknown x86 function in IDA and reason your way from
the disassembly to a correct C reconstruction, then confirm your reconstruction
in WinDbg.

Read the chapters in order the first time. Each chapter assumes the mental models
built in the previous ones. On later passes, jump to whichever chapter matches
the code in front of you.

### Chapter structure

Every chapter follows the same ten-part shape so you always know where to look:

1. **Objective** — what you will be able to do after the chapter.
2. **Background** — the hardware/ABI reality that makes the topic exist.
3. **Mental model** — the picture to hold in your head.
4. **Assembly examples** — real disassembly, annotated instruction by instruction.
5. **Equivalent C** — the source the compiler most plausibly started from.
6. **Reverse engineering methodology** — a repeatable procedure.
7. **Common compiler idioms** — the shapes MSVC emits so you recognize *structure*, not magic.
8. **Common mistakes** — where analysts go wrong, and why.
9. **Exercises** — derive-it-yourself problems (answers reason from instructions).
10. **Summary** — the load-bearing ideas to carry forward.

## The core discipline

Four rules govern everything here:

- **Derive, never assume.** A name is a hypothesis. `rep movsd` is evidence.
- **Reason before you recognize.** Recognition is a shortcut you earn *after* you
  can do the derivation. If you memorize the shortcut first, you will misread the
  first function that breaks the pattern — and exam binaries are built to break it.
- **Every instruction has a reason.** The compiler is not sloppy. If you cannot
  explain why an instruction is there, you have not finished analyzing.
- **Confirm in the debugger.** Static reasoning produces a hypothesis. WinDbg
  turns it into a fact. The two workflows are a loop, not a sequence.

## Chapters

| # | Chapter | Core question it answers |
|---|---------|--------------------------|
| 0 | [Setup and orientation](00-setup-and-orientation.md) | What am I looking at, and how do IDA and WinDbg fit together? |
| 1 | [The x86 register model](01-register-model.md) | What is each register *for*, and what does the CPU actually do per instruction? |
| 2 | [Memory, addressing modes, pointer arithmetic](02-memory-and-addressing.md) | How does `[base + index*scale + disp]` map to C pointer math? |
| 3 | [The stack and stack frames](03-stack-and-frames.md) | Where do arguments and locals live, and how do ESP and EBP track them? |
| 4 | [Calling conventions, prologues, epilogues](04-calling-conventions.md) | How do I recover a function's signature and locals from its frame? |
| 5 | [Reading loops](05-reading-loops.md) | How do I find the induction variable and rewrite a loop as C? |
| 6 | [Decision logic and switch recovery](06-decision-logic.md) | Is this a chain of `if`s, a decision tree, or a jump table? |
| 7 | [Data flow and attacker-controlled input](07-data-flow.md) | Where does input enter, and where can I influence execution? |
| 8 | [Structures, arrays, heap vs stack](08-aggregates-and-memory.md) | How do I recover a struct layout and tell heap from stack? |
| 9 | [Recognizing library behavior from implementation](09-library-idioms.md) | How do I prove a function is `memcpy`/`strlen`/`strcpy` without a name? |
| 10 | [Buffer sizes and overwrite offsets](10-buffers-and-offsets.md) | How do I derive the exact offset from input to a saved return address? |
| 11 | [Reading optimized code and MSVC idioms](11-optimized-code.md) | Why does `-O2` code look nothing like the source, and how do I read it anyway? |
| 12 | [IDA and WinDbg working loop](12-ida-windbg-loop.md) | How do I drive a real analysis end to end and verify it? |
| 13 | [Capstone: reasoning about an unknown function](13-worked-example.md) | Can I apply the whole method, start to finish, to one unknown function? |

## Companion playbook

- [How to Think While Reverse Engineering](how-to-think-while-reversing.md) — the
  running set of internal questions an experienced reverser asks while reading
  unfamiliar assembly. The chapters above teach *what* x86 constructs mean; this
  playbook teaches the *methodology* — the questions, the evidence bar, and the
  temperament. Reread it at the start of every hard target.

## Conventions used throughout

- Assembly is shown in **Intel syntax** (`dst, src`), matching IDA and WinDbg.
- Addresses use `0x` prefixes; hex without prefix appears only inside operands
  where the disassembler omits it.
- `[expr]` means "the memory at address `expr`." A register without brackets is
  the value in the register.
- C reconstructions are labeled *plausible source* — the compiler erased the
  original, and several sources can produce the same code. We reconstruct the
  simplest one consistent with the instructions.
- WinDbg command lines are prefixed with the `0:000>` prompt so they are easy to
  spot.

## Maintenance notes

This guide evolves with the course. Each chapter is a standalone file so new
material (new examples, a new optimization pattern, a course-specific module) can
be added without rewriting neighbors. When you learn something that corrects or
extends a chapter, edit that chapter and, if it changes the reading order, update
this index. Keep the ten-section shape — it is what makes the guide a textbook
instead of a pile of notes.
