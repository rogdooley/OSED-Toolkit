# Preface and Study Method {.unnumbered}

This workbook is for the stage where assembly syntax is no longer the main
problem. You can read registers, stack references, addressing modes, calls, and
conditional jumps. The hard part is deciding what those facts mean.

An OSED-level reverse engineer is not trying to produce pretty C. The job is to
recover enough of the programmer's model to answer security questions:

- What did the programmer think this value represented?
- What did the compiler preserve, erase, or transform?
- Where does attacker-controlled data enter?
- Which checks make a value trusted?
- Which checks only protect a different object?
- What memory is read or written because of that value?
- What control-flow edge becomes reachable?

The difference matters. A decompiler may tell you a function calls `memcpy`.
That is not the answer. The answer is whether the destination, source, and count
form a valid relationship under all reachable inputs.

## Prerequisites

This workbook assumes you already have working knowledge of:

- **x86 register names and roles**: EAX through EDI, ESP, EBP, EIP, EFLAGS.
  You should know which registers are caller-saved vs. callee-saved in common
  calling conventions.

- **Addressing modes**: immediate (`mov eax, 42h`), register (`mov eax, ecx`),
  memory direct (`mov eax, [401000h]`), base+displacement (`mov eax, [ebp+8]`),
  base+index*scale+displacement (`mov eax, [ecx+edx*4+10h]`).

- **Basic WinDbg commands**: `bp` (set breakpoint), `g` (go/continue),
  `dd` (display dwords), `da` (display ASCII), `uf` (unassemble function),
  `p` (step over), `t` (step into), `r` (display registers).

- **IDA navigation**: ability to open a PE binary in IDA Free or IDA Pro,
  locate functions in the Functions window, follow cross-references with `x`,
  and read the disassembly listing.

If the register model or instruction syntax is still unfamiliar, work through
the `x86-osed-assembly-reference/` companion directory in this repository
before continuing. Chapters 01 through 06 of that reference cover the CPU
execution model, registers, memory operands, endianness, EFLAGS, and core
instructions.

## Tool setup

You need the following environment to work through this book and practice on
real binaries:

- **Windows 10 x86 VM**: a 32-bit Windows 10 installation or a 64-bit
  installation with WoW64. Snapshot it clean before installing target binaries.

- **WinDbg**: the classic WinDbg from the Windows SDK, or WinDbg Preview from
  the Microsoft Store. Either works. Configure your symbol path:
  `.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`

- **IDA Free 8.x or IDA Pro**: for static disassembly and cross-reference
  navigation. IDA Free handles 32-bit PE files. If you have IDA Pro, enable
  the Hex-Rays decompiler but treat its output as a hypothesis, not ground
  truth.

- **Python 3 with struct and socket**: for writing exploit scripts, packing
  addresses, and building network payloads. The `struct` module handles
  little-endian packing (`struct.pack('<I', addr)`). The `socket` module
  handles network delivery.

## How to work each chapter

Read each chapter in four passes.

First pass: skim the concept discussion and pattern list. Do not memorize the
patterns as signatures. Use them as expectations to test against evidence.

Second pass: read the annotated example with a notebook open. For every compare,
write the question being asked. For every memory operand, write whether it is a
read, write, address calculation, stack slot, structure field, array element, or
indirect control-flow source.

Third pass: do the exercise without looking at the solution. Do not write
pseudocode first. Fill out a fact ledger:

```text
Inputs:
Outputs:
Important reads:
Important writes:
Branch questions:
Validated ranges:
Compiler artifacts:
Programmer assumptions:
Exploit relevance:
Unresolved facts:
```

Fourth pass: compare your answer to the solution. If your pseudocode differs but
your facts match, that is usually acceptable. If your facts differ, fix the
reasoning before moving on.

**Exam note**: The OSED exam is a 48-hour proctored hands-on exam with no
internet access. You will not have time to look up instruction semantics, and
you will not have access to online references. The fact-ledger habit directly
supports exam-speed analysis -- if you can fill out a fact ledger quickly and
accurately from raw disassembly, you will spend less time on the reverse
engineering portions and more time on exploit development. Build this habit now.
Every chapter you work through with the ledger method is practice for the exam.

## Evidence levels

Not every conclusion has the same strength.

Strong evidence:

- A memory write destination and count.
- A call target and pushed arguments.
- A conditional jump tied to a specific `cmp` or `test`.
- A dereference proving a value is used as a pointer.
- An immediate size used as a copy bound or allocation size.
- A field offset used consistently across functions.

Medium evidence:

- A return convention such as `0` for success and `-1` for failure.
- A repeated offset suggesting a structure field.
- A string constant used near dispatch code.
- An import name such as `recv`, `send`, `malloc`, `free`, or `VirtualProtect`.

Weak evidence:

- A decompiler variable name.
- A guessed source-level type.
- A familiar-looking pattern without destination/count proof.
- A function name from an old symbol file or analyst comment.

The workbook solutions deliberately separate facts from hypotheses. Keep that
habit. It prevents the most common reverse engineering failure: explaining code
you have not actually proven.

## What to ignore first

Experienced reversers ignore aggressively, but they do it after classification.

Usually ignore on the first pass:

- standard frame setup and teardown
- callee-saved register preservation
- stack-cookie setup (`mov eax, ___security_cookie; xor eax, ebp; mov [ebp-4],
  eax` and the matching check before `retn`) until exploit impact is being
  considered (chapter 9 covers cookie patterns in detail)
- logging calls unless attacker data becomes a format string
- response formatting unless it leaks useful information
- import thunks once the API boundary is identified

Do not ignore:

- argument setup before calls
- copies into stack or heap buffers
- compare signedness
- length/capacity relationships
- indirect calls or jumps
- stores through attacker-influenced pointers
- exception registration in stack-corruption contexts

## How a reverse engineer thinks differently than a compiler

The compiler already solved a different problem: preserve program behavior while
obeying the ABI and optimization rules. It does not preserve source intent for
your convenience. It may remove variables, merge branches, reuse stack slots,
inline routines, tail-call handlers, or replace multiplication with `lea`.

The reverse engineer solves a semantic problem: identify the model that makes
the machine behavior coherent.

The exploit developer solves a narrower adversarial problem: identify where
attacker-controlled values violate the programmer's assumed invariants and turn
that violation into control, disclosure, or corruption.

Those mindsets overlap, but they are not identical. A reverse engineer may stop
after proving a parser accepts a record. An exploit developer keeps going until
they know whether a field controls a write size, write address, function pointer,
saved return address, SEH record, heap metadata, or ROP-relevant state.

## Print workflow

For each exercise page, cover the solution section. Write your answer in this
order:

```text
1. One-sentence purpose hypothesis.
2. Facts that support it.
3. Facts that weaken it.
4. Values that are attacker-controlled or unknown.
5. Pseudocode only after the above is complete.
```

If you cannot explain why the compiler emitted an instruction, mark it as
unresolved. Do not invent a source statement just to make the disassembly feel
complete.

## Suggested pace

Work through two chapters per week. Each chapter takes roughly 2-4 hours of
focused effort: one hour to read and annotate, one hour for the exercises
and challenge problems, and one to two hours of live WinDbg practice on
real binaries.

Interleave each chapter with hands-on sessions using the drill templates in
the `DRILLS/` directory. A productive weekly rhythm looks like:

- **Day 1**: Read and annotate the next chapter. Fill out fact ledgers for
  the annotated examples.
- **Day 2**: Work the exercises and challenge problems without looking at
  solutions.
- **Day 3**: Compare solutions, then pick a drill from `DRILLS/` and apply
  the chapter's concepts to a real binary.
- **Day 4**: Read and annotate the second chapter of the week.
- **Day 5**: Exercises and challenge problems for the second chapter.
- **Weekend**: Pick a fresh binary, apply the `DRILLS/function_analysis.md`
  or `DRILLS/reverse_engineering.md` template, and practice the fact-ledger
  workflow end-to-end.

At this pace, the 16-chapter workbook takes 8 weeks -- roughly aligned with
an OSED preparation cycle. Adjust based on your comfort with the material,
but do not skip the drill sessions. Reading assembly and analyzing assembly
are different skills; only practice under time pressure builds the second one.

## Key takeaways

- The goal is not to produce pretty C. The goal is to recover the programmer's
  model well enough to answer security questions about memory, control flow,
  and trust boundaries.

- Separate facts from hypotheses. A memory write destination is a fact. A
  guessed variable name is a hypothesis. Never confuse the two.

- The fact-ledger method is the primary analysis technique for the OSED exam,
  where you have no internet, no symbols, and limited time.

- Ignore compiler scaffolding (frame setup, register saves, cookie checks)
  on the first pass. Focus on argument setup, copies, comparisons, and
  indirect control flow.

- Build speed through repetition on real binaries, not by memorizing patterns
  in isolation.

## See also

- `x86-osed-assembly-reference/01-cpu-execution-model.md` through
  `06-core-instruction-reference.md` -- prerequisite instruction-level
  reference material
- `x86-osed-assembly-reference/23-ida-pro-reading-guide.md` -- IDA navigation
  and annotation conventions
- `x86-osed-assembly-reference/24-windbg-reading-guide.md` -- WinDbg command
  reference for dynamic analysis
- `x86-osed-assembly-reference/26-common-analyst-mistakes.md` -- pitfalls that
  the fact-ledger method is designed to prevent
- `osed-reversing-guide/00-setup-and-orientation.md` -- companion setup guide
  for the reversing methodology
- `DRILLS/function_analysis.md` -- drill template for single-function analysis
- `DRILLS/reverse_engineering.md` -- drill template for multi-function reversing
- `DRILLS/windbg_investigation.md` -- drill template for WinDbg-driven analysis
