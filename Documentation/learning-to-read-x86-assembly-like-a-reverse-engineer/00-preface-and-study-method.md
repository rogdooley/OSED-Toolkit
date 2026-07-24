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

### How to work each chapter

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

### Evidence levels

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

### What to ignore first

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

### How a reverse engineer thinks differently than a compiler

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

### Print workflow

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

