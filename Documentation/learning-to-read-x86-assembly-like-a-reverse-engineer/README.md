 # Learning to Read x86 Assembly Like a Reverse Engineer

> A semantic recovery workbook for intermediate OSED students who already know
> x86 syntax, WinDbg, and IDA/Ghidra, but want to recover programmer intent from
> compiler-generated Windows x86 code.

This is not an assembly reference. The point is to learn how to read a function
as a set of questions the CPU is answering:

- What information enters this function?
- Where does it flow?
- What conditions decide execution?
- Which values are trusted, which are attacker-controlled, and which are only
  compiler scaffolding?
- What did the programmer likely believe was true?
- What assumptions did MSVC encode into the generated code?

Every exercise presents assembly first. Do not jump to pseudocode. Build a fact
ledger, identify what matters, ignore scaffolding, and only then write a source
level reconstruction.

## Table of contents

| # | Chapter | Core skill |
|---|---------|------------|
| 0 | [Preface and Study Method](00-preface-and-study-method.md) | How to use the workbook, grade evidence, and work assembly-first. |
| 1 | [Reading Assembly as Semantic Evidence](01-reading-assembly-as-semantic-evidence.md) | Stop translating instruction-by-instruction; start answering intent questions. |
| 2 | [Frames, Arguments, Locals, CALL, and RET](02-frames-arguments-locals-call-and-ret.md) | Recover function boundary, stack layout, arguments, locals, and cleanup rules. |
| 3 | [LEA, MOVSX, MOVZX, TEST, CMP, and SETcc](03-lea-movsx-movzx-test-cmp-and-setcc.md) | Read type hints, address arithmetic, flags, and boolean materialization. |
| 4 | [Branches, Conditions, and Nested Decisions](04-branches-conditions-and-nested-decisions.md) | Recover if, if/else, guard clauses, nested decisions, and signedness. |
| 5 | [Loops and Repeated Work](05-loops-and-repeated-work.md) | Recognize counters, sentinels, string scans, traversals, and loop invariants. |
| 6 | [Switches, Jump Tables, Tail Calls, and Thunks](06-switches-jump-tables-tail-calls-and-thunks.md) | Recover dispatcher logic and indirect control flow without overtrusting decompiler output. |
| 7 | [Data Flow: Pointers, Aliases, Stack, Heap, and Globals](07-data-flow-pointers-aliases-stack-heap-and-globals.md) | Track values through memory and distinguish storage class from trust. |
| 8 | [Structures, Arrays, Strings, and Buffer Semantics](08-structures-arrays-strings-and-buffer-semantics.md) | Recover object shape, indexing, field offsets, lengths, and terminators. |
| 9 | [MSVC Idioms and Runtime Artifacts](09-msvc-idioms-and-runtime-artifacts.md) | Recognize compiler/runtime patterns: copies, cookies, probing, SEH, imports, vtables. |
| 10 | [Methodology: From Unknown Function to Working Model](10-methodology-from-unknown-function-to-working-model.md) | Build a repeatable reverse engineering workflow centered on evidence. |
| 11 | [Exploit-Oriented Reading](11-exploit-oriented-reading.md) | Identify bug classes and exploit-relevant data/control flow. |
| 12 | [Case Studies from Vulnerable Windows Service Patterns](12-case-studies-from-vulnerable-windows-service-patterns.md) | Full walkthroughs modeled on auth-gated dispatch, copy helpers, and parser bugs. |
| 13 | [Printable Worksheets and Checklists](13-printable-worksheets-and-checklists.md) | Reusable print pages for function triage, branches, calls, copies, loops, and exploit analysis. |
| 14 | [Shellcode Idioms and Position-Independent Patterns](14-shellcode-idioms-and-position-independent-patterns.md) | Recognize call/pop, PEB walking, encoder stubs, egghunters, and null-byte avoidance. |
| 15 | [ROP Gadgets and Code-Reuse Patterns](15-rop-gadgets-and-code-reuse-patterns.md) | Read gadgets, trace chains through the stack, identify pivots and mid-instruction gadgets. |

## How to use this workbook

For each example, write four lists before writing pseudocode:

1. Facts forced by the instructions.
2. Hypotheses suggested by compiler patterns.
3. Data sources and destinations.
4. Exploit relevance, if any.

Names are weak evidence. Types are hypotheses. Control-flow edges, memory writes,
argument setup, compare operands, and return values are stronger evidence.

---

## Building the PDF

```bash
scripts/build-x86-reverse-engineer-workbook.sh
```

Output: `Documentation/learning-to-read-x86-assembly-like-a-reverse-engineer.pdf`.

The build script assembles the numbered chapter files in order, adds a table of contents, and formats the result for printing.
