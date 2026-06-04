# M6 Lesson Loader And Lesson System

## Roadmap Position

This document now describes the lesson-loader phase that follows the executor and explanation-engine milestones.

Canonical milestone order lives in `Documentation/Roadmap/README.md`.

## Goal

Create a lesson-driven teaching flow that keeps the product constrained around pedagogy instead of drifting into general-purpose execution tooling.

## Format

Lessons should be authored in YAML for readability and validated into typed models.

Each lesson should define:

- title
- summary
- pedagogical objective
- architecture
- tags
- initial state
- ordered steps
- expected learning outcomes

## Teaching Spine

The current teaching spine is:

1. Bytes
2. Little Endian
3. Stack Strings
4. Pointers
5. Stack Frames
6. Calling Conventions - cdecl Arguments
7. PEB Walk
8. Export Resolution

New executor support should follow this sequence.

## Design Rules

- Keep lessons hand-authored
- Keep step structure narrow and explicit
- Reject unsupported instructions at validation time
- Allow lesson metadata to drive future filtering and progression
- Add one hand-authored golden lesson fixture before runtime implementation expands
- Introduce predict-then-reveal prompts early so lesson content drives the interaction model
- Plan for state history and reverse stepping early, even if the first runtime does not implement them yet
- All executor growth must be justified by a lesson on the teaching spine
- Instruction support follows lessons, not the reverse

## Validation Needs

Each lesson step should eventually support assertions for:

- expected register changes
- expected memory reads and writes
- expected explanation categories
- expected inspect interpretations

Before broad lesson authoring begins, one golden lesson should define:

- initial machine state
- expected execution trace per step
- expected state diff per step
- expected explanation keys and categories
- expected inspect output

This fixture is the acceptance test for the architecture. If the models cannot represent it cleanly, runtime work should not continue.

## Golden Lesson First

The first implementation-grade lesson should be:

- `Stack Strings - calc.exe`

It exists before runtime implementation for one reason:

- to prove the product contract is expressive enough for real teaching output

That fixture should stay hand-authored and stable.

It is not a runtime loader.
It is not a generated artifact.
It is the reference object the executor, explanation engine, and UI will eventually converge on.

The next lesson expansion should be:

- `Pointer Lesson - calc DWORD`

That lesson justifies future support for:

- `mov reg, imm`
- `mov reg, [reg]`

The Pointer Lesson must emit these explanation keys:

- `address_vs_value`
- `pointer_setup`
- `pointer_dereference`
- `memory_read`
- `register_updated_from_memory`
- `little_endian_interpretation`

Why each exists:

- `address_vs_value`: teaches that a register can contain a location without being the bytes stored at that location
- `pointer_setup`: teaches that a register can be prepared as a pointer target
- `pointer_dereference`: teaches that `[reg]` triggers a memory access
- `memory_read`: teaches that the loaded data came from memory
- `register_updated_from_memory`: teaches that dereferenced bytes become a register value
- `little_endian_interpretation`: teaches that bytes and integers are two views of the same underlying data

The next lesson after pointers should be:

- `Stack Frame - Canonical x86 Prologue`

That lesson should define this canonical frame:

- `[ebp+8]` argument_1
- `[ebp+4]` return_address
- `[ebp]` saved_ebp
- `[ebp-4]` local_1
- `[ebp-8]` local_2

Required explanation keys:

- `frame_setup`
- `frame_pointer_established`
- `stack_growth`
- `local_storage_allocated`
- `saved_frame_pointer`
- `return_address_location`
- `argument_location`

Role-aware inspect output is a hard acceptance criterion for this lesson.

The next lesson after Stack Frames should be:

- `Calling Conventions - cdecl Arguments`

That lesson should define this canonical cdecl argument layout:

- `[ebp+8]` argument_1
- `[ebp+12]` argument_2
- `[ebp+16]` argument_3

Required lesson goals:

- the caller pushes arguments before call
- arguments live above the return address
- the callee accesses arguments through positive EBP-relative offsets

For this lesson, argument labels remain structural only:

- `argument_1`
- `argument_2`
- `argument_3`

Do not introduce application-specific argument names in this lesson.

## Future Tiers

Tier 1:

- bytes
- endianness
- pointers
- stack strings
- stack frames

Tier 2:

- calling conventions
- TEB and PEB
- linked lists
- reverse-engineering memory structures
- predict-then-reveal lesson flow
- state history and reverse stepping

Tier 3:

- kernel32 discovery
- export parsing
- API resolution
- shellcode hashing

## Roadmap Note

`EFLAGS` support is deferred for now.

It becomes mandatory before introducing:

- `cmp`
- `test`
- `jz`
- `jnz`
- any conditional-control-flow lesson

## Exit Criteria

This milestone is complete when:

- YAML lesson files load into validated models
- the first five lessons are represented in the repository
- lesson scope remains tightly aligned with milestone 1
