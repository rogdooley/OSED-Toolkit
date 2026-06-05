# M5 Explanation Engine

## Roadmap Position

This document describes milestone five in the current roadmap.

Canonical milestone order lives in `Documentation/Roadmap/README.md`.

## Goal

Build the core educational abstraction for ASM-Lab: the transformation from state change into an explanation object.

## Core Architecture

The system flow must remain:

`Lesson Engine -> Execution Core -> State Diff Engine -> Explanation Engine -> UI Renderer`

The explanation engine is the product center.

The UI is only a renderer.

## Responsibilities

The explanation engine must produce structured output for every lesson step:

- `what_changed`
- `why`
- `interpretation`
- `shellcode_relevance`

It must also attach supporting detail such as:

- register changes
- memory reads
- memory writes
- stack movement
- pointer interpretations

The milestone-two foundation must also include assertion matcher utilities that validate:

- execution traces
- state diffs
- emitted explanation categories
- explanation entry keys

These validators are part of the pedagogical contract because they let lessons assert meaning without depending on fragile UI output.

## Design Rules

- Never generate explanations directly inside Textual widgets
- Prefer deterministic templates over opaque prose generation
- Explanations must be inspectable, serializable, and testable
- Each explanation must stand on its own for UI, logs, and future export
- Validation should return structured failures, not bare booleans
- Prefer category- and key-based matching over exact full-prose comparison
- If a trace lacks context, emit a safe generic explanation rather than inventing facts

## Initial Targets

Support only milestone-1 instruction forms needed by these lessons:

- Bytes
- Little Endian
- Pointers
- Stack Strings
- Stack Frames

Initial deterministic explanation builders should support:

- `mov`
- `push`
- `xor`

## Golden Scenarios

The explanation engine must handle at least:

- `mov eax, [esi]`
- `push 0x6578652e`
- `push 0x636c6163`
- `xor eax, eax`

## Output Quality Criteria

Every explanation should help a student understand:

- which bytes were read or written
- how the bytes map to integer and ASCII interpretations
- how pointers connect registers to memory
- why the behavior matters in shellcode or reverse engineering

Assertion validation should verify:

- state transitions
- emitted explanation categories
- interpretation keys
- shellcode relevance keys

Exact prose matching is intentionally avoided in milestone two so wording can improve without breaking lesson validation.

## Exit Criteria

This milestone is complete when:

- every supported instruction emits a structured explanation
- explanations are deterministic and covered by golden tests
- explanation generation remains fully decoupled from the UI layer
- assertion matcher utilities can validate trace, diff, and explanation outputs with structured failure reports
