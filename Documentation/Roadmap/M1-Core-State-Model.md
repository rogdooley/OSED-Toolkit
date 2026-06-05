# M1 Core State Model

## Goal

Define the stable, typed data contracts for ASM-Lab milestone 1 before any execution or UI logic is built.

## Pedagogical Contract

Success is measured by educational value, not by emulator completeness.

Every model must help answer:

- What changed?
- Why did it change?
- How should a student interpret the bytes?
- Why does this matter in exploit development?

ASM-Lab milestone 1 is:

- An x86 exploit-development memory visualizer
- Lesson-driven only
- Focused on memory intuition

ASM-Lab milestone 1 is not:

- A debugger
- A disassembler
- A general emulator
- A plugin platform

## Scope

Create typed models for:

- `MachineState`
- `RegisterChange`
- `MemoryRead`
- `MemoryWrite`
- `StackChange`
- `Explanation`
- `InspectViewModel`
- `Lesson`
- `LessonStep`

Freeze these models before building:

- instruction semantics
- lesson rendering
- Textual UI components
- inspect interactions

## Deliverables

- A new `asm_lab` Python package
- Core model definitions implemented with modern typed models
- Package skeleton for future architecture, CPU, lesson, and UI modules

## Key Decisions

- Use Python 3.12+
- Use Pydantic models for validation and serialization
- Keep the explanation contract independent from Textual
- Keep UI-specific rendering state out of execution-state models
- Represent values as explicit integers and derived interpretations, not formatted strings
- Normalize byte-oriented data to one canonical internal representation: `bytes`
- Prefer category- and key-based assertions over exact explanation prose matching

## Constraints

- x86 only
- No arbitrary instruction input
- No Capstone, Keystone, or Unicorn dependency in milestone 1 logic
- No generic expression parsing
- Only support operand forms required by the first lessons
- Do not introduce execution semantics in the model layer

## Canonical Byte Representation

All byte-oriented fields should accept:

- `bytes`
- `bytearray`
- `list[int]`

They should normalize internally to `bytes`.

This applies to:

- memory regions
- memory reads
- memory writes
- stack byte movement
- inspect sections that display raw bytes

The byte abstraction should expose helpers for:

- hex rendering
- ASCII rendering with safe replacement for non-printable bytes
- little-endian integer interpretation for 1, 2, 4, and 8 byte widths

## Assertion Models

Lesson-step assertions exist to validate educational outcomes without freezing wording too early.

Assertions should target:

- changed registers
- memory reads
- memory writes
- stack pointer movement
- explanation categories
- interpretation keys
- shellcode-relevance keys

Assertions should avoid exact prose matching in milestone 1.

This keeps wording flexible while still enforcing:

- correct state transitions
- correct explanation structure
- correct educational emphasis

## ExecutionTrace Purpose

`ExecutionTrace` is the future handoff object between runtime behavior and explanation generation.

It should capture:

- instruction
- operands
- reads
- writes
- register changes
- stack changes
- derived state diff

This keeps the explanation engine independent from both the executor and the UI layer.

## Exit Criteria

This milestone is complete when:

- the state and explanation models exist
- the lesson schema is defined
- the inspect schema is defined
- the assertion schema is defined
- the execution-trace schema is defined
- no execution or UI logic has leaked into the model layer
