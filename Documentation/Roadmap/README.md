# ASM-Lab Roadmap

## Canonical Milestone Order

The current roadmap order for ASM-Lab is:

1. `M1` Models
2. `M2` Golden Fixture
3. `M3` Validation Layer
4. `M4` Minimal Executor
5. `M4.5` Reference Lesson
6. `M5` Explanation Engine
7. `M6` Lesson Loader
8. `M7` Predict-Then-Reveal
9. `M8` State History
10. `M9` Textual UI
11. `M10` Additional Lessons

## Why This Order Exists

ASM-Lab is not being built as a generic emulator or debugger.

It is being built around a single educational contract:

- a lesson defines expected state transitions
- the executor reproduces them deterministically
- the explanation engine interprets them
- validators confirm the output still matches the teaching intent

The `stack_strings_calc_exe` golden fixture is the acceptance target for the first executor milestone.

## Hard Rule

New instructions may not be added until at least one lesson fixture exercises them.

The sequence must be:

- new lesson
- hand-authored fixture
- executor support

All executor growth must be justified by a lesson on the teaching spine.

Instruction support follows lessons.
Lessons do not follow instruction support.

## Teaching Spine

The project teaching spine is:

1. Bytes
2. Little Endian
3. Stack Strings
4. Pointers
5. Stack Frames
6. Calling Conventions - cdecl Arguments
7. PEB Walk
8. Export Resolution

Architectural decisions should improve one or more of these lessons.

## Pointer Lesson Contract

The Pointer Lesson must emit these explanation keys:

- `address_vs_value`
- `pointer_setup`
- `pointer_dereference`
- `memory_read`
- `register_updated_from_memory`
- `little_endian_interpretation`

These are educational acceptance criteria, not optional wording hints.

## Current Reference Artifacts

Reference lessons:

1. `Stack Strings - calc.exe`
2. `Pointer Dereference`
3. `Stack Frame - Canonical x86 Prologue`

- `M1`: state and explanation contracts in `Documentation/Roadmap/M1-Core-State-Model.md`
- `M2`: golden lesson fixture in `tests/asm_lab/fixtures/stack_strings_calc_exe.yaml`
- `M2`: pointer lesson fixture in `tests/asm_lab/fixtures/pointer_lesson_calc_dword.yaml`
- `M3`: validation helpers in `asm_lab/validation/`
- `M4`: minimal executor notes in `Documentation/Roadmap/M4-Minimal-Executor.md`
- `M4.5`: reference lesson notes in `Documentation/Roadmap/M4.5-Reference-Lesson.md`
- `M5`: explanation-engine notes in `Documentation/Roadmap/M2-Explanation-Engine.md`
- `M6`: lesson-system notes in `Documentation/Roadmap/M3-Lesson-System.md`

Some file names still reflect earlier numbering. The sequence in this file is the canonical roadmap.
