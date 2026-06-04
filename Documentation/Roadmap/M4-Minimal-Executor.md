# M4 Minimal Executor

## Goal

Implement the smallest possible executor that satisfies the `stack_strings_calc_exe` golden fixture.

## Scope

Support only:

- `xor reg, reg`
- `push reg`
- `push imm32`

Support only the registers required by the fixture:

- `eax`
- `esp`
- `eip`

## Acceptance Criteria

The executor is complete for this milestone only when:

- the golden fixture loads
- the executor produces an `ExecutionResult`
- `compare_fixture_output(..., mode="strict")` passes for every step

## Non-Goals

Do not add support for:

- `mov`
- `pop`
- `add`
- `sub`
- memory operands
- register dereferences
- generic x86 execution

## Rule

New instructions may not be added until at least one lesson fixture requires them.
