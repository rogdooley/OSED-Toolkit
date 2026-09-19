# FMT-01: Stack Argument Survey

## Objective

Determine how `printf` consumes variadic arguments and locate the attacker-recognizable marker.

## Starting Files

- `fmt01_stack_leak.exe`
- Its PDB may remain available for the first pass.

## Task

Start with:

```text
AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
```

Break immediately before or at the vulnerable `printf` call. Correlate the output with `dd esp L20` and the call instruction.

## Expected Discoveries

- The format pointer and variadic arguments occupy different stack slots.
- Every consuming conversion advances the internal argument cursor.
- Width affects rendering, not which argument is selected.

## Success Condition

Identify the marker's argument index and explain why `AAAA` at the beginning of the format string is not itself consumed as an argument.

## Common Failure Modes

- Counting literal separators as consumed arguments.
- Treating every leaked integer as an address.
- Inspecting the stack after `printf` has returned and assuming it is unchanged.

## Debrief

Write the exact relationship between the call-site stack, the first `%x`, and the marker.
