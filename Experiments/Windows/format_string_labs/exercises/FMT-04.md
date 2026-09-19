# FMT-04: Function-Pointer Overwrite

## Objective

Redirect an indirect call from `normal_action` to the benign `proof_action` using format-string writes.

## Starting Files

- `fmt04_function_pointer.exe`
- PDB for the guided attempt; repeat with symbols disabled afterward.

## Task

Determine the destination slot, both function addresses, and the smallest write strategy that changes `selected_action` correctly. Confirm the final pointer before allowing the indirect call to execute.

Useful observations:

```text
x fmt04_function_pointer!*action*
dd <destination> L1
u <candidate> L5
```

## Expected Discoveries

- The overwrite destination stores a pointer; it is not the function itself.
- A full `%n` write may require an impractical output count.
- Partial writes require byte-order and unchanged-byte reasoning.

## Success Condition

Reach the benign proof action and explain each written byte or half-word, including why untouched bytes remain valid.

## Common Failure Modes

- Writing to `normal_action` instead of `selected_action`.
- Confusing a symbol address with the pointer value stored there.
- Continuing execution without checking that the result points to executable memory.

## Debrief

Record the before/after pointer, write widths, output counts, and indirect-call instruction.
