# FMT-02: Pointer-Directed String Disclosure

## Objective

Use integer leaks to distinguish likely pointers, then dereference the correct argument with `%s`.

## Starting Files

- `fmt02_string_read.exe`
- FMT-01 notes

## Task

Survey arguments without dereferencing them. Use WinDbg to validate candidate pointers before replacing the matching conversion with `%s`.

Useful observations:

```text
dd esp L20
!address <candidate>
da <candidate>
```

## Expected Discoveries

- `%x` renders an argument value; `%s` treats that same value as a pointer.
- A readable pointer is not necessarily the target record.
- Earlier conversions change which argument a later `%s` consumes.

## Success Condition

Print the protected record and explain the argument-cursor state at the `%s` conversion.

## Common Failure Modes

- Trying `%s` across every slot without validating memory first.
- Forgetting that a failed dereference can terminate the process.
- Reusing an argument index after adding or removing a conversion.

## Debrief

Record the candidate values, memory validation, selected slot, and why the decoy was rejected.
