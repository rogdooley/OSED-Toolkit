# FMT-03: Exact Controlled Write

## Objective

Use `%n` to set `authorization_gate` to exactly `0x40`.

## Starting Files

- `fmt03_controlled_write.exe`
- FMT-01 and FMT-02 notes

## Task

First find and validate the writable destination pointer as an integer leak. Then account for every character emitted before `%n` and construct a format string that writes 64.

Set a data breakpoint on the destination before the final attempt:

```text
ba w4 <destination>
```

## Expected Discoveries

- `%n` emits nothing; it stores the number of characters already emitted.
- Literal text, separators, padding, and prior conversions all affect the count.
- Field width is a practical count-control mechanism.

## Success Condition

Reach `[success] Gate value accepted.` and explain the exact count at the write.

## Common Failure Modes

- Counting format-string bytes instead of emitted characters.
- Using `%n` while the cursor points to a non-pointer argument.
- Forgetting that a field width is a minimum, not always an exact length.

## Debrief

Show the count equation, destination address validation, and debugger evidence of the write.
