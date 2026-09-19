# FMT-07: Byte-Wise Arbitrary Write

## Objective

Turn `%n` into a reusable byte-write primitive despite the bounded output buffer.

## Task

Locate a writable scratch DWORD in the executable. Derive its runtime address, then write a chosen four-byte value one byte at a time using `%hhn`. Verify every write with a data breakpoint before automating it.

## Expected Discoveries

- `%hhn` stores the emitted count modulo 256.
- A zero byte can be written by emitting 256 characters.
- Width is a minimum, so the consumed dummy value must not render wider than planned.
- Little-endian DWORD construction advances the destination by one byte per request.

## Success Condition

Construct the chosen DWORD exactly and show the four write events in WinDbg.

## Common Failure Modes

- Writing bytes in display order instead of memory order.
- Forgetting prior literal output in the character count.
- Allowing a dummy integer to exceed the requested width.
- Using `%n` where `%hhn` was intended.

## Debrief

Provide a table containing byte index, destination, desired byte, emitted count, and observed memory.
