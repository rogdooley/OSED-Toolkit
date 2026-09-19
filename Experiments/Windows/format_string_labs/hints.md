# Staged Hints

Read only the next hint for the active exercise.

## FMT-01

1. Each `%08x` consumes one 32-bit argument; punctuation consumes none.
2. Label the words at the call site in order instead of searching the entire stack.
3. The recognizable marker is `0x41414141`.

## FMT-02

1. Survey with `%08x` before using `%s`.
2. Candidate pointers should map to readable memory and show useful ASCII under `da`.
3. There are two string pointers; the protected record is later than the decoy.

## FMT-03

1. The destination pointer is the sixth variadic argument.
2. Consume the first five arguments while controlling how many total characters they emit.
3. Arrange for exactly 64 emitted characters immediately before the sixth conversion, then use `%n`.

## FMT-04

1. The destination pointer is the fourth variadic argument.
2. Compare the addresses of `normal_action` and `proof_action` byte by byte.
3. `%hhn` writes one byte and `%hn` writes two; choose the smallest sufficient overwrite and include all earlier output in the count.

## FMT-05

1. Start from `recv`, identify the fixed request size, and follow the opcode branch.
2. Use eight distinct request arguments before surveying contextual slots.
3. The first contextual code pointer follows the eight explicit request arguments.

## FMT-06

1. Validate the contextual pointer with `ln` and `lm` before doing arithmetic.
2. Subtract the anchor RVA from its leaked VA.
3. Supply the derived record VA as the first explicit argument and make `%s` consume slot 1.

## FMT-07

1. Use one request per destination byte while learning the primitive.
2. Put a small dummy integer before the destination pointer in the argument list.
3. A format shaped like `%<count>x%hhn` consumes the dummy and then the destination.

## FMT-08

1. Resolve pointer storage and the proof function as separate module-relative addresses.
2. Write all four little-endian bytes before using the execute opcode.
3. Use `dd` on pointer storage and `u` on the resulting value before execution.
