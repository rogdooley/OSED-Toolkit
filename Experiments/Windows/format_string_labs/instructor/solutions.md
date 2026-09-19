# Instructor Notes and Validation

Do not provide this file before the student has supplied observations.

## FMT-01

The marker is variadic argument 4. A minimal confirmation is `%x.%x.%x.%x`, which ends in `41414141`. At function entry, the format pointer is the fixed argument; the first conversion starts with the first variadic slot.

Classification target: **A** if the student independently correlates call-site words and output; **B** with one cursor hint; **C** after being told the marker slot; **D** if the distinction between format bytes and arguments remains unclear.

## FMT-02

The decoy pointer is argument 3 and the protected record pointer is argument 6. One valid input is:

```text
%x.%x.%x.%x.%x.%s
```

The first five conversions advance the cursor so `%s` consumes argument 6. Confirm with `da` before dereferencing.

## FMT-03

The destination pointer is argument 6. One valid input is:

```text
%12x%12x%12x%12x%16x%n
```

Each dummy integer needs fewer digits than its field width, so the widths emit exactly `12 + 12 + 12 + 12 + 16 = 64` characters. `%n` consumes argument 6 and writes `0x40`.

## FMT-04

The destination pointer is argument 4. Addresses vary by linker output even with ASLR disabled, so derive them live. Because the functions are close, their upper bytes should match; use `%hhn` or `%hn` only after confirming exactly which low bytes differ. Account for output from the three conversions needed to reach argument 4. Break on the indirect call and verify that the final pointer resolves to executable code at `proof_action`.

If the linker places the two functions across a 64 KiB boundary, prefer byte writes or adjust source ordering; never assume a partial write is valid from symbol names alone.

## FMT-05

`OP_FORMAT` reaches `_snprintf` with attacker-controlled format data. Slots 1-8 are request arguments. Slot 9 is `module_anchor`, slot 10 points to the stack-resident request, and slot 11 points to `protected_record`. Require students to prove this dynamically; do not award full credit for reading source or the scaffold.

## FMT-06

Derive all values from the current binary and process:

```text
image_base = leaked_anchor_va - module_anchor_rva
record_va  = image_base + protected_record_rva
```

The arbitrary read can place `record_va` in explicit slot 1 and consume it with `%s`. Numeric values are intentionally omitted because RVAs change after rebuilding.

## FMT-07

Use `scratch_dword` as the destination. A reliable single-byte request supplies a small dummy value in one slot and the destination in the next, then uses a controlled width followed by `%hhn`. Treat desired byte zero as an emitted count of 256. Verify each destination byte with `ba w1`.

## FMT-08

Recover the base from slot 9, derive both `selected_action` storage and `proof_action`, and write the proof VA in little-endian order with four `%hhn` requests. Only then send `OP_EXECUTE`. The proof prints a success message and exits. This demonstrates ASLR-aware existing-code reuse under DEP, not injected-code execution.

Classification: **A** for independent binary discovery and fresh-run composition; **B** with one primitive-specific hint; **C** after receiving a slot number or equation; **D** if the student cannot distinguish VA, RVA, pointer storage, and pointee.
