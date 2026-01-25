# Pattern Utilities

This module provides deterministic pattern generation and offset resolution utilities
commonly used during memory corruption vulnerability research (e.g. stack overflows).

The goal is to reliably determine **exact overwrite offsets** without relying on external
frameworks or ad-hoc scripts.

This tooling is intentionally minimal, deterministic, and designed to be trusted under
time pressure.

---

## What This Module Does

The pattern utilities solve two related problems:

1. **Pattern Creation**  
   Generate a deterministic, non-repeating byte pattern of a given length.

2. **Offset Resolution**  
   Given a value observed in a crashed register (e.g. EIP/RIP), determine the exact
   offset in the original pattern where control was overwritten.

These are foundational tasks in exploit development and are typically performed early
in the workflow.

---

## Design Principles

- **Deterministic**  
  Given the same inputs, the output is always identical.

- **Architecture-agnostic**  
  The code is parameterized by _word size_ (4 or 8 bytes), not CPU type.
  This supports x86, x64, ARM32, and AArch64 user-mode targets.

- **Endianness-aware**  
  Register values are interpreted correctly according to target endianness
  (little-endian by default).

- **Library-first, CLI-friendly**  
  All logic lives in reusable Python modules.  
  CLI tools are thin wrappers over the library.

- **No hidden assumptions**  
  No randomness, no global state, no implicit offsets.

---

## Pattern Generation

Patterns are generated using a deterministic cartesian product of byte alphabets:

- `A–Z`
- `a–z`
- `0–9`

This produces patterns such as:

```text
Aa0Aa1Aa2Aa3…
```

This structure guarantees that every contiguous window of bytes (up to typical register
sizes) is unique within the generated pattern.

The output is returned as raw `bytes` and may be rendered as ASCII or hex as needed.

---

## Offset Resolution

Offset resolution works by:

1. Regenerating the original pattern deterministically
2. Normalizing the observed crash value into raw bytes
3. Accounting for endianness when the value represents a register
4. Searching for the byte sequence in the regenerated pattern

If the sequence is found, the exact offset is returned.  
If not, `None` is returned.

Valid query inputs include:

- Hex strings (e.g. `42306142`, `0x42306142`)
- Integers (e.g. `0x42306142`)
- Raw bytes (memory order)

---

## CLI Tools

Two CLI tools are provided:

### `pattern_create`

Generate a deterministic pattern.

```bash
pattern_create -l 800
pattern_create -l 1200 --arch x64
pattern_create -l 256 --hex
```

### `pattern_offset`

Locate the offset of an overwritten value.

```bash
pattern_offset -l 800 -q 42306142
pattern_offset -l 800 -q 0x42306142
pattern_offset -l 800 -q B0aB --raw
```
