# Bad Character Analysis Utilities

This module provides tooling to assist with **bad character discovery** during
memory corruption vulnerability research.

It is designed to answer one specific question reliably:

> _Which byte values do not survive intact from input to memory?_

The module intentionally avoids debugger automation or exploit delivery and
focuses purely on **byte comparison and analysis**.

---

## What Are Bad Characters?

A _bad character_ is any byte value that cannot be safely used in an exploit
payload because it is:

- Removed
- Truncated
- Altered
- Reordered
- Treated as a terminator

Common examples include:

- `0x00` (NULL)
- `0x0a` (line feed)
- `0x0d` (carriage return)

Bad characters are **context-dependent** and must be identified empirically for
each vulnerable code path.

---

## Design Philosophy

This module follows a few strict principles:

- **No guessing**  
  Bad characters are identified by comparison, not assumption.

- **Deterministic behavior**  
  The same inputs always produce the same results.

- **No debugger coupling**  
  The user controls how memory is inspected (e.g. WinDbg).

- **Streaming analysis**  
  The analyzer tolerates missing bytes, transformations, and truncation in a
  single run.

- **Library-first**  
  All logic is reusable programmatically; the CLI is a thin wrapper.

---

## Core Components

### `BadCharAnalyzer`

The primary class responsible for:

- Generating canonical test byte sequences
- Comparing expected vs observed bytes
- Reporting:
  - missing bytes
  - transformed bytes

#### Test Byte Generation

A canonical test sequence is generated from:

```code
\x00 → \xff
```

with user-specified exclusions (e.g. `0x00`).

Example output (conceptual):

```code
\x01\x02\x03…\xff
```

---

### Analysis Model

The analyzer compares two byte streams:

- **Expected**: the bytes you intended to send
- **Observed**: the bytes actually found in memory

The comparison is performed as a **streaming walk**, not a naive index-by-index
comparison. This allows the analyzer to:

- Detect missing bytes
- Detect transformations (e.g. `0x0a → 0x20`)
- Continue analysis after mismatches
- Report _all_ bad characters in a single run

---

## CLI Tool: `find_badchars`

A simple command-line interface is provided for convenience.

### Example Usage

```bash
python -m Tools.badchars.cli.find_badchars \
  --expected 0102030405 \
  --observed 01022005
```

### Example Output

```code
[!] Bad characters:
03 04

[!] Transformed bytes:
03 -> 20
```
