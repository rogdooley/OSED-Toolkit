# Target 03 Instructor Guide

## Architecture

The parser uses standard C file APIs. `main` opens a file and calls `load`; `load` reads a header, allocates a slot array, then processes fixed-size entries. The header contains a marker, revision, record count, and table-size field.

## Analysis notes

The parser checks the advertised table size against the record count, then derives an allocation byte count with a narrowing conversion. The record-processing loop uses the original wider count. Valid small files behave predictably. A large accepted count can make the allocated region smaller than the later indexed writes. ASLR is disabled and DEP is enabled. The consequence and exact behavior depend on the produced PE and Windows heap implementation, so teach this as a corruption condition rather than a guaranteed exploit.

## Suggested hints

1. Locate the `fopen`/`fread` references and reconstruct the first fixed-size structure.
2. Write down each use of the record-count field, including operand width.
3. Compare the allocation argument's width with the loop bound and indexed store scale.

## Validation notes

The sample file demonstrates ordinary parsing only. Keep malformed test cases and their explanation instructor-only.
