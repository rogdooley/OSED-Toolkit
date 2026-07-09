# Architecture

This lab is deliberately larger than the earlier network-overflow exercise.
The student should have to separate signal from noise before they ever find
the bug.

## High-level flow

`main()` -> `service bootstrap` -> `accept loop` -> `session auth` ->
`packet parse` -> `opcode dispatch` -> `handler` -> `helper / gadgetlib`

## Why the extra modules exist

- `service` is the thing the student will reverse engineer first.
- `protocol` isolates wire parsing so the packet contract can be reasoned
  about independently of the socket code.
- `helper.dll` makes the service look more like a product that grew
  organically.
- `gadgetlib.dll` gives the student a realistic module to inspect when the
  mitigation phase begins.
- `client` keeps packet construction reproducible.
- `tools` captures the repeatable workflow that should not live in the service
  itself.

## Service responsibilities

The service should be split into these translation units:

- `main.c`: process startup, config load, and console/service mode selection.
- `network.c`: socket setup, accept loop, recv loop, and connection teardown.
- `session.c`: per-client state, auth state, and request sequencing.
- `dispatch.c`: opcode routing.
- `handlers.c`: stable opcode handlers.
- `logging.c`: structured log emission.

This split teaches the student to identify responsibility boundaries instead of
assuming every function in the binary is equally important.

## Packet contract

The wire format should support one fixed header and a small set of nested
records. The safe design needs multiple records so the student has to follow a
cursor through the body and cannot solve the lab from the first header field.

Suggested fields:

```text
FrameHeader
  magic
  version
  flags
  opcode
  session_id
  total_length
  record_count
```

Each record then carries:

```text
RecordHeader
  type
  flags
  length
```

The body content is opcode-dependent. The future vulnerable parser will live in
one record handler, but the current phase should only define the contract.

## Opcode model

Keep the opcode space small and readable:

- `OP_HELLO`: protocol handshake and version check.
- `OP_AUTH`: token or challenge-response verification.
- `OP_STATUS`: harmless status query.
- `OP_CONFIG`: configuration fetch or echo.
- `OP_DIAG`: diagnostic bundle parser.
- `OP_ANALYZE`: the future bug path, but safe for now.

The important lesson is that several commands should appear interesting but
remain safe after inspection.

## Suspicious but safe paths

The design should deliberately include code that looks like a bug until the
student proves otherwise:

- bounded `memcpy` helpers with explicit length checks
- string formatting into fixed buffers with proper truncation
- auth token parsing that rejects malformed input early
- diagnostic record handling that copies into scratch buffers only after
  validation

These paths train the student to prove a problem instead of reacting to any
copy operation they see.

## Future vulnerability insertion point

When the next phase starts, the intended bug should be added in exactly one
place:

- inside the diagnostic or analysis record parser
- after the packet envelope has already been validated
- with enough surrounding safe code to make the code path non-obvious

That placement supports the later exercises on offset finding, bad characters,
DEP, gadget selection, and WinDbg verification.
