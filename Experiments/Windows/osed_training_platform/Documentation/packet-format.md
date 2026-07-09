# Packet Format

All fields are little-endian.

## FrameHeader

```text
magic        uint32  fixed sentinel
version      uint16  protocol version
flags        uint16  session and request flags
opcode       uint16  command selector
session_id   uint16  client session token
total_length  uint32  frame length including header and records
record_count  uint16  number of nested records
reserved     uint16  alignment / future use
```

## RecordHeader

```text
type    uint16
flags   uint16
length  uint32
```

## Record types

- `RECORD_CLIENT`
- `RECORD_AUTH`
- `RECORD_CONFIG`
- `RECORD_COMMAND`
- `RECORD_DIAG`

## Design intent

The frame is large enough to teach cursor-based parsing but still small enough
to reason about by hand in WinDbg.

- The fixed header teaches students to confirm magic, version, and length
  before trusting the body.
- The nested records teach incremental validation and state tracking.
- The opcode selects the handler, but the record types determine what each
  handler is actually allowed to consume.

## Why this shape

The earlier lab used a very direct request-to-handler path. This one adds a
protocol envelope so the student must answer a more realistic question:

“Which bytes matter to the actual bug, and which bytes are just protocol
decoration?”

That is the same decision-making problem encountered in real services.
