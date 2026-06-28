# Packet Format

All fields are little-endian.

## PacketHeader

```c
typedef struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t opcode;
    uint32_t total_length;
    uint32_t record_count;
} PacketHeader;
```

### Fields

- `magic` must be `0x4445534F` (`"OSED"` in little-endian memory).
- `version` must be `1`.
- `opcode` selects the handler.
- `total_length` includes the header plus every record.
- `record_count` is the number of nested records.

## RecordHeader

```c
typedef struct RecordHeader {
    uint16_t type;
    uint16_t flags;
    uint32_t length;
} RecordHeader;
```

### Record types

- `RECORD_METADATA`
- `RECORD_COMMAND`
- `RECORD_PAYLOAD`

## Record bodies

- `RECORD_METADATA` body: client name bytes.
- `RECORD_COMMAND` body: note or label bytes.
- `RECORD_PAYLOAD` body:
  - `uint32 copy_length`
  - payload bytes

## Example layout

```text
PacketHeader
RecordHeader(METADATA)
  client name bytes
RecordHeader(COMMAND)
  note bytes
RecordHeader(PAYLOAD)
  copy_length
  payload bytes
```

For opcode `0x1337`, `copy_record_payload()` copies `copy_length` bytes into a 128-byte stack buffer without a bounds check.
