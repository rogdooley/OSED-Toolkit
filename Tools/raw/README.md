# Payload Layout Examples

These specs demonstrate how to use the layout engine. All are fully generic —
no hardcoded sizes, no ordering constraints.

---

## Shellcode workflow

The builder never generates shellcode internally. Bring your own `.bin` file:

```
# Save raw shellcode bytes to a file however you like, then:
python -m Tools.exploit.cli --layout-spec classic_32bit_bof.json \
                      --shellcode-file my_sc.bin \
                      --write-payload out.bin \
                      --verbose
```

The `--shellcode-file` flag overrides the path of the segment named `shellcode`
in the spec without editing the file.

---

## Padding strategies

| Strategy        | Key            | Use when                                      |
|-----------------|----------------|-----------------------------------------------|
| `pad_count`     | fixed count    | You know the exact gap in bytes               |
| `pad_to_offset` | absolute pos   | You know where EIP/RIP sits in memory         |
| `pad_to_align`  | alignment      | You need stack alignment (e.g. 16-byte SSE)   |
| `repeat`        | single byte    | NOP sleds, specific fill bytes                |

---

## Value widths

```json
{ "name": "eip",  "value": "0xdeadbeef",           "width": 4, "endian": "little" }
{ "name": "rip",  "value": "0x00007ffff7a1b2c3",   "width": 8, "endian": "little" }
{ "name": "word", "value": "0x1234",                "width": 2, "endian": "big"    }
{ "name": "byte", "value": "0x42",                  "width": 1                     }
```

---

## Adding a custom computed function

```python
# my_encoders.py — run this before the builder, or import it in your harness
from Tools.exploit.computed_registry import register

def alphanumeric_pad(args: dict) -> bytes:
    count = int(args["count"])
    return bytes([c % 26 + 0x41 for c in range(count)])

register("alphanumeric_pad", alphanumeric_pad)
```

Then reference it in your spec:

```json
{
  "name": "encoded_pad",
  "computed": {
    "function": "alphanumeric_pad",
    "args": { "count": 64 }
  }
}
```

---

## Spec reference

```json
{
  "badchars": "000a0d",
  "expected_size": 1024,
  "segments": [
    { "name": "...", "bytes_file":    "sc.bin"               },
    { "name": "...", "pad_count":     174,  "pad_byte": "0x41" },
    { "name": "...", "pad_to_offset": 524,  "pad_byte": "0x41" },
    { "name": "...", "pad_to_align":  16,   "pad_byte": "0x00" },
    { "name": "...", "value": "0xdeadbeef", "width": 4, "endian": "little" },
    { "name": "...", "raw_bytes":     "deadbeef"             },
    { "name": "...", "raw_bytes":     [0xde, 0xad, 0xbe, 0xef] },
    { "name": "...", "repeat":        { "byte": "0x90", "count": 32 } },
    { "name": "...", "computed":      { "function": "short_jump_back", "args": { "distance": 32 } } }
  ]
}
```
