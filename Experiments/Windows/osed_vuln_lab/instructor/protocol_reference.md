# Instructor Protocol Reference

This file contains solution material. Do not include it in the student bundle.
The clients under `python/` are instructor validation and post-exercise tools;
they are not starting scripts for the binary-reversing exercise.

## Packet Format

All integer fields are little endian.

| Offset | Type | Meaning |
|---:|---|---|
| 0 | `uint32` | magic `0x4F534544` (`OSED`) |
| 4 | `uint16` | opcode |
| 6 | `uint16` | reserved |
| 8 | `uint32` | payload length |
| 12 | bytes | payload |

The declared payload length must not exceed 8192 bytes.

## Opcodes

| Value | Symbol | Purpose |
|---:|---|---|
| `0x1000` | `OP_PING` | Neutral connectivity check; returns `PONG`. |
| `0x1001` | `OP_STACK` | Classic stack-overflow path. |
| `0x1002` | `OP_SEH` | SEH-overwrite training path. |
| `0x1003` | `OP_SMALLBUF` | Constrained overflow for staged-payload practice. |
| `0x1004` | `OP_LEAK` | Controlled helper-module pointer disclosure. |
| `0x1005` | `OP_ROP` | Overflow path for the DEP/ROP profile. |

## Validation Clients

With the service running on `127.0.0.1:9999`:

```bat
python python\protocol_smoketest.py --host 127.0.0.1 --port 9999
python python\exploit_scaffold.py pattern --opcode stack --length 800
```

Expected smoke-test output is `PONG`. Use these clients to validate a build or
after the learner has independently recovered and documented the protocol.

The scaffold also supports offset calculation, bad-character generation, raw
payload files, and layouts made from learner-supplied return addresses and ROP
bytes. It rejects payloads larger than the service limit.
