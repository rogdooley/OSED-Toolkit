# 06 - Network Overflow Lab (Win32/x86)

This is a small Windows x86 reverse-engineering lab built for WinDbg and IDA practice.

The service listens on TCP port `11460` and parses a fixed packet header followed by nested records.
Only opcode `0x1337` reaches the intentional stack overflow in `copy_record_payload()`.

## Repository layout

- `src/mini_proto_vuln/` - server source
- `docs/` - walkthroughs and packet notes
- `send_packet.py` - client for benign and crashing requests

## Lesson objectives

- break on `ws2_32!recv`
- trace data through packet parsing
- follow the dispatch path across multiple source files
- distinguish safe copies from the vulnerable copy
- observe the overflow in WinDbg

## Build

### MSVC x86 Native Tools Prompt

From the lab root:

```bat
cd Learning\Win32_X86\06_network_overflow_lab\src\mini_proto_vuln
cl /nologo /W3 /Od /Zi /GS- /MT main.c network.c protocol.c commands.c util.c ^
    /link /OUT:mini_proto_vuln.exe ws2_32.lib
```

If you want explicit incremental-linker disablement during debugging:

```bat
cl /nologo /W3 /Od /Zi /GS- /MT main.c network.c protocol.c commands.c util.c ^
    /link /OUT:mini_proto_vuln.exe /DEBUG /INCREMENTAL:NO ws2_32.lib
```

### Optional MinGW build

```bat
cd Learning\Win32_X86\06_network_overflow_lab\src\mini_proto_vuln
gcc -m32 -O0 -g -fno-stack-protector main.c network.c protocol.c commands.c util.c ^
    -o mini_proto_vuln.exe -lws2_32
```

## Run

Start the server:

```bat
mini_proto_vuln.exe
```

It listens on `127.0.0.1:11460`.

## Send packets

From another terminal:

```bat
py -3 send_packet.py --host 127.0.0.1 --port 11460 --opcode 0x1001 --size 0 --copy-len 0 --pattern A
py -3 send_packet.py --host 127.0.0.1 --port 11460 --opcode 0x1002 --size 32 --copy-len 16 --pattern B
py -3 send_packet.py --host 127.0.0.1 --port 11460 --opcode 0x1337 --size 256 --copy-len 300 --pattern C
```

The last command is the crash path.

## Packet format overview

- fixed `PacketHeader`
- fixed `RecordHeader`
- nested `RECORD_METADATA`, `RECORD_COMMAND`, and `RECORD_PAYLOAD`
- payload record begins with `uint32 copy_length`

See `docs/packet_format.md` for the structure.

## WinDbg checklist

1. Launch the server under WinDbg.
2. Set `bp ws2_32!recv`.
3. Set `bp mini_proto_vuln!parse_protocol`.
4. Set `bp mini_proto_vuln!dispatch_command`.
5. Set `bp mini_proto_vuln!copy_record_payload`.
6. `g`
7. Send a benign packet first.
8. Step through the parser and watch `eax` after `recv`.
9. Send the `0x1337` packet and inspect the crash.

Useful commands:

```text
bp ws2_32!recv
g
dd esp L5
pt
k
dds esp L8
```

## IDA checklist

1. Open `mini_proto_vuln.exe`.
2. Load the PDB if available.
3. Find `receive_packet()`.
4. Follow into `parse_protocol()`.
5. Step through `validate_records()`.
6. Compare the safe copy helpers to `copy_record_payload()`.

See `docs/ida_walkthrough.md` for the detailed workflow.

## Expected crash behavior

- opcode `0x1001`: `PONG`
- opcode `0x1002`: safe echo response
- opcode `0x1337`: stack corruption and crash after the vulnerable `memcpy`

## Quick checkpoint

1. Start the server.
2. Launch WinDbg.
3. Break on `ws2_32!recv`.
4. Send a benign packet.
5. Step back into the application.
6. Locate `parse_protocol()`.
7. Trace to `copy_record_payload()`.
8. Trigger the overflow.
