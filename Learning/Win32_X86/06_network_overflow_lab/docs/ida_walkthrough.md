# IDA Walkthrough

## Load the binary

- Open `mini_proto_vuln.exe` in IDA Free.
- Load the matching PDB if you have it available in the same directory.
- Ensure the database is configured for 32-bit x86.

## What to find

Start from these functions:

- `start_server`
- `receive_packet`
- `parse_protocol`
- `validate_records`
- `dispatch_command`
- `process_client_message`
- `copy_record_payload`

## Workflow

1. Find `receive_packet()` and confirm it uses a fixed receive buffer.
2. Follow the code into `parse_protocol()`.
3. Inspect the record loop in `validate_records()`.
4. Compare the safe copy helpers with `copy_record_payload()`.
5. Trace the `0x1337` opcode branch into the vulnerable function.

## What to inspect

- The packet header validation.
- The record length checks.
- The safe `memcpy` sites.
- The missing bounds check in `copy_record_payload()`.
- The 128-byte local stack buffer.

## Graph view

Use graph view to confirm the call chain instead of relying on linear disassembly only.

## Sync with WinDbg

Keep the same function names open in IDA while stepping in WinDbg.
That makes it easier to map the live stack frame back to the static call graph.
