# Architecture

This lab is intentionally small. The goal is to practice tracing one request from `recv()` into a single stack overflow path.

## Call flow

`main()`  
`start_server()`  
`receive_packet()`  
`parse_protocol()`  
`validate_records()`  
`dispatch_command()`  
`process_client_message()`  
`copy_record_payload()`

## Files

- `src/mini_proto_vuln/main.c` starts the process.
- `src/mini_proto_vuln/network.c` owns the socket loop and `recv()`.
- `src/mini_proto_vuln/protocol.c` parses and validates the packet envelope.
- `src/mini_proto_vuln/commands.c` dispatches opcodes and holds the copy routines.
- `src/mini_proto_vuln/util.c` prints opcodes, record names, and packet bytes.

## Design notes

- The receive buffer is fixed-size.
- The packet header is fixed-size.
- Records are nested inside the packet body.
- Only `copy_record_payload()` is intentionally unsafe.
- All other copy helpers perform explicit length checks first.
