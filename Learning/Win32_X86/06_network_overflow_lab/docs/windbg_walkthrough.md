# WinDbg Walkthrough

## First breakpoints

Set these breakpoints after loading the server under WinDbg:

```text
bp ws2_32!recv
bp mini_proto_vuln!parse_protocol
bp mini_proto_vuln!dispatch_command
bp mini_proto_vuln!copy_record_payload
g
```

## At `recv`

When execution stops in `ws2_32!recv`:

```text
dd esp L5
pt
```

Inspect the return value in `eax` after stepping out of `recv`.

## Inspect the buffer

After `recv` returns:

```text
r eax
db @esi L80
dd @esp L10
```

Use the actual register state from your session to locate the receive buffer and confirm the packet bytes.

## Parser path

Expected path:

```text
parse_protocol
validate_records
dispatch_command
process_client_message
copy_record_payload
```

Helpful commands:

```text
k
dds esp L8
```

## Vulnerable copy site

At `copy_record_payload`, compare the stack buffer address to the saved return address.

Useful inspection commands:

```text
r
dd esp L20
db esp L80
```

The local buffer is 128 bytes. A large `copy_length` should overwrite the stack frame and crash the process.

## Expected crash behavior

- `EIP` becomes corrupted after the vulnerable `memcpy`.
- `k` shows the call chain into `copy_record_payload`.
- The stack buffer in `db esp` should be overwritten by your payload pattern.
- If the payload is too short, the crash may not occur.
