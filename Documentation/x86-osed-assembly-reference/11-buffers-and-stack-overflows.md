# 11. Buffers and Stack Overflows

## Stack Buffer Layout

```
Higher addresses
+----------------------------+
| function arguments         |  [EBP+0x0C], [EBP+0x08]
+----------------------------+
| return address             |  [EBP+0x04]
+----------------------------+
| saved EBP                  |  [EBP+0x00]
+----------------------------+
| /GS cookie (if present)    |  [EBP-0x04]
+----------------------------+
| other local variables      |
+----------------------------+
| local buffer (e.g. 64 B)  |  [EBP-0x40]
+----------------------------+  <-- ESP
Lower addresses
```

## Overflow Mechanics

An unbounded copy (strcpy, sprintf, recv without length check) writes past the
buffer boundary, overwriting adjacent locals, saved EBP, and the return address.
The write travels from low addresses toward high addresses (upward in the
diagram).

## Offset Calculation

The offset from the start of the buffer to the return address:

```
offset = (EBP - &buffer) + 4

If buffer is at [EBP-0x40]:
  offset = 0x40 + 4 = 0x44 = 68 bytes
```

The `+ 4` accounts for the saved EBP between the locals and the return address.

Verify statically by reading the `lea reg, [ebp-X]` that feeds the copy. The
offset comes from the buffer's actual position relative to EBP, not from the
frame size (`sub esp, N`).

## Cyclic Pattern Verification

1. Generate a cyclic (De Bruijn) pattern of sufficient length
2. Send the pattern through the vulnerability
3. Read the value in EIP at the crash
4. Look up the 4-byte sequence in the pattern to get the exact offset

```python
# Using mona in WinDbg:
# !py mona pattern_create 500
# !py mona pattern_offset <EIP_value>
```

If the pattern offset matches your static calculation, the offset is confirmed.
If they differ, the difference reveals saved registers, cookies, or alignment
padding you missed.

## Bad Characters

Certain byte values are transformed or truncated by the target application
before they reach the vulnerable buffer. Common bad characters:

- `0x00` -- null terminator (truncates strings)
- `0x0A` -- line feed
- `0x0D` -- carriage return
- `0x09` -- tab
- `0x20` -- space

Test by sending all 256 byte values through the vulnerability and comparing
what arrives in memory with what was sent. Any byte that is missing, modified,
or causes truncation is a bad character.

Bad characters affect:
- The return address bytes (the address you overwrite EIP with)
- ROP gadget addresses
- Shellcode bytes
- All payload data that passes through the vulnerable path

## Partial Overwrites

Sometimes only the low 1, 2, or 3 bytes of the return address can be
controlled (the overflow is bounded, or null bytes terminate the write early).
A partial overwrite can redirect EIP within the same module if the high bytes
of the original return address are preserved.

## Stack Pivots

When the shellcode or ROP chain is not adjacent to the overwritten return
address (e.g., it lives in a different buffer), a stack pivot redirects ESP
to point at the controlled data:

```asm
xchg eax, esp ; ret    ; ESP = old EAX (must point to ROP chain)
mov esp, eax ; ret      ; same effect
add esp, 0x800 ; ret    ; jump ESP forward to reach data further up the stack
```

## SEH Overwrites

When `/GS` cookies block a direct return-address overwrite, structured
exception handling (SEH) records on the stack can be targeted instead.
The SEH chain is a linked list starting at `FS:[0]`. Overwriting the handler
pointer in an `EXCEPTION_REGISTRATION_RECORD` and then triggering an exception
diverts execution through the corrupted handler. See the SEH documentation in
this repository for the full technique.
