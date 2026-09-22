# 16. Recovering File and Protocol Formats

## Learning objectives

- Recover headers, magic bytes, versions, opcodes, flags, lengths, and payload
  boundaries from parser code.
- Distinguish file-format structure from in-memory structure.
- Use assembly evidence to build a byte-accurate format map.
- Identify parser bugs caused by trusting declared lengths or type fields.
- Design small test inputs that prove or disprove the recovered format.

## Concept discussion

A parser is a contract between bytes and code. The input does not arrive as
types; the program creates meaning by comparing, slicing, copying, dispatching,
and rejecting bytes.

When reversing a file or protocol format, the main question is:

```text
Which byte offsets must have which values before the parser trusts the rest?
```

Do not start by naming a struct. Start by building a map:

```text
offset  width  role          evidence
+0x00   2      magic         compared against 0x5A4D
+0x02   1      version       compared with 1 and 2
+0x03   1      opcode        drives jump table
+0x04   4      body length   checked against received/file size, then used as memcpy count
+0x08   N      body          pointer computed as base+8
```

Names are hypotheses. Offsets, widths, constants, branches, and call arguments
are facts.

### File format vs. in-memory structure

The same assembly pattern can mean two different things:

```asm
cmp word ptr [esi], 4D5Ah
mov eax, [esi+3Ch]
```

If `esi` points to bytes read from disk, this is a file/header parse. If `esi`
points to an allocated object built by the program, this is an in-memory
structure. The distinction matters because file and wire formats are attacker
controlled at the trust boundary; in-memory structures may already be validated
or synthesized by trusted code.

Use pointer provenance:

- `recv`, `ReadFile`, `fread`, memory-mapped files: external bytes.
- `HeapAlloc`, constructor-like initialization, local stack object: internal
  representation.
- decompression or decoding output: external bytes in a transformed buffer.
- `memcpy` from an external buffer into a local object: transition from wire
  format to internal structure.

## Common compiler patterns

- `cmp word ptr [buf], imm16`: two-byte magic or signature.
- `cmp dword ptr [buf], imm32`: four-byte magic, tag, or chunk type.
- `movzx eax, byte ptr [buf+2]`: one-byte version, type, flags, or opcode.
- `movzx eax, word ptr [buf+4]`: 16-bit length or field.
- `bswap eax`: big-endian dword conversion.
- `xchg al, ah` or `ror ax,8`: big-endian word conversion.
- `cmp len, minimum_header_size; jb reject`: short-header gate.
- `cmp declared_len, actual_len; ja reject`: declared length must fit received
  data.
- `lea edx, [buf+header_size]`: body starts after fixed header.
- `add eax, header_size`: total packet/file size from body length.
- `and eax, flag_mask`: flags field.
- compare chain or jump table keyed from a byte/word: opcode dispatch.
- CRC/checksum loop before accepting body data: integrity gate.

## Endianness: magic bytes tell the truth

IDA displays immediate values in numeric form, but memory stores bytes in
little-endian order on x86.

```asm
cmp dword ptr [esi], 314F5250h
```

The bytes in the file or packet are:

```text
50 52 4F 31
 P  R  O  1
```

So the magic is `"PRO1"`, not `"1ORP"`.

For 16-bit values:

```asm
cmp word ptr [esi], 4B4Fh
```

The bytes are:

```text
4F 4B
 O  K
```

If the parser uses `ntohs`, `ntohl`, `bswap`, or manual byte shifts before
comparison, the format field is likely big-endian or network-order.

## Fully annotated example

Assembly first:

```asm
parse_packet:
    push    ebp
    mov     ebp, esp
    sub     esp, 84h
    push    esi
    push    edi

    mov     esi, [ebp+8]          ; buf
    mov     edi, [ebp+0Ch]        ; received length

    cmp     edi, 8
    jb      reject

    cmp     dword ptr [esi], 314F5250h
    jnz     reject

    movzx   eax, byte ptr [esi+4]
    cmp     eax, 2
    ja      reject

    movzx   ecx, byte ptr [esi+5]
    cmp     ecx, 4
    ja      reject
    jmp     ds:off_403000[ecx*4]

case_2:
    movzx   edx, word ptr [esi+6]
    lea     eax, [edx+8]
    cmp     eax, edi
    ja      reject

    lea     eax, [ebp-80h]
    push    edx
    lea     ecx, [esi+8]
    push    ecx
    push    eax
    call    _memcpy
    add     esp, 0Ch
    xor     eax, eax
    jmp     done

reject:
    mov     eax, 0FFFFFFFFh
done:
    pop     edi
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
```

Annotated:

```asm
cmp edi, 8 / jb reject
; Minimum packet size is 8 bytes. Nothing before this point should be trusted as
; a complete field.

cmp dword ptr [esi], 314F5250h
; Magic bytes are 50 52 4F 31, ASCII "PRO1".

movzx eax, byte ptr [esi+4]
cmp eax, 2 / ja reject
; One-byte version at +0x04. Valid versions are 0, 1, and 2.

movzx ecx, byte ptr [esi+5]
cmp ecx, 4 / ja reject
jmp ds:off_403000[ecx*4]
; One-byte opcode at +0x05. Valid opcodes are 0 through 4. It drives a jump
; table.

movzx edx, word ptr [esi+6]
lea eax, [edx+8]
cmp eax, edi / ja reject
; Little-endian 16-bit body length at +0x06. Total packet size is 8+body_len.
; Reject if declared body extends past received data.

lea ecx, [esi+8]
push edx / push ecx / push eax / call _memcpy
; Body starts at +0x08. Body length is used as memcpy count.
```

Recovered format:

```text
+0x00  4 bytes  magic      "PRO1"
+0x04  1 byte   version    0..2
+0x05  1 byte   opcode     0..4, dispatch key
+0x06  2 bytes  body_len   little-endian uint16
+0x08  N bytes  body       N == body_len
```

Exploit note: the parser proves that `body_len` fits inside the received packet,
but it does not prove that `body_len` fits inside the local destination at
`[ebp-80h]`. If `body_len > 0x80`, this case handler is an overflow candidate.

## Recovering a header step by step

Use this loop for unknown formats:

1. Find the first size gate.
2. Record every fixed-offset load from the input pointer.
3. Record every constant comparison.
4. Convert magic constants back to byte order.
5. Identify fields that feed branches, jump tables, loops, pointer arithmetic,
   or copy counts.
6. Identify the first pointer computed as `base + constant`; that constant is
   often the fixed header size.
7. Track declared lengths separately from actual buffer length.
8. Write the smallest valid input that reaches a later parser block.
9. Mutate one field at a time to prove each hypothesis.

The most important discipline: never merge declared length, received length,
destination capacity, and loop counter into one vague word like "size." Those
are different values with different safety meanings.

## Recognizing field roles

### Magic/signature

Magic bytes are usually read early and compared to constants:

```asm
cmp word ptr [esi], 4142h
jnz reject
```

Little-endian bytes: `42 41`, ASCII `"BA"`.

### Version

Versions are commonly small integers with upper-bound checks:

```asm
movzx eax, byte ptr [esi+4]
cmp eax, 3
ja unsupported
```

This says valid versions are `0..3`, unless later code rejects version 0 or
requires a minimum.

### Opcode/type

Opcodes feed dispatch:

```asm
movzx ecx, byte ptr [esi+5]
cmp ecx, 7
ja reject
jmp ds:jump_table[ecx*4]
```

Record the valid range and follow each case separately. A safe opcode handler
does not prove the next handler is safe.

### Flags

Flags usually appear through masks:

```asm
movzx eax, byte ptr [esi+6]
test eax, 4
jnz compressed_path
and eax, 1
jnz authenticated_path
```

Here `+0x06` is not a plain enum; it is a bit field. Record each bit as a
separate hypothesis until code proves the role.

### Lengths and offsets

Length fields are dangerous because they turn data into pointer arithmetic:

```asm
mov ecx, [esi+8]
lea edx, [esi+10h]
push ecx
push edx
push edi
call _memcpy
```

The field at `+0x08` is not merely "some dword." It is a count passed to
`memcpy`. Now ask:

- Was it checked against actual input size?
- Was it checked against destination capacity?
- Was it sign-extended or zero-extended?
- Was a header size added, and can that addition overflow?
- Was it truncated from dword to word or byte?

### Checksums and CRCs

Integrity checks often look like a loop over the input followed by a comparison
with a header field:

```asm
xor     eax, eax
xor     ecx, ecx
loop_crc:
    movzx   edx, byte ptr [esi+ecx]
    xor     eax, edx
    inc     ecx
    cmp     ecx, [ebp-4]
    jb      loop_crc
cmp     eax, [esi+0Ch]
jnz     reject
```

You do not need to name the algorithm immediately. First record:

- start offset
- number of bytes covered
- initial value
- update operation
- stored/check field offset

## WinDbg verification

After recovering a tentative format, prove it with small inputs.

Break at the parser:

```text
0:000> bp app!parse_packet
0:000> g
0:000> dd esp L4
0:000> db poi(esp+4) L poi(esp+8)
```

At a copy call:

```text
0:000> bp app!memcpy ".printf \"dst=%p src=%p n=%x\\n\",poi(esp+4),poi(esp+8),poi(esp+c);db poi(esp+8) L20;g"
```

Useful test inputs:

```text
Bad magic        proves the signature gate.
Short header     proves the minimum size gate.
Bad opcode       proves dispatch range.
Body len = 0     proves empty payload handling.
Body len = 1     proves body offset.
Body len = max   probes capacity assumptions.
Declared > real  proves actual-length validation.
```

For a network protocol, do not send a raw cyclic pattern until the format is
valid enough to reach the vulnerable operation. A framed service may reject the
input before the copy ever runs.

## Practice drill

Take one parser function and fill this in before writing pseudocode:

```text
Input pointer:
Actual input length:
Minimum accepted length:

Recovered header:
  +0x00:
  +0x01:
  +0x02:
  +0x04:
  +0x08:

Magic bytes:
Version rules:
Opcode/type rules:
Flags:
Declared lengths:
Body offset:
Body length:

First dangerous use of a field:
Missing validation, if any:
Smallest valid input:
Next dynamic proof:
```

## Review checklist

Before trusting your recovered format, verify:

- Every fixed offset has a width and evidence source.
- Every immediate constant has been converted through little-endian memory
  order when it represents bytes.
- Declared lengths are separated from actual input length and destination
  capacity.
- Dispatch fields are mapped to every reachable handler.
- Rejected paths and success paths are both understood.
- Checksums, compression, or decoding steps are recorded before downstream
  parser analysis.
- At least one small valid input reaches the expected handler.
- At least one bad input fails at the expected gate.
