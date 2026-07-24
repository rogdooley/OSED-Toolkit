# Case Studies from Vulnerable Windows Service Patterns

## Learning objectives

- Apply the full methodology to realistic service-handler shapes.
- Follow attacker-controlled network data through dispatch, auth, parsers, and
  copy helpers.
- Distinguish suspicious-safe code from exploitable code.
- Build an exploit-relevant model without relying on source names.

## Concept discussion

Real vulnerable services rarely put the bug in the first function you open. The
dispatcher routes by opcode. The handler checks auth. The parser extracts fields.
The helper copies bytes. The bug appears when a programmer assumption at one
layer is not enforced at the layer doing memory writes.

These case studies are modeled on patterns found in the repository's Windows x86
training labs under `Tools/` and `scripts/`. The function names below are
representative; the actual lab binaries use similar shapes:

- opcode dispatch similar to `dispatch_command`
- safe copy helpers similar to `copy_metadata` and `copy_echo_payload`
- unsafe record copy similar to `copy_record_payload`
- auth-gated parser routing similar to config-set handlers

## Common compiler patterns

- `strncmp` dispatch: compare command prefixes, branch to handlers.
- Switch dispatch: opcode range check and jump table.
- Safe copy helper: `if (len >= dst_size) fail; memcpy; dst[len]=0`.
- Unsafe copy helper: local buffer plus attacker-controlled count.
- Auth gate: session field checked before parser call.
- Response/logging calls: noise unless they consume attacker data dangerously.

## Fully annotated example

Assembly first:

```asm
sub_402000:
    push    ebp
    mov     ebp, esp
    sub     esp, 84h
    mov     eax, [ebp+0Ch]
    cmp     eax, [ebp+10h]
    ja      reject
    lea     ecx, [ebp-80h]
    push    eax
    push    [ebp+8]
    push    ecx
    call    _memcpy
    add     esp, 0Ch
    xor     eax, eax
    mov     esp, ebp
    pop     ebp
    retn
reject:
    mov     eax, 0FFFFFFFFh
    mov     esp, ebp
    pop     ebp
    retn
```

Annotated:

```asm
sub esp,84h / lea ecx,[ebp-80h]
; Local stack buffer around 128 bytes.

mov eax,[ebp+0Ch]
cmp eax,[ebp+10h] / ja reject
; Checks copy_len <= source_len or declared_len. This is not a destination
; capacity check.

push eax / push [ebp+8] / push ecx / call _memcpy
; Copy attacker-controlled count into fixed local destination if prior length
; relation holds.
```

The key semantic failure: the code proves the copy does not read past the source
record, but it does not prove the local destination can hold the copy. The
programmer assumed "copy length is valid" meant "copy length is safe for every
destination." The compiler merely implemented that assumption.

## Reverse engineering thought process

Case-study ledger:

```text
data origin: network body, through parser
gate: copy_len <= source_len
missing invariant: copy_len < sizeof(local_buffer)
destination: stack local
impact: overwrite frame if copy_len > 0x80
next steps: identify reachability, saved return offset, cookie/SEH, bad chars,
DEP strategy
```

A reverse engineer explains the bug as an invariant mismatch. An exploit
developer turns the mismatch into control: offset, controllable bytes, reliable
return path, and mitigation bypass.

## Common mistakes

- Seeing a length check and declaring the copy safe.
- Ignoring which buffer the length check protects.
- Stopping at opcode dispatch instead of following the body pointer.
- Treating auth gates as blockers instead of reachability conditions.
- Confusing source length, requested copy length, and destination capacity.

## Exercises

Assembly only:

```asm
sub_402080:
    push    ebp
    mov     ebp, esp
    sub     esp, 40h
    mov     eax, [ebp+8]
    cmp     byte ptr [eax+24h], 0
    jz      noauth
    lea     ecx, [ebp-40h]
    push    [ebp+10h]
    push    [ebp+0Ch]
    push    ecx
    call    parse_set_line
    add     esp, 0Ch
    test    eax, eax
    jnz     bad
    xor     eax, eax
    mov     esp, ebp
    pop     ebp
    retn
noauth:
    mov     eax, 0FFFFFFFEh
    mov     esp, ebp
    pop     ebp
    retn
bad:
    mov     eax, 0FFFFFFFFh
    mov     esp, ebp
    pop     ebp
    retn
```

Questions:

- What must be true before parser execution?
- What is the likely role of the local buffer passed to `parse_set_line`?
- What exploit question does the third argument raise?
- Where should you go next?

## Challenge problems

Assembly only:

```asm
sub_402100:
    push    ebp
    mov     ebp, esp
    sub     esp, 48h
    lea     eax, [ebp-40h]
    push    eax
    push    offset fmt_get
    push    [ebp+8]
    call    _sscanf
    add     esp, 0Ch
    cmp     eax, 1
    jnz     fail
    lea     eax, [ebp-40h]
    push    eax
    call    config_lookup
    add     esp, 4
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     ebp
    retn
```

Assume `fmt_get` may be either `"get %63s"` or `"get %s"`. Explain how the
security conclusion changes and how to prove which one is present.

## Solutions with reasoning

Exercise solution:

The session/client field at offset `+0x24` must be nonzero before the parser
runs. That is likely an auth or state gate. The local buffer at `ebp-0x40` (64
bytes) is passed as the first argument to `parse_set_line`, likely as a
destination for parsed output. The second argument is `[ebp+0Ch]` (caller body
pointer) and the third is `[ebp+10h]` (caller length or size). The exploit
question is whether `parse_set_line` can write more than 64 bytes into the local
buffer based on the third argument. The next target is `parse_set_line`, because
this wrapper only gates and forwards.

Plausible pseudocode:

```c
int handle_set(Client *c, const char *body, unsigned len) {
    char local[64];
    if (!c->authenticated) return -2;
    if (parse_set_line(local, body, len) != 0) return -1;
    return 0;
}
```

Challenge solution:

If the format is `"get %63s"`, `_sscanf` writes at most 63 non-whitespace bytes
plus a terminator into a 64-byte buffer, which matches the local buffer size. If
the format is `"get %s"`, the copy is unbounded and can overflow the local
buffer. Prove it by following the `fmt_get` data reference in IDA/Ghidra or by
dumping the address in WinDbg with `da fmt_get`. The security conclusion depends
on the format string, not on the presence of `_sscanf` alone.

## Final capstone

Analyze this complete function as if it were unknown:

```asm
sub_402200:
    push    ebp
    mov     ebp, esp
    sub     esp, 0CCh
    push    esi
    mov     esi, [ebp+8]
    test    esi, esi
    jz      fail
    cmp     byte ptr [esi+20h], 0
    jz      fail
    mov     eax, [ebp+10h]
    cmp     eax, [ebp+14h]
    ja      fail
    lea     ecx, [ebp-80h]
    push    eax
    push    [ebp+0Ch]
    push    ecx
    call    _memcpy
    add     esp, 0Ch
    lea     eax, [ebp-80h]
    push    eax
    call    process_record
    add     esp, 4
    xor     eax, eax
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
```

Solution:

Facts:

- `arg0` is a pointer, preserved in ESI.
- `arg0` must be non-null.
- Byte field `arg0+0x20` must be nonzero before processing.
- `arg2 <= arg3` unsigned is required before the copy.
- Destination is a stack local at `ebp-0x80`.
- Source is `arg1`.
- Count is `arg2`.
- The local buffer is passed to `process_record`.

Interpretation:

This is an auth/state-gated record-processing wrapper. It checks that the copy
length does not exceed some source/declaration length, copies into a fixed stack
buffer, then processes the local copy.

Exploit reasoning:

The length check does not mention the destination capacity. If `arg2` can exceed
`0x80`, this is a stack-overflow candidate even though a length check exists. If
a stack cookie is absent, saved return address or saved registers may be
reachable. If a cookie exists in a real build, look for SEH layout, non-return
control flow, adjacent object corruption, or a different bug path.

Plausible pseudocode after reasoning:

```c
int handle_record(Client *c, const unsigned char *body,
                  unsigned copy_len, unsigned declared_len) {
    unsigned char local[128];

    if (!c) return -1;
    if (!c->authenticated) return -1;
    if (copy_len > declared_len) return -1;

    memcpy(local, body, copy_len);
    process_record(local);
    return 0;
}
```

The reverse engineer's final model is not "memcpy overflow." It is: an
authenticated record handler validates source bounds but fails to validate
destination capacity before copying network-controlled bytes into a stack local.

---

## Appendix A: Exercise answering template

Use this before pseudocode:

```text
Function boundary:
Inputs:
Outputs:
Memory reads:
Memory writes:
Calls:
Branch questions:
Value ranges after checks:
Compiler artifacts:
Programmer assumptions:
Attacker-controlled values:
Exploit relevance:
Unresolved facts to verify:
```

## Appendix B: Fast semantic checklist

- `test p,p` before `[p+off]`: null guard.
- `movzx`: unsigned narrow value.
- `movsx`: signed narrow value.
- `ja/jb`: unsigned comparison.
- `jg/jl`: signed comparison.
- `lea` without later dereference: arithmetic.
- `lea local; push local; call`: address-taken local.
- `dst[len]=0`: string termination and possible off-by-one.
- `len < cap`: usually leaves room for terminator.
- `len <= cap`: dangerous if terminator is also written.
- `call [reg+off]`: code pointer read from data.
- `jmp __imp_*`: import thunk.
- `__security_check_cookie`: compiler protection, not business logic.
- `__chkstk`: large stack allocation, not application loop.

## Appendix C: WinDbg verification prompts

Use WinDbg to promote hypotheses to facts:

```text
bp module!function
uf module!function
dd esp L20
dd ebp-100 L80
da poi(esp+4)
dds poi(table) L10
ba w4 address
!exchain
kv
```

Verify:

- actual argument order at call sites
- whether source bytes are attacker-controlled
- exact overwrite offset
- stack cookie placement
- SEH chain position
- imported API addresses
- whether a suspicious path is reachable
