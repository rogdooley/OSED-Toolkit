# 12. Case Studies from Vulnerable Windows Service Patterns

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

## Case study 2: SEH-based exploitation

```asm
sub_402300:
    push    ebp
    mov     ebp, esp
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax               ; store /GS cookie at [ebp-4]
    push    offset handler_402400      ; SEH handler
    push    dword ptr fs:[0]           ; previous SEH record
    mov     fs:[0], esp                ; register exception handler
    sub     esp, 100h
    lea     ecx, [ebp-10Ch]            ; local buffer (256 bytes)
    push    [ebp+0Ch]                  ; attacker-controlled count
    push    [ebp+8]                    ; attacker-controlled source
    push    ecx
    call    _memcpy
    add     esp, 0Ch
    ; ... normal processing ...
    pop     dword ptr fs:[0]           ; restore SEH chain
    add     esp, 4
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    @__security_check_cookie@4 ; verify /GS cookie
    mov     esp, ebp
    pop     ebp
    retn
```

Stack layout:

```text
Higher addresses
+--------------------------------------+
| [ebp+0Ch]   arg1 (count)             |
| [ebp+08h]   arg0 (source ptr)        |
| return address                       |
| saved EBP                   <-- EBP  |
| /GS cookie        [ebp-04h]          |
| SEH handler addr   [ebp-08h]         |  <-- EXCEPTION_REGISTRATION_RECORD
| prev SEH (nSEH)   [ebp-0Ch]          |
| ... 256 bytes of buffer ...          |
| buffer start       [ebp-10Ch]        |
+--------------------------------------+
Lower addresses
```

### Why SEH wins over /GS

The overflow writes upward from `[ebp-10Ch]`:
1. Fills 256 bytes of buffer.
2. Overwrites nSEH at `[ebp-0Ch]` (4 bytes).
3. Overwrites SEH handler at `[ebp-08h]` (4 bytes).
4. Overwrites /GS cookie at `[ebp-04h]`.
5. Overwrites saved EBP and return address.

The /GS cookie check runs in the epilogue AFTER the function returns normally.
But the overflow may trigger an access violation (writing past the guard page),
which invokes the SEH handler BEFORE the epilogue runs. The cookie check never
executes.

### Exploit construction

```text
Overflow buffer layout:
+--------------------------------------+
| 256 bytes padding (0x41 * 256)       |
| nSEH = EB 06 90 90 (short jmp +6)   |
| SEH  = <POP POP RET from non-SafeSEH module> |
| 6 bytes alignment padding            |
| shellcode or ROP chain               |
+--------------------------------------+
```

When the exception fires:
1. Windows calls the corrupted SEH handler (POP-POP-RET gadget).
2. The gadget pops two values and `ret` lands on nSEH.
3. nSEH contains `EB 06` (short jump forward 6 bytes).
4. Execution reaches the shellcode after the alignment padding.

### Verify in WinDbg

```
0:000> !exchain                  ; before overflow: clean chain
0:000> g                         ; trigger overflow
0:000> !exchain                  ; after overflow: handler = POP-POP-RET addr
0:000> bp <pop_pop_ret_addr>     ; break at gadget
0:000> g
0:000> p; p; p                   ; step: pop, pop, ret -> lands on nSEH
0:000> u eip                     ; should show EB 06 (jmp short)
```

## Case study 3: format string in logging

```asm
sub_402500:
    push    ebp
    mov     ebp, esp
    sub     esp, 200h
    mov     eax, [ebp+8]              ; arg0 = client session
    mov     ecx, [eax+10h]            ; ECX = log message from client buffer
    lea     edx, [ebp-200h]
    push    ecx                       ; format string (ATTACKER CONTROLLED)
    push    edx                       ; destination buffer (512 bytes local)
    call    _sprintf
    add     esp, 8
    lea     edx, [ebp-200h]
    push    edx
    call    write_log
    add     esp, 4
    mov     esp, ebp
    pop     ebp
    retn
```

### Analysis

The client message at `[session+0x10]` is passed directly as `sprintf`'s
format string. The programmer intended to log the message as text, but
`sprintf` interprets it as a format command string.

### What the attacker can do

1. **Read the stack** with `%x` or `%08x`: each specifier reads one dword
   from the stack above the format string argument. After 3-4 `%x` specifiers,
   the attacker can see the saved EBP, return address, and /GS cookie.

2. **Write to memory** with `%n`: the specifier writes the number of characters
   output so far to the address stored in the corresponding stack dword. Using
   direct parameter access (`%N$n`), the attacker targets a specific stack slot.

3. **Partial writes** with `%hn` (16-bit) or `%hhn` (8-bit) to construct
   arbitrary values in two or four writes.

### Exploit strategy

```text
1. Leak stack values:  send "%x.%x.%x.%x.%x.%x.%x.%x"
   Read response to extract return addresses and cookie.

2. Calculate offsets:  find the stack slot containing a target address
   (return address, function pointer, or SEH handler).

3. Write payload:      use %hn writes to overwrite the target with shellcode
   address or ROP gadget, splitting the 32-bit value into two 16-bit writes.

4. Trigger execution:  when the function returns (or exception fires), EIP
   goes to the overwritten address.
```

### Verify in WinDbg

```
0:000> bp app!sub_402500
0:000> g
0:000> da poi(ebp+8)+10h         ; view format string content
0:000> dd esp L20                ; view stack that %x will read
0:000> bp app!sprintf            ; break inside sprintf
0:000> g
0:000> dd esp L8                 ; sprintf args: dest, fmt, ...
```

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
    mov     esp, ebp
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    mov     esp, ebp
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

## Key takeaways

- Real bugs hide behind layers: dispatcher -> handler -> parser -> copy helper.
  Follow attacker data through each layer, do not stop at the first function.
- A length check only protects the buffer it compares against. A check proving
  "copy length <= source length" says nothing about destination capacity.
- SEH overwrites bypass /GS cookies because the exception handler fires before
  the epilogue cookie check. Look for SEH registration in functions with buffers.
- Format string bugs turn string data into arbitrary read/write primitives.
  Any function that passes attacker data as a format argument is exploitable.
- Always fill the complete exploit ledger before writing exploit code: data
  origin, gate conditions, missing invariants, impact, mitigations, bad chars.

## See also

- `x86-osed-assembly-reference/11-buffers-and-stack-overflows.md` -- overflow
  mechanics, offset calculation, cyclic patterns.
- `x86-osed-assembly-reference/22-format-string-assembly-concepts.md` -- format
  specifier behavior and partial-write technique.
- `osed-reversing-guide/13-worked-example.md` -- full worked reversing example.
- `DRILLS/stack_overflow.md` -- stack overflow practice drills.
- `DRILLS/crash_analysis.md` -- crash triage drills.
- `Tools/exploit/` -- exploit construction framework.
- `Tools/badchars/` -- bad character identification.
- `Tools/pattern/` -- cyclic pattern for offset calculation.
