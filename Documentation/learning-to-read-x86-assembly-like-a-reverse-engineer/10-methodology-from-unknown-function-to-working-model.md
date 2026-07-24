# Methodology: From Unknown Function to Working Model

## Learning objectives

- Analyze an unknown function with a repeatable process.
- Track origin, destination, control conditions, and invariants.
- Separate facts, hypotheses, and unresolved questions.
- Know when to switch from IDA/Ghidra to WinDbg.

## Concept discussion

Good reverse engineering is disciplined uncertainty reduction. You do not need
to understand every instruction at once. You need to identify the load-bearing
facts and test the model.

Use this method:

1. Find boundaries: prologue, epilogue, tail calls, exception exits.
2. Identify inputs: arguments, globals, object fields, imports, prior calls.
3. Identify outputs: return value, writes, calls, global changes.
4. Recover guards: null checks, bounds checks, auth checks, type checks.
5. Track attacker-controlled values.
6. Identify invariants after each guard.
7. Classify compiler artifacts.
8. Draft pseudocode only after the fact ledger stabilizes.
9. Verify uncertain facts in WinDbg.

## Common compiler patterns

- Repeated `return -1` blocks: validation failure.
- Calls one layer deeper: wrappers hiding real behavior.
- Status codes checked with `test eax,eax` or `cmp eax,0`.
- Auth/session fields checked before parser calls.
- Logging calls that use attacker data but do not consume it dangerously.

## Fully annotated example

```asm
sub_401900:
    push    ebp
    mov     ebp, esp
    push    esi
    mov     esi, [ebp+8]
    cmp     byte ptr [esi+20h], 0
    jz      noauth
    push    [ebp+10h]
    push    [ebp+0Ch]
    call    parse_config_set
    add     esp, 8
    test    eax, eax
    jnz     bad
    push    offset ok_msg
    push    esi
    call    send_status
    add     esp, 8
    pop     esi
    pop     ebp
    retn
noauth:
    push    offset auth_msg
    push    esi
    call    send_status
    add     esp, 8
    pop     esi
    pop     ebp
    retn
bad:
    push    offset bad_msg
    push    esi
    call    send_status
    add     esp, 8
    pop     esi
    pop     ebp
    retn
```

Annotated:

```asm
mov esi, [ebp+8]
cmp byte ptr [esi+20h], 0 / jz noauth
; Session/client object has an auth-like byte at +0x20. It gates parser access.

push [ebp+10h] / push [ebp+0Ch] / call parse_config_set
; Body pointer and body length are passed one layer deeper. The bug, if any, is
; probably not in this wrapper.

test eax,eax / jnz bad
; Parser status controls response.
```

The CPU is answering: "Is this client authenticated, and did the parser accept
the body?" The programmer wrote workflow control. An exploit developer follows
the attacker-controlled body into `parse_config_set`.

## Reverse engineering thought process

Fact ledger:

```text
arg0 = client/session pointer
field +0x20 gates parser
arg1/arg2 = parser inputs
parse_config_set returns zero on success
send_status consumes result messages
```

Open questions:

```text
What writes field +0x20?
Where do arg1/arg2 originate?
Does parse_config_set copy without bounds?
Can auth be bypassed or legitimately obtained?
```

## Common mistakes

- Stopping at the handler and declaring it safe.
- Treating auth gates as irrelevant because they are not memory corruption.
- Spending time on response formatting before following input data.
- Writing pseudocode before knowing which arguments are body pointer and length.

## Exercises

```asm
sub_401980:
    mov     eax, [esp+4]
    cmp     dword ptr [eax+14h], 3
    jnz     short reject
    push    [esp+0Ch]
    push    [esp+0Ch]
    call    sub_402500
    add     esp, 8
    retn
reject:
    mov     eax, 0FFFFFFFFh
    retn
```

Questions:

- What is the gate?
- What value flows past the gate?
- What must be verified before trusting the stack offsets?

## Challenge problems

Given a function with one obvious unsafe `memcpy`, list the evidence you need
before calling it exploitable.

## Solutions with reasoning

Exercise solution:

The gate is a field comparison at object offset `+0x14` against value `3`.
Arguments after the gate are forwarded into `sub_402500`, but the repeated
`[esp+0Ch]` is suspicious because pushes change ESP. Verify actual arguments by
normalizing stack deltas in IDA or breaking before the call and dumping the
stack. The source-level model is "only state 3 may call worker."

Challenge solution:

You need destination location and size, copy count, source control, reachability,
mitigations, overwrite target, and post-overwrite control flow. Unsafe-looking
copy is not enough. A bounded copy into a large buffer may be safe; an unbounded
copy may be unreachable; an exploitable copy must connect attacker bytes to a
security-relevant overwrite under reachable conditions.

---
