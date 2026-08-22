# 10. Methodology: From Unknown Function to Working Model

## Learning objectives

- Analyze an unknown function with a repeatable process.
- Track origin, destination, control conditions, and invariants.
- Separate facts, hypotheses, and unresolved questions.
- Apply IDA-specific and WinDbg-specific workflows to real analysis.
- Know when to switch from static to dynamic analysis.

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

### Decision flowchart

```text
Start: unknown function
  |
  v
Identify calling convention (cdecl/stdcall/thiscall/fastcall)
  |
  v
Map arguments and locals from frame layout
  |
  v
Classify each call: API import? internal? indirect?
  |
  v
Is any argument attacker-controlled?
  |No --> Low priority (deprioritize, move to next function)
  |Yes
  v
Does it copy or write using attacker-influenced values?
  |No --> Check for format strings, indirect calls, array indexing
  |Yes
  v
Is the copy bounded to destination capacity?
  |Yes --> Is the bound correctly computed? (signed? off-by-one?)
  |No
  v
EXPLOITABLE CANDIDATE -- verify mitigations and reachability
```

## IDA workflow

### Finding attack surface

1. **Open the Imports window** (View -> Open subviews -> Imports). Search for
   dangerous functions: `recv`, `ReadFile`, `memcpy`, `strcpy`, `sprintf`,
   `sscanf`, `HeapAlloc`, `VirtualAlloc`.

2. **Cross-reference callers** (select the import, press `x` or Ctrl+X). This
   lists every location that calls the function. Follow each caller.

3. **Trace data flow forward**: from `recv` or `ReadFile`, identify the buffer
   argument and trace it through subsequent function calls. Look for the buffer
   being passed as a source to `memcpy`, `strcpy`, or `sprintf`.

4. **Examine frame layout**: in the function containing a suspicious copy, look
   at the local variable panel (left side of IDA). `var_80` means `[ebp-80h]`,
   which is 128 bytes below EBP. If `memcpy` writes into `var_80` with a count
   larger than 128, it overflows.

5. **Check the decompiler** (F5, if Hex-Rays is available): use it as a
   hypothesis generator, not as ground truth. The decompiled C is a guess that
   may have wrong types, wrong signedness, or merged variables. Verify every
   claim against the actual instructions.

### Key IDA shortcuts

```text
x or Ctrl+X    Cross-references to/from current address
n              Rename function or variable
y              Set type for function or variable
g              Go to address
Ctrl+F         Search in current view
Space          Toggle graph/text view
F5             Decompile (Hex-Rays)
Shift+F12      Strings window
```

## WinDbg workflow

### When to switch from static to dynamic

Switch to WinDbg when:
- You need to verify argument values at runtime.
- The static analysis shows a suspicious copy but you cannot determine if the
  count is attacker-controlled.
- You need to trigger the vulnerability and observe the crash.
- You need to calculate the exact overflow offset.
- ASLR or other runtime state affects the analysis.

### Attach and set initial breakpoints

```
0:000> .sympath srv*c:\symbols*https://msdl.microsoft.com/download/symbols
0:000> .reload /f
0:000> bp app!recv                         ; break on network input
0:000> bp app!sub_401900                   ; break at target function
0:000> g
```

### Examine function entry state

```
0:000> dd esp L8         ; view stack: return addr, arg0, arg1, arg2, ...
0:000> da poi(esp+4)     ; if arg0 is a string pointer, print it
0:000> db poi(esp+8) L40 ; if arg1 is a buffer pointer, dump first 64 bytes
0:000> r                 ; view all registers
```

### Trace data flow from recv

```
0:000> bp ws2_32!recv
0:000> g
Hit breakpoint:
0:000> dd esp L4         ; args: socket, buf, len, flags
0:000> dd poi(esp+4) L10 ; preview buffer location
0:000> g                 ; let recv complete
0:000> db poi(esp+4) L poi(esp+8)  ; view received data
```

### Monitor copy operations

```
0:000> bp app!memcpy ".printf \"memcpy(dst=%p, src=%p, n=%x)\\n\",poi(esp+4),poi(esp+8),poi(esp+c);g"
```

This conditional breakpoint prints the memcpy arguments and continues,
creating a log of every copy operation with sizes.

### After a crash

```
0:000> .ecxr             ; switch to exception context
0:000> r                 ; view registers at crash
0:000> !exchain          ; view SEH chain (for SEH exploits)
0:000> kb                ; stack backtrace
0:000> !address eip      ; determine what module EIP is in
0:000> !address esp      ; verify stack region
```

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

### Exploitability checklist

Before declaring a function exploitable, verify:

```text
[ ] Attacker-controlled data reaches the function (trace from recv/ReadFile)
[ ] The vulnerable operation uses attacker data (not just constant values)
[ ] Destination buffer size is known (from frame layout or allocation)
[ ] Copy count exceeds destination capacity under attacker control
[ ] Overflow reaches a security-relevant target (return address, SEH, pointer)
[ ] Mitigations are identified (/GS cookie, SafeSEH, DEP, ASLR)
[ ] A bypass strategy exists for each mitigation
[ ] Bad characters are identified for the input path
[ ] Sufficient payload space exists (or egghunter is viable)
```

### OSED exam time management

The exam is 48 hours, proctored, no internet. Suggested allocation for 3
targets:

```text
Phase                  | Time
-----------------------|------
Reconnaissance (all 3) | 4 hours
Target 1 analysis      | 4 hours
Target 1 exploit dev   | 6 hours
Target 2 analysis      | 4 hours
Target 2 exploit dev   | 6 hours
Target 3 analysis      | 4 hours
Target 3 exploit dev   | 6 hours
Report writing         | 6 hours
Buffer / debugging     | 8 hours
```

Do not spend more than 10 hours on any single target before moving to the next.
Coming back with fresh eyes often breaks a deadlock.

## Common mistakes

- Stopping at the handler and declaring it safe.
- Treating auth gates as irrelevant because they are not memory corruption.
- Spending time on response formatting before following input data.
- Writing pseudocode before knowing which arguments are body pointer and length.
- Trying to understand every function before identifying the attack surface.
  Start from dangerous operations and trace backward to attacker input.
- Not using conditional breakpoints in WinDbg to log function arguments.
  Manual stepping through hundreds of calls is too slow.

## Exercises

### Exercise 1

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

### Exercise 2

```asm
sub_402000:
    push    ebp
    mov     ebp, esp
    sub     esp, 100h
    mov     eax, [ebp+8]        ; arg0 = session pointer
    mov     ecx, [eax+0Ch]      ; ECX = buffer from session object
    push    ecx                  ; source
    lea     edx, [ebp-100h]
    push    edx                  ; destination (256-byte local)
    call    _strcpy
    add     esp, 8
    lea     edx, [ebp-100h]
    push    edx
    call    process_command
    add     esp, 4
    mov     esp, ebp
    pop     ebp
    retn
```

Apply the 9-step methodology. Fill out a fact ledger and list open questions.
Is this function exploitable? What additional information do you need?

### Exercise 3

You are analyzing a network service. In IDA, you find that `ws2_32!recv` is
called in function `sub_401000`. Using cross-references, you trace the received
buffer through `sub_401200` (which parses a length field) and into `sub_401400`
(which calls `memcpy`).

In `sub_401400`, the frame layout shows `sub esp, 80h` and
`lea eax, [ebp-80h]` as the memcpy destination. The count argument comes from
`[ebp+0Ch]`, which is the parsed length from `sub_401200`.

Write the WinDbg commands to:
1. Break when `sub_401400` is called.
2. Print the destination address, source address, and count.
3. Determine if the count can exceed 0x80.

## Challenge problems

Given a function with one obvious unsafe `memcpy`, list the evidence you need
before calling it exploitable. Structure your answer as a checklist with
specific WinDbg commands or IDA steps for each item.

## Solutions with reasoning

### Exercise 1 solution

The gate is a field comparison at object offset `+0x14` against value `3`.
Arguments after the gate are forwarded into `sub_402500`, but the repeated
`[esp+0Ch]` is suspicious because pushes change ESP. After `push [esp+0Ch]`
(first push), ESP decreases by 4, so the second `push [esp+0Ch]` reads from
a different original offset. Normalize: the first push reads `[original_esp+0Ch]`
= arg2; after the push, the second `push [esp+0Ch]` reads `[original_esp+08]`
= arg1. So `sub_402500(arg1, arg2)`. Verify by breaking before the call and
dumping the stack. The source-level model is "only state 3 may call worker."

### Exercise 2 solution

Fact ledger:

```text
Inputs:
  arg0 = session pointer
  [arg0+0Ch] = buffer pointer (source for strcpy)

Outputs:
  return value: implicit (EAX not set before retn)

Important reads:
  [eax+0Ch] -- loads buffer pointer from session object

Important writes:
  strcpy writes into [ebp-100h], a 256-byte local buffer

Branch questions:
  None -- no validation, no bounds check

Validated ranges:
  NONE -- this is the problem

Compiler artifacts:
  Standard EBP frame, no /GS cookie visible

Programmer assumptions:
  The buffer at [session+0Ch] is shorter than 256 bytes

Exploit relevance:
  strcpy has no length limit. If [session+0Ch] points to a string longer
  than 255 bytes (plus NUL), it overflows the 256-byte buffer.
```

Open questions:
- Where does the session buffer content come from? (network input?)
- Is there a length check in the caller or in the code that populates
  [session+0Ch]?
- Is there a /GS cookie (check the full function, not just this snippet)?
- Is there an SEH record on the stack between the buffer and saved EBP?

The function is exploitable IF the session buffer content is attacker-controlled
and can exceed 255 bytes. The `strcpy` call has no bounds check.

### Exercise 3 solution

```
0:000> bp app!sub_401400 ".printf \"sub_401400 called\\n\"; .echo; dd esp+4 L3; g"
```

Or more precisely:

```
0:000> bp app!sub_401400
0:000> g
Hit breakpoint:
0:000> dd esp L4              ; return addr, arg0 (dest), arg1 (src), arg2 (count)
0:000> ? poi(esp+0Ch)         ; evaluate count as a number
0:000> .if (poi(esp+0Ch) > 80) { .printf "OVERFLOW: count = %x\n", poi(esp+0Ch) } .else { .printf "safe: count = %x\n", poi(esp+0Ch) }
0:000> g
```

Send inputs of increasing size and check whether the count at `[esp+0Ch]` ever
exceeds 0x80. If it does, the memcpy will overflow the 128-byte destination.

### Challenge solution

Evidence checklist for exploitable memcpy:

```text
[ ] Reachability: trace from recv/ReadFile to this function
    IDA: x-ref chain from recv caller to this function
    WinDbg: bp on function, send network input, verify it hits

[ ] Source control: does attacker control the source buffer content?
    WinDbg: db poi(esp+8) L20 at memcpy -- compare with sent payload

[ ] Count control: does attacker influence the count argument?
    WinDbg: ? poi(esp+c) at memcpy -- send varying lengths, observe count

[ ] Destination size: what is the buffer capacity?
    IDA: check sub esp, N and lea for destination -- capacity = N or offset

[ ] Overflow: can count exceed capacity?
    WinDbg: send payload with count > capacity, observe crash

[ ] Target: what gets overwritten?
    WinDbg: !exchain (SEH), dd ebp L2 (saved EBP + return addr)
    Calculate: offset from buffer to return address = capacity + saved_ebp(4)

[ ] Mitigations:
    WinDbg: !checksec, !nmod (ASLR, SafeSEH status)
    IDA: look for __security_cookie (GS), SEH registration
    WinDbg: !exploitable (after crash)

[ ] Bad characters:
    Send 0x00-0xFF test pattern, compare in memory
    WinDbg: db <buffer> L100

[ ] Payload space:
    Count how many controlled bytes between overflow start and crash
    Determine if egghunter is needed for small spaces
```

## Key takeaways

- Follow the 9-step methodology: boundaries, inputs, outputs, guards,
  attacker-controlled values, invariants, compiler artifacts, pseudocode,
  WinDbg verification.
- Start from dangerous operations (memcpy, strcpy, sprintf) and trace backward
  to attacker input. Do not analyze every function sequentially.
- IDA's cross-references (Ctrl+X) are the primary tool for tracing data flow
  between functions. The decompiler is a hypothesis generator, not ground truth.
- WinDbg conditional breakpoints (`bp addr "commands"`) turn manual stepping
  into automated logging. Use them to monitor every memcpy call with arguments.
- Never declare a function exploitable from static analysis alone. Verify
  attacker reachability, count control, and overflow impact in the debugger.

## See also

- `osed-reversing-guide/how-to-think-while-reversing.md` -- complementary
  reversing mindset guide.
- `osed-reversing-guide/07-data-flow.md` -- data flow tracing methodology.
- `osed-reversing-guide/12-ida-windbg-loop.md` -- IDA and WinDbg integration.
- `osed-reversing-guide/13-worked-example.md` -- full worked example applying
  methodology to a real binary.
- `DRILLS/function_analysis.md` -- function analysis practice drills.
- `DRILLS/dataflow.md` -- data flow tracing drills.
- `DRILLS/windbg_investigation.md` -- WinDbg investigation drills.
- `Tools/crashtriage/` -- automated crash triage.
- `Tools/pattern/` -- cyclic pattern generation for offset calculation.
