# 13. Printable Worksheets and Checklists

Use these pages while working through unknown functions. They are intentionally
repetitive. The repetition builds the habit that matters in real reversing:
facts first, source reconstruction second.

### Unknown function worksheet

```text
Function address/name:
Caller(s):
Callee(s):

Boundary:
  Prologue:
  Epilogue:
  Tail calls:
  Exception exits:

Incoming values:
  [ ] stack arguments
  [ ] register arguments
  [ ] globals
  [ ] object fields
  [ ] imported/runtime state

Outgoing values:
  [ ] EAX return
  [ ] memory writes
  [ ] global writes
  [ ] calls with modified arguments
  [ ] indirect control flow

Compiler scaffolding:
  [ ] saved registers
  [ ] frame allocation
  [ ] stack cookie
  [ ] stack probe
  [ ] SEH registration
  [ ] import thunk

One-sentence current hypothesis:

Evidence that supports it:

Evidence that contradicts or weakens it:

Next verification step:
```

### Branch worksheet

```text
Compare/test instruction:
Conditional jump:
Signed or unsigned:
Taken edge means:
Fall-through edge means:

Value constrained:
Constraint after taken edge:
Constraint after fall-through edge:

Is this a validation gate?
  [ ] null check
  [ ] type/opcode check
  [ ] length/capacity check
  [ ] auth/state check
  [ ] error/status check
  [ ] other

What becomes safe after this branch?

What is still not proven?
```

### Call-site worksheet

```text
Call target:
Direct or indirect:
Caller cleanup or callee cleanup:

Arguments:
  Note: arg0 is the first C parameter, usually `[ebp+8]`; it is pushed last at a cdecl/stdcall call site.
  arg0:
  arg1:
  arg2:
  arg3:
  arg4:

For each pointer argument:
  Origin:
  Points to:
  Read or write:
  Size/capacity:
  Attacker-controlled:

Return value use:
  [ ] ignored
  [ ] zero/nonzero check
  [ ] signed error check
  [ ] pointer dereference
  [ ] length/count
  [ ] stored for later

Question this call answers:
```

### Pointer provenance and alias worksheet

```text
Pointer value:
First observed at:
Original source:
  [ ] stack argument
  [ ] register argument
  [ ] global
  [ ] heap allocation
  [ ] object field
  [ ] return value
  [ ] computed address

Copies/aliases:
  register alias 1:
  register alias 2:
  stack spill:
  structure field:
  global/table entry:

Adjustments:
  added offset:
  scaled index:
  pointer increment:
  cast or width change:

Dereferences:
  read at:
  write at:
  width:

Calls that may clobber aliases:
  caller-saved registers live across call:
  preserved registers:
  memory aliases still valid:

Trust:
  attacker-controlled pointer:
  attacker-controlled pointed-to data:
  validated before dereference:
  validated before write:

Unresolved alias questions:
```

### Copy-operation worksheet

```text
Operation:
  [ ] memcpy-like
  [ ] memmove-like
  [ ] strcpy-like
  [ ] strncpy-like
  [ ] memset-like
  [ ] rep movs/stos
  [ ] sscanf/string parser

Destination:
  Address:
  Storage:
    [ ] stack
    [ ] heap
    [ ] global
    [ ] caller-provided
  Capacity:
  How capacity is known:

Source:
  Address:
  Origin:
  Attacker-controlled:

Count/termination:
  Count value:
  Count origin:
  Terminator written:
  Maximum proven:

Safety relationship:
  [ ] count <= destination capacity
  [ ] count < destination capacity because terminator follows
  [ ] only source length checked
  [ ] no destination check found
  [ ] unknown

Exploit notes:
```

### Structure recovery worksheet

```text
Base pointer:
How base pointer is obtained:

Observed fields:
  +0x00:
  +0x04:
  +0x08:
  +0x0C:
  +0x10:
  +0x14:
  +0x18:
  +0x1C:
  +0x20:

For each field:
  Read/write:
  Width:
  Signedness:
  Compared against:
  Passed to:
  Stored from:

Likely object role:
Invariants:
Trust boundary:
```

### Loop worksheet

```text
Loop header:
Loop body:
Exit block:

Induction variable:
Initial value:
Update:
Exit condition:

Memory access pattern:
Element size:
Base pointer:
Index or pointer bump:

Loop type:
  [ ] counted
  [ ] sentinel
  [ ] bounded sentinel
  [ ] traversal
  [ ] retry/error loop

Invariant before each iteration:
What is returned or written:
```

### Dispatch and switch worksheet

```text
Dispatch function address:
Dispatch key register/operand:
Key source (argument, field, computed):

Range check:
  Instruction:
  Valid range:
  Unsigned or signed:
  Default/out-of-range target:

Dispatch mechanism:
  [ ] compare chain
  [ ] jump table
  [ ] lookup table + indirect call
  [ ] tail call series
  [ ] other

Targets:
  case 0:
  case 1:
  case 2:
  case 3:
  default:

Which target receives attacker-controlled data:
Which target performs memory writes:
Are any targets tail calls (jmp, not call):
Is the dispatch key attacker-controlled:

Next analysis target:
```

### Exploit triage worksheet

```text
Suspicious operation:
Reachability:
Attacker-controlled input:
Validation gates:
Missing invariant:

Bug class candidate:
  [ ] stack overflow
  [ ] heap overflow
  [ ] integer overflow/truncation
  [ ] format string
  [ ] use-after-free
  [ ] double free
  [ ] off-by-one
  [ ] SEH overwrite
  [ ] function pointer/vtable corruption
  [ ] info leak

Overwrite/read target:
Offset calculation:
Bad characters or input constraints:
Mitigations:
  [ ] stack cookie
  [ ] DEP/NX
  [ ] ASLR
  [ ] SEHOP/SafeSEH
  [ ] heap hardening

What would prove exploitability:
What would disprove exploitability:
```

### WinDbg verification worksheet

```text
Breakpoint:
Input used:

Before call:
  esp:
  ebp:
  eax:
  ecx:
  edx:
  esi:
  edi:

Stack dump:

Memory dump of destination:

Memory dump of source:

After call:
  eax:
  changed memory:
  exception:

Static hypothesis confirmed?
  [ ] yes
  [ ] no
  [ ] partially

Correction to static model:
```

### Shellcode analysis worksheet

```text
Sample source:
Entry point:

EIP recovery method:
  [ ] call/pop
  [ ] jmp/call backward
  [ ] fstenv
  [ ] other
  Register holding recovered EIP:

Encoder/decoder:
  [ ] single-byte XOR
  [ ] additive
  [ ] multi-byte key
  [ ] sub-based
  [ ] none / cleartext
  Key value:
  Encoded region start:
  Encoded region length:
  Bad characters avoided:

PEB walk present:
  [ ] yes
  [ ] no
  Module list used:
    [ ] InLoadOrderModuleList (+0Ch)
    [ ] InMemoryOrderModuleList (+14h)
    [ ] InInitializationOrderModuleList (+1Ch)
  Target module (by position):
  DllBase offset:

API resolution:
  [ ] hash-based (ROR/ADD loop)
  [ ] string comparison
  [ ] GetProcAddress after resolution
  [ ] hardcoded addresses
  Hash algorithm:
  APIs resolved:

Payload action:
  [ ] reverse shell
  [ ] bind shell
  [ ] download-and-execute
  [ ] command execution
  [ ] other

Null-byte avoidance techniques observed:

WinDbg verification:
  Break at decoder end, dump decoded payload:
  Break at API call, verify arguments:
```

### ROP chain worksheet

```text
Overflow target:
  [ ] saved return address
  [ ] SEH handler
  [ ] function pointer
  [ ] vtable entry

Stack pivot (if needed):
  Pivot gadget address:
  Pivot instruction:
  Controlled register:
  New ESP value:

Chain trace:
  Slot  Address     Gadget/Value           Effect
  +00:
  +04:
  +08:
  +0C:
  +10:
  +14:
  +18:
  +1C:
  +20:
  +24:
  +28:
  +2C:
  +30:

Register state after chain:
  EAX:
  EBX:
  ECX:
  EDX:
  ESI:
  EDI:
  ESP:
  EBP:

API call being set up:
  Function:
  arg0 (return address after API):
  arg1:
  arg2:
  arg3:
  arg4:

DEP bypass method:
  [ ] VirtualProtect
  [ ] VirtualAlloc
  [ ] WriteProcessMemory
  [ ] SetProcessDEPPolicy
  [ ] NtSetInformationProcess
  [ ] other

Gadget quality notes:
  Non-ASLR module used:
  Clobbered registers:
  Conditional branches in gadgets:
  Bad characters in addresses:

What would break the chain:
```

### Daily practice drill

Use this for one unknown function per day.

```text
Function:
Timebox: 25 minutes

Minute 0-5:
  Boundary, arguments, return, obvious calls.

Minute 5-10:
  Branch questions and validated ranges.

Minute 10-15:
  Data origin/destination and memory writes.

Minute 15-20:
  Programmer assumptions and exploit relevance.

Minute 20-25:
  Pseudocode and verification plan.

Final sentence:
  This function exists to...
```

### Chapter review grid

```text
Chapter:

Three patterns I can recognize:
1.
2.
3.

One pattern I can derive but not yet recognize quickly:

One mistake I made:

One WinDbg command that would verify the main idea:

One exploit question raised by the chapter:
```

## Filled-in example: unknown function worksheet

This example shows a completed worksheet for a real analysis, demonstrating the
level of detail expected.

```text
Function address/name: sub_401900
Caller(s): sub_401000 (network handler), sub_401200 (command dispatcher)
Callee(s): _memcpy, send_status

Boundary:
  Prologue: push ebp / mov ebp, esp / sub esp, 200h
  Epilogue: mov esp, ebp / pop ebp / retn
  Tail calls: none
  Exception exits: none

Incoming values:
  [x] stack arguments: [ebp+8] = client object ptr, [ebp+0Ch] = data ptr,
      [ebp+10h] = data length
  [ ] register arguments
  [ ] globals
  [ ] object fields: [ebp+8]+0x20 = auth flag (byte)
  [ ] imported/runtime state

Outgoing values:
  [x] EAX return: 0 success, -1 failure
  [x] memory writes: memcpy into [ebp-200h] (512-byte local buffer)
  [ ] global writes
  [x] calls with modified arguments: send_status(client, message)
  [ ] indirect control flow

Compiler scaffolding:
  [ ] saved registers: ESI (used for client pointer)
  [x] frame allocation: sub esp, 200h
  [ ] stack cookie: NOT PRESENT
  [ ] stack probe: not needed (< 4096 bytes)
  [ ] SEH registration: none
  [ ] import thunk: _memcpy

One-sentence current hypothesis:
  Authenticated command handler that copies client data into a local buffer
  and sends a status response.

Evidence that supports it:
  - Auth check at [esi+20h] gates the copy path
  - memcpy destination is a 512-byte local buffer
  - send_status called with response messages on both paths

Evidence that contradicts or weakens it:
  - No bounds check on [ebp+10h] before memcpy -- data length is used directly
    as copy count
  - No /GS cookie despite 512-byte buffer (older compile? /GS disabled?)

Next verification step:
  Set breakpoint at memcpy call, send data > 512 bytes, verify overflow occurs.
  Check whether auth can be bypassed or is obtained via a prior legitimate
  request.
```

## Exploit development workflow worksheet

Use this worksheet to track progress through a complete exploit development
cycle. Each section corresponds to a phase of the OSED exam workflow.

```text
Target binary:
Target service/protocol:
Date started:
Time spent so far:

=== Phase 1: Reconnaissance ===
Binary type: [ ] EXE  [ ] DLL  [ ] Service
Architecture: [ ] x86  [ ] x64
Protections:
  ASLR:     [ ] Yes  [ ] No   [ ] Partial (which modules?)
  DEP/NX:   [ ] Yes  [ ] No
  SafeSEH:  [ ] Yes  [ ] No   (per module)
  /GS:      [ ] Yes  [ ] No   (per function)
  SEHOP:    [ ] Yes  [ ] No

Network protocol: [ ] TCP  [ ] UDP  [ ] Named pipe  [ ] Other
Port:
Authentication required: [ ] Yes  [ ] No  [ ] Optional
Input format:

Non-ASLR modules:
  Module name    Base address    SafeSEH
  __________     __________     ________

=== Phase 2: Vulnerability Discovery ===
recv/ReadFile locations:
Data flow from input to vulnerable function:
Vulnerable function:
Bug class:
Overflow offset (cyclic pattern):
Controlled registers at crash:
Bad characters:

=== Phase 3: Exploit Strategy ===
Exploit type: [ ] Direct RET overwrite  [ ] SEH overwrite  [ ] Other
DEP bypass:   [ ] Not needed  [ ] ROP chain  [ ] Other
Payload space available:
Egghunter needed: [ ] Yes  [ ] No

=== Phase 4: Exploit Construction ===
Return address / SEH handler:
    Source module:
    Address:
    Instruction:
ROP chain (if needed):
    VirtualProtect / VirtualAlloc address:
    Key gadgets:
Shellcode:
    Type: [ ] Reverse shell  [ ] Bind shell  [ ] Custom
    Size:
    Encoder:

=== Phase 5: Verification ===
Exploit works in debugger: [ ] Yes  [ ] No
Exploit works standalone:  [ ] Yes  [ ] No
Shell received:            [ ] Yes  [ ] No
Screenshot taken:          [ ] Yes  [ ] No
```

## Practice binary sources

For hands-on practice with these worksheets, use binaries from these sources
(available on the OSED lab environment or for download):

- **Vulnserver** (by Stephen Bradshaw): a deliberately vulnerable TCP server
  with multiple exploit paths (TRUN, GMON, KSTET, etc.). Ideal for practicing
  stack overflow, SEH, and egghunter techniques.
- **dostackbufferoverflowgood** (by Justin Steven): guided stack buffer
  overflow tutorial binary.
- **brainpan**: VulnHub/TryHackMe binary for practicing basic overflow and
  shellcode.
- **OSED lab binaries**: the course-provided binaries for each module.
  Apply these worksheets to every lab exercise.
- **Exploit-DB applications**: search for Windows x86 applications with known
  vulnerabilities in the stack overflow or SEH categories.

When using any practice binary, fill out the Unknown Function Worksheet for
at least three functions before writing exploit code. This builds the analysis
discipline that separates exam-ready students from those who trial-and-error
their way through.

## Key takeaways

- Worksheets are not busywork. They enforce the fact-ledger discipline that
  prevents the most common reversing failure: acting on unproven assumptions.

- Print the worksheets and fill them out by hand during practice. Handwriting
  forces slower, more deliberate analysis than typing.

- The exploit development workflow worksheet maps directly to the OSED exam
  structure. Practice filling it out under time pressure.

- Use the daily practice drill (25-minute timebox) to build speed. One
  function per day, every day, for the duration of your OSED preparation.

## See also

- Chapter 0 (Preface) -- study method and four-pass reading strategy
- Chapter 10 (Methodology) -- the 9-step analysis process these worksheets
  support
- Chapter 11 (Exploit-oriented reading) -- exploit triage checklist
- Chapter 12 (Case studies) -- worked examples using these worksheet patterns
- `DRILLS/` directory -- drill templates organized by skill area
- `Tools/` directory -- automation tools for bad characters, patterns, and
  exploit construction
