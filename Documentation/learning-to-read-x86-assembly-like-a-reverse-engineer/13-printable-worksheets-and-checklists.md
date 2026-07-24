# Printable Worksheets and Checklists

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
