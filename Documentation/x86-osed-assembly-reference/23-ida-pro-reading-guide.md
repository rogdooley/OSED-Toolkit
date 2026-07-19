# 23. IDA Pro Reading Guide

## Views

- **Disassembly (text):** linear listing of instructions with addresses,
  opcodes, and operands
- **Graph view:** control-flow graph with basic blocks as nodes and branches as
  edges; the primary view for understanding function logic
- **Pseudocode (F5):** decompiler output approximating C; useful as a
  hypothesis but can be wrong -- always verify against the actual assembly

## Stack Variables

IDA labels stack variables in the function frame. A variable shown as
`var_40` typically means `[EBP-0x40]` (or `[ESP+offset]` in FPO code). IDA's
variable naming is a convenience label, not ground truth -- verify the actual
offset by reading the instruction operand.

## Argument Labels

Function parameters are labeled `arg_0` ([EBP+0x08]), `arg_4` ([EBP+0x0C]),
etc. The offset names reflect the displacement from EBP, not the argument's
position in the prototype.

## Cross-References (Xrefs)

Press `X` on a function or variable to see all locations that reference it.
Xrefs reveal:

- Who calls this function
- Where a global variable is read or written
- What code references a string

Follow xrefs backward to trace data flow from a sink to a source.

## Imported Functions

The Imports window lists functions imported from other DLLs. IDA often wraps
them in thunk functions (a single `jmp [IAT_entry]`). Calls to the thunk are
calls to the imported function.

## Function Boundaries

IDA may fail to identify a function boundary correctly, especially in
obfuscated or hand-written code. Signs: code displayed in gray (not in a
function), unexpected `retn` instructions, or missing function prologue. Use
`P` to create a function at the current address.

## Switch Tables

IDA represents switch statements as a jump through a table:

```asm
jmp ds:off_401234[eax*4]   ; jump table indexed by EAX
```

IDA annotates the cases. If it does not detect the switch, the jump target
appears as an indirect jump with no context.

## Thunk Functions

A thunk is a minimal function that only jumps to another:

```asm
_VirtualProtect:
    jmp ds:[__imp__VirtualProtect@16]
```

Calls to thunks are effectively calls to the target. IDA usually resolves the
name.

## Type Propagation

IDA propagates types from known function signatures to their arguments. If IDA
knows `recv(SOCKET, char*, int, int)`, it labels the arguments at the call
site. This is helpful but can be wrong if the function prototype is misidentified.

## Debugger vs. Disassembler Disagreement

The disassembly shows the on-disk layout. The debugger shows runtime state.
Differences arise from:

- Self-modifying code
- Runtime unpacking
- Loader relocations
- Different module base (ASLR vs. IDA's assumed base)

Rebase the IDA database to match the runtime base:
Edit -> Segments -> Rebase program.
