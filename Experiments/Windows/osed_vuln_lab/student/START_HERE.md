# Binary Protocol Reversing Lab

This directory is the complete student handout. Treat the service as a
black-box target: do not use its source tree, build artifacts, symbols, or the
instructor validation clients while solving the lab.

The binary is deliberately beginner-readable. It is not packed or obfuscated,
and compiler optimization and function inlining are disabled. Protocol
constants, imported APIs, receive calls, validation branches, dispatcher logic,
and vulnerable copies are all present directly in IDA's disassembly.

This exercise assumes IDA Free 7.7 with no decompiler and no Internet access.
You do not need pseudocode, online symbol services, plugins, or external protocol
documentation. Use disassembly, graph/text view, imports, strings, xrefs, and
the debugger.

Use only:

- `osed_vulnsvc.exe`
- `osedhelper.dll`
- this brief
- `protocol_notes.md`

Run the service in an isolated Windows x86 training VM:

```bat
osed_vulnsvc.exe 9999
```

## Objective

Reverse the TCP application protocol in IDA Pro, write your own minimal client,
identify the simplest memory-corruption command, and demonstrate controlled
instruction-pointer overwrite under WinDbg.

Do not begin by sending an arbitrary long byte string. The service validates a
message envelope before any command handler receives its data. A timeout or a
clean disconnect is protocol evidence, not proof that the overflow is absent.

## IDA Starting Point

1. Load `osed_vulnsvc.exe` without external PDB files.
2. Open **Imports**, locate the socket receive API, and follow its code xrefs.
3. Identify any local wrapper around that API, then inspect the wrapper's
   callers.
4. At each call, work backward through the preceding x86 instructions. For a
   normal 32-bit call, arguments are placed on the stack in reverse order. Use
   the imported API signature to label the socket, buffer, requested length,
   and flags arguments.
5. At the connection-handling caller, record the destination buffer and the
   requested byte count for the first receive operation.
6. Follow the checks performed on those bytes: comparisons, bounds checks, and
   branches to rejection paths. Record byte-order conversions only if you
   actually observe one.
7. Find the subsequent receive operation and determine how its requested size
   is derived.
8. Trace the dispatch logic that selects a handler from message-controlled
   data.
9. Implement only what you have demonstrated from disassembly or runtime
   observation.

IDA graph mode works only when the cursor is inside a recognized function. If
an import entry reports that graph mode is unavailable, press `X` for its
cross-references, follow a code reference into `.text`, and graph that function.

Useful offline keys in IDA 7.7:

- `X`: cross-references to the selected import, function, or address.
- `Space`: switch between text and graph view while inside a function.
- `Enter`: follow the selected call or address.
- `Esc`: return to the previous location.
- `N`: rename a function, local variable, or address as your understanding
  improves.
- `;`: add a repeatable comment containing the evidence for your conclusion.

## Dynamic Confirmation

Use breakpoints on the receive API and its callers to confirm each static
finding. For every receive operation, capture:

- socket argument
- destination address
- requested byte count
- return value
- bytes written to the destination

Send one field change at a time. Keep a fact separate from a hypothesis until
the corresponding branch or debugger observation confirms it.

## Common Completion Criteria

- A documented message format with field offsets, widths, byte order, and
  validation evidence.
- A dispatcher map based on observed comparisons and destinations.
- A client you wrote from those findings, capable of reaching at least one
  non-crashing command and the vulnerable handler.
- Notes explaining why a raw long string does not reach the vulnerable copy.

## Profile Goal

Complete only the section matching the supplied build. Do not assume a
primitive from one profile exists in another.
Likewise, do not assume that a command in a later profile accepts the same body
layout as an earlier one. Re-enter the dispatcher and follow every validation
branch to the bytes ultimately passed to the vulnerable copy.

### easy

- Produce a reproducible cyclic-pattern crash and verify the saved-return offset.
- Find a direct stack-transfer instruction in the supplied module set.
- Verify the supplying module has ASLR and DEP disabled.
- Redirect execution to benign controlled bytes immediately after saved EIP.

### seh

- Determine the nSEH and SEH offsets from debugger evidence.
- Find a pop-pop-ret sequence in a supplied module and verify SafeSEH is off.
- Demonstrate control returning through nSEH to benign controlled bytes.

### dep

- Prove DEP prevents the easy profile's direct stack-execution path.
- Inventory and verify the register, arithmetic, dispatch, and writable-memory
  primitives needed for a VirtualProtect call frame.
- Break on `kernel32!VirtualProtect`, validate all four arguments, and continue
  to benign proof bytes.

### aslr_dep

- Prove relevant module bases change between process launches.
- Recover a live module pointer through the protocol and establish its module
  provenance in WinDbg.
- Convert verified gadget addresses to RVAs, derive each live address from the
  recovered base, and complete the DEP exercise without fixed application
  addresses.

Keep all proof behavior benign and confined to the lab VM.
