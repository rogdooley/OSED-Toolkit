# Binary Protocol Reversing Lab

This directory is the complete student handout. Treat the service as a
black-box target: do not use its source tree, build artifacts, symbols, or the
instructor validation clients while solving the lab.

The binary is deliberately beginner-readable. It is not packed or obfuscated,
and compiler optimization and function inlining are disabled. Protocol
constants, imported APIs, receive calls, validation branches, dispatcher logic,
and vulnerable copies are all present directly in IDA's disassembly.

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
4. At the connection-handling caller, record the destination buffer and the
   requested byte count for the first receive operation.
5. Follow the checks performed on those bytes: comparisons, bounds checks, and
   branches to rejection paths. Record byte-order conversions only if you
   actually observe one.
6. Find the subsequent receive operation and determine how its requested size
   is derived.
7. Trace the dispatch logic that selects a handler from message-controlled
   data.
8. Implement only what you have demonstrated from disassembly or runtime
   observation.

IDA graph mode works only when the cursor is inside a recognized function. If
an import entry reports that graph mode is unavailable, press `X` for its
cross-references, follow a code reference into `.text`, and graph that function.

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

## Completion Criteria

- A documented message format with field offsets, widths, byte order, and
  validation evidence.
- A dispatcher map based on observed comparisons and destinations.
- A client you wrote from those findings, capable of reaching at least one
  non-crashing command and the vulnerable handler.
- A reproducible cyclic-pattern crash with the instruction-pointer offset
  calculated and verified.
- Notes explaining why a raw long string does not reach the vulnerable copy.

Keep all proof behavior benign and confined to the lab VM.
