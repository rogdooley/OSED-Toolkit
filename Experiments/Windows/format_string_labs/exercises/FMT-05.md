# FMT-05: Binary-Driven Vulnerability Discovery

## Objective

Find and characterize a remotely reachable format-string vulnerability in an unfamiliar x86 binary.

## Environment

- `fmt05_service.exe` running under WinDbg
- IDA database created from the executable
- Packet scaffold in `tools/fmt05_client.py`

Do not inspect the target source or instructor notes.

## Task

Trace packet parsing from `recv` to dispatch. Identify which request field becomes a formatting function's first argument and determine the explicit argument layout using marker values and `%x`.

## Expected Discoveries

- One opcode reaches a bounded formatting function.
- The format string is attacker controlled.
- Eight variadic slots come from the request, followed by process-context pointers.
- Output truncation constrains the number of characters available to a single request.

## Success Condition

Produce an argument map for slots 1 through 11 and identify which slots contain a module pointer, a stack pointer, and a string pointer.

## Common Failure Modes

- Treating the output-size bound as elimination of the vulnerability.
- Dereferencing candidates before validating their memory ranges.
- Counting literal separators as arguments.

## Debrief

Document the input-to-sink dataflow and classify the available read and write primitives.
