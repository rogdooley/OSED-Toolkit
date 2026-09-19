# ASLR-02: Find the Disclosure Path

## Objective

Discover and validate the network-reachable information disclosure without reading source.

## Starting Files

- `osed_vulnsvc.exe`
- `osedhelper.dll`
- Packet framing documented in the main lab README

Do not inspect `osed_protocol.h` or `aslr_scaffold.py` until you have identified the disclosure opcode.

## Task

Use IDA to locate packet dispatch, identify the opcode that produces a pointer-bearing response, and trace the value backward to its source. Confirm the path dynamically at the send call.

## Expected Discoveries

- A distinct opcode reaches a disclosure handler.
- The response contains a live code pointer into `osedhelper.dll`.
- The leak is useful because its relationship to the module is stable.

## Success Condition

Request the leak, map it to its owning module, and identify the exact exported function it references.

## Common Failure Modes

- Searching for gadgets before proving the leak's provenance.
- Assuming every pointer-looking value belongs to the helper.
- Recording the pointer but not the binary version that produced it.

## Debrief

Document the input-to-dispatch-to-send dataflow and label static facts separately from runtime facts.
