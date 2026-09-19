# ASLR-03: Recover the Module Base

## Objective

Convert the leaked function VA into the current `osedhelper.dll` base, then derive a second exported function's VA.

## Task

In IDA, determine the RVAs of the leaked anchor and `helper_aslr_proof`. Calculate:

```text
module_base = leaked_anchor_va - anchor_rva
proof_va    = module_base + proof_rva
```

Validate both results in WinDbg. Repeat after restarting the service.

## Expected Discoveries

- IDA offsets are useful across launches only when tied to the same binary.
- Subtraction recovers the page-aligned module base.
- Every useful address in that module can then be rebuilt from an RVA.

## Success Condition

After a fresh restart, predict `helper_aslr_proof` before resolving its symbol in WinDbg, then confirm an exact match.

## Common Failure Modes

- Subtracting the preferred base twice.
- Confusing file offset, RVA, and VA.
- Mixing decimal and hexadecimal values.
- Reusing a leak from the previous process.

## Debrief

Record the complete equation with values and explain why the result should be page aligned.
