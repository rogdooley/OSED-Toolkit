# ASLR-04: Leak to Control Flow

## Objective

Combine the disclosure with the `OP_ROP` stack overwrite and redirect execution to the benign proof export under ASLR and DEP.

## Task

Find the saved-return-address offset independently with a cyclic pattern. Restart the service, request a fresh anchor leak, derive the proof VA, and replace the saved return address with that runtime value.

Before continuing from the overwritten return, verify:

```text
EIP candidate == derived proof VA
candidate belongs to osedhelper.dll
candidate memory is executable
disassembly matches helper_aslr_proof
```

## Expected Discoveries

- ASLR does not prevent reuse of a live disclosed module address.
- DEP does not block execution of existing executable image code.
- The leak and corruption primitive are separate stages of one exploit.
- The absolute target must be rebuilt after every process restart.

## Success Condition

Reach the `[success] ASLR-derived control flow` message using an address calculated from the current process leak.

## Common Failure Modes

- Using an offset from a different build configuration.
- Reusing yesterday's module base.
- Packing the address in the wrong byte order.
- Claiming DEP was bypassed with injected code; this exercise reuses existing code.

## Debrief

Explain the complete chain from packet field to leaked VA, recovered base, derived target, saved-return overwrite, and final EIP.
