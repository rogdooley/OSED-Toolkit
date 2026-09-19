# ASLR-01: Observe Randomization

## Objective

Prove that absolute addresses from `osedhelper.dll` are unstable while RVAs remain stable.

## Environment

- Windows x86 VM
- `aslr_dep` build with `HELPER_ASLR=ON`
- WinDbg attached at process start

## Task

Record the service and helper module ranges with `lm`. Restart the process at least three times and record the helper base and one exported function address each time. In IDA, record the same function's RVA.

## Expected Discoveries

- The helper's virtual addresses change between launches.
- `function VA - module base` remains constant for an unchanged binary.
- A hardcoded virtual address from a previous launch is stale.

## Success Condition

Provide a three-run table and demonstrate the same RVA in every run.

## Common Failure Modes

- Detaching and reattaching without restarting the process.
- Comparing addresses from different binary builds.
- Treating preferred image base as the current loaded base.

## Debrief

State precisely which term ASLR changes in `VA = base + RVA`.
