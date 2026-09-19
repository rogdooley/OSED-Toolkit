# FMT-06: Arbitrary Read and ASLR Recovery

## Objective

Use the integrated format-string primitive to recover the executable base and read a protected record at a separately derived address.

## Task

Leak the contextual code pointer, identify its RVA in IDA, and calculate the current image base. Locate the protected record statically, derive its current VA, place that VA in a request argument, and consume it with `%s`.

## Expected Discoveries

- A leaked code VA and its known RVA recover the randomized image base.
- Request arguments can supply an arbitrary address to `%s`.
- The protected record's address must be rebuilt after every restart.

## Success Condition

Print the integrated secret after a fresh process restart using only values derived from that run's leak.

## Common Failure Modes

- Confusing an IDA VA with an RVA.
- Using the image's preferred base as the runtime base.
- Forgetting that `%s` follows a pointer and may cross unreadable memory.
- Reusing an address from a previous process.

## Debrief

Record the leak, anchor RVA, recovered base, record RVA, and final VA as a checked equation.
