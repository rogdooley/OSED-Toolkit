# FMT-08: Leak, Write, Redirect

## Objective

Combine the read and write primitives to redirect a persistent function pointer under ASLR and DEP.

## Task

Recover the current image base, identify the storage address of the persistent action pointer, and derive the benign proof function's runtime address. Write that address byte by byte, validate the completed pointer, then use the execute opcode.

Before execution, prove:

```text
stored pointer == derived proof VA
derived proof VA belongs to fmt05_service
target memory is executable
disassembly matches the intended proof function
```

## Expected Discoveries

- The leak and write primitives can be composed across requests while the process remains alive.
- ASLR changes absolute values but not module-relative relationships.
- DEP permits control transfer to existing executable image code.
- Partial pointer states are dangerous and should never be invoked.

## Success Condition

Reach `[success] Format-string write redirected` after restarting the service and recalculating every address.

## Common Failure Modes

- Executing the pointer before all four bytes are correct.
- Reusing the previous process base.
- Writing to the function body instead of pointer storage.
- Claiming injected-code execution; this lab uses existing code.

## Debrief

Explain the full exploit state machine: leak, base recovery, target derivation, four writes, validation, and indirect call.
