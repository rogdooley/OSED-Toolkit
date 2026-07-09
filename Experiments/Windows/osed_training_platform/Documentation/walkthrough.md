# Walkthrough

This walkthrough is intentionally pre-exploit.

The goal is to teach the student how to explore the binary before the bug is
introduced.

## Phase 1: orient

1. Identify the service binary and its DLLs.
2. Confirm the process is x86 and Release-optimized.
3. Map the import table and note which DLLs are custom.

What this teaches:

- start with the module graph, not with guesses about the bug

## Phase 2: follow input

1. Break on `recv`.
2. Find the packet header in memory.
3. Trace the header into the protocol parser.
4. Find the opcode dispatcher.

What this teaches:

- identify the real path of attacker-controlled bytes

## Phase 3: separate noise from signal

1. Inspect the auth path.
2. Inspect the config and diagnostics handlers.
3. Confirm which copies are bounded and which are merely suspicious.

What this teaches:

- prove safety before calling a path vulnerable

## Phase 4: prepare for later exploit work

1. Build a note of module bases and mitigation state.
2. Identify the gadget source DLL.
3. Capture the wire format and record layout.

What this teaches:

- make the next phase deterministic before the bug exists

## What not to do yet

- Do not assume the final bug is in the first copy you see.
- Do not collapse the architecture into a single file.
- Do not introduce the overflow until the packet contract and debugging
  exercises are stable.
