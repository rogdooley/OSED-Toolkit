# 04 - IDA Free Core Workflow (x86)

Goal: quickly answer "what is the bug" without getting lost in the UI.

Use this on `vuln_strcpy_x86.exe` first, then repeat for any course lab binaries.

## Load

1. Open the x86 EXE in IDA Free.
2. Let auto-analysis finish.

## Find the Entry

- Jump to `main` (or a function that looks like it parses argv).
- Follow the call into the helper where the copy happens.

## Confirm the Vulnerability

In the vulnerable function:

1. Identify the local buffer:
   - in assembly, look for `sub esp, <size>` (stack space allocation)
   - then locate the buffer reference at `[ebp-XX]`
2. Identify the copy:
   - `strcpy`, `strncpy`, `sprintf`, `strcat`, etc.
3. Identify the source:
   - `argv[1]`, `gets`, file read, socket recv, etc.

## Stack Frame Sizing Exercise

For the lesson 01 binary (`buf[128]`), you should see:

- stack allocation >= 128 (often more due to alignment, saved regs, etc.)
- a pointer to the user input being passed to the copy

Write down:

- buffer size (your best estimate from code)
- exact unsafe API used
- where the input comes from

## Practical Output

Your output from IDA for every target should be a 5-line note:

1. Bug class: stack buffer overflow via unsafe copy
2. Input source: argv[1]
3. Destination: local stack buffer (approx size)
4. Copy primitive: strcpy(...)
5. Crash likely: overwrite return address / saved EBP (x86)

