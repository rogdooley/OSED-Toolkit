# OSED Reverse Engineering Practice Lab

## Objective

Create three independent, realistic Windows x86 (32-bit) reverse-engineering challenges for a student preparing for Offensive Security’s EXP-301/OSED examination.

The objective is reverse engineering and vulnerability analysis, NOT developing working exploits.

The student must independently analyze the compiled binaries using IDA Free without a decompiler.

The exercises should develop proficiency in:

* Reconstructing unfamiliar application behavior from x86 assembly.
* Navigating imports, cross-references, functions, and call graphs.
* Reconstructing network protocols and file formats.
* Identifying attacker-controlled data and following its propagation.
* Understanding stack frames, calling conventions, and pointer arithmetic.
* Identifying memory-corruption vulnerabilities.
* Recognizing information disclosures and their implications for ASLR.
* Understanding how multiple vulnerabilities might form an exploitation chain.
* Reasoning about DEP, ASLR, and SEH/SafeSEH.

The student has substantial programming experience and understands basic exploitation. Do not create beginner exercises.

The student has approximately two weeks remaining before the examination and limited study time.

Prioritize educational value and efficient reverse-engineering practice.

---

## 1. Challenge Requirements

Create three independent applications.

### Target 1 — Network Protocol Analysis

A 32-bit Windows TCP server implementing a small custom binary protocol.

The student should need to:

1. Locate networking functionality through imports.
2. Follow cross-references into the connection-handling code.
3. Identify the receive loop.
4. Reconstruct message framing and command dispatch.
5. Identify attacker-controlled fields.
6. Follow those fields through multiple functions.
7. Discover a memory-corruption vulnerability.
8. Explain the resulting exploitation primitive and relevant mitigations.

Include at least one non-obvious complication involving validation, data transformation, or the relationship between multiple fields.

Do not simply implement an obvious unchecked `strcpy`.

### Target 2 — Information Disclosure and Memory Corruption

A second 32-bit Windows TCP service.

This target should require the student to recognize how separate application behaviors could contribute to an exploitation chain.

Include:

* An information-disclosure vulnerability.
* A separate memory-corruption vulnerability.
* At least one dependency between the two that becomes apparent through analysis.
* Relevant ASLR and DEP considerations.

The information disclosure should not be immediately obvious from the imports alone.

The student should need to investigate data flow and function behavior to understand its significance.

Do not disclose the vulnerability types through program names, strings, or command names.

### Target 3 — File Parser

A 32-bit Windows application processing a custom binary file format.

The student should need to:

1. Locate file-handling functionality.
2. Identify how the file is opened and read.
3. Reconstruct the file header.
4. Identify record structures and field sizes.
5. Trace lengths, offsets, allocations, and copy operations.
6. Discover a vulnerability involving incorrect validation or memory handling.
7. Explain its exploitation implications.

Include a non-obvious complication involving the interaction of multiple fields, integer arithmetic, or parser state.

The file format should be understandable through systematic reverse engineering without requiring knowledge of obscure compression algorithms or cryptography.

---

## 2. Difficulty and Hidden Twists

Difficulty should be intermediate to moderately challenging, comparable to meaningful EXP-301 reverse-engineering exercises.

Each target must contain one or two deliberately designed twists.

A twist should:

* Require careful assembly analysis.
* Be discoverable using normal IDA functionality.
* Reward following data flow across functions.
* Challenge an initially plausible assumption.
* Have a clear explanation once understood.

Possible categories include:

* Validation performed before a transformation.
* Different interpretations of the same length field.
* Signed versus unsigned comparisons.
* Integer truncation or extension.
* A length check that applies to the wrong destination.
* An information disclosure hidden inside otherwise legitimate output.
* Multiple commands sharing internal state.
* A wrapper function that obscures a dangerous operation.
* Incorrect assumptions about allocation sizes.

Select the actual twists independently.

Do not disclose which twists were selected.

Avoid:

* Excessive obfuscation.
* Anti-debugging.
* Packers.
* Self-modifying code.
* Deliberately malformed PE files.
* Extremely complicated protocols.
* Unnecessary cryptography.
* Unreasonably large applications.
* Vulnerabilities requiring obscure exploitation techniques.

The challenges should be difficult because of their logic, not because the binary is hostile to analysis.

---

## 3. Compilation Requirements

Use C for the applications.

Target Windows x86 (32-bit).

Prefer MinGW-w64 GCC with no third-party runtime dependencies beyond standard Windows libraries.

Provide:

* A root Makefile.
* A Windows `build.bat`.
* A Linux-compatible cross-compilation workflow.
* A clean build target.
* A validation target.

The preferred build command is:

```text
make
```

The build must produce:

```text
dist/
    target01.exe
    target02.exe
    target03.exe
```

If MinGW-w64 is unavailable, report the missing dependency clearly.

Do not silently substitute another architecture.

### Compiler configuration

Use settings that preserve realistic, understandable x86 assembly.

* Disable compiler optimizations initially (`-O0`).
* Preserve frame pointers.
* Avoid unnecessary compiler-generated complexity.
* Do not include debug symbols in distributed executables.
* Avoid function names that reveal vulnerabilities.
* Configure ASLR and DEP deliberately for each target.
* Do not introduce stack-cookie-based exercises.
* Use SEH/SafeSEH only where supported by the selected toolchain.

Document the actual mitigation configuration in instructor materials.

Do not assume SafeSEH is supported merely because a linker flag exists.

Verify PE characteristics after compilation.

---

## 4. Reverse-Engineering Realism

The binaries should resemble small, realistic applications rather than isolated vulnerability demonstrations.

Include:

* Application initialization.
* Normal input handling.
* Multiple internal functions.
* Some benign functionality.
* Error handling.
* Realistic data structures.
* Ordinary Windows API imports.
* Plausible control flow.

For network applications, use Winsock.

For the file parser, use ordinary Windows file APIs or standard C file I/O.

Imported functions should be recognizable in IDA when normally resolved through the PE import table.

Internal functions should not have descriptive symbols that reveal their purpose.

The student must be able to investigate the application through imports and cross-references.

Do not require IDA Pro, Hex-Rays, or commercial plugins.

---

## 5. Determinism and Correctness

The applications must have stable, reproducible behavior.

The implementation must not rely on undefined behavior in normal execution paths.

Where a vulnerability intentionally causes undefined behavior, document the expected behavior and its limitations in the instructor materials.

Every vulnerability must be reachable through a well-defined input path.

Do not assume that a source-level vulnerability necessarily produces the intended binary-level behavior.

Validate the compiled output.

The vulnerability must not disappear because of compiler transformations or unexpected runtime behavior.

The student should be able to reconstruct the relevant control flow from the actual executable.

---

## 6. Validation

Create automated validation scripts.

For each target, verify:

1. Successful compilation.
2. Correct PE32 architecture.
3. Expected imports.
4. Expected mitigation flags.
5. Normal application behavior.
6. Correct handling of valid inputs.
7. Reachability of the intended vulnerable code.
8. Reproducibility of the intended vulnerability trigger.

Use Python 3.12+ for test utilities.

Keep test dependencies minimal.

Where possible, include benign sample inputs demonstrating normal functionality.

Vulnerability-triggering inputs and their explanations must remain in the instructor materials.

If Windows execution is unavailable, distinguish between:

* Compilation verified.
* PE structure verified.
* Static vulnerability analysis completed.
* Runtime behavior verified.

Never report runtime validation as successful unless the executable was actually run.

Do not claim that a vulnerability is exploitable merely because the source contains an unsafe operation.

---

## 7. Project Structure

Use the following structure:

```text
osed-reversing-labs/
├── Makefile
├── build.bat
├── README.md
│
├── src/
│   ├── target01/
│   ├── target02/
│   └── target03/
│
├── dist/
│   ├── target01.exe
│   ├── target02.exe
│   └── target03.exe
│
├── student/
│   ├── target01/
│   ├── target02/
│   └── target03/
│
├── instructor/
│   ├── target01/
│   ├── target02/
│   └── target03/
│
├── tests/
│
└── progress/
    ├── investigation-log.md
    ├── mistakes.md
    └── techniques.md
```

The student directory must contain only the binaries, minimal execution instructions, and benign sample inputs.

The instructor directory must contain all solutions and implementation explanations.

The source code must remain outside the student directory.

Do not place spoiler information in the root README.

Ensure the instructor materials and vulnerability-triggering test cases are excluded from any student-only archive.

---

## 8. Instructor Documentation

For each target, create a complete instructor guide containing:

### Application architecture

* Application purpose.
* Relevant functions.
* Call graph.
* Important data structures.
* Protocol or file-format specification.

### Vulnerability analysis

* Exact vulnerable operation.
* Root cause.
* Attacker-controlled inputs.
* Relevant validation logic.
* Explanation of the hidden twists.
* Important assembly instructions.
* Relevant stack-frame or memory-layout details.

### Exploitation reasoning

* Available vulnerability primitives.
* Relevant mitigations.
* Whether information disclosure is necessary.
* Conceptual exploitation-chain requirements.
* Constraints that would complicate exploitation.

Do not implement shellcode or a working ROP exploit.

### Learning objectives

* What the student should discover.
* Common incorrect interpretations.
* Important clues.
* Efficient investigation path.
* Suggested hints in increasing order of specificity.

Include at least three progressively stronger hints per target.

The final hint may identify the relevant function, but earlier hints should preserve independent discovery.

---

## 9. Student Experience

The student will not read the source code or instructor documentation before attempting each exercise.

The student will primarily interact with IDA and an external AI instructor.

Therefore:

* Do not expose spoilers in terminal output.
* Do not include vulnerability descriptions in build summaries.
* Do not reveal intended twists in filenames.
* Do not print vulnerability-triggering inputs in the final response.

The binaries should contain sufficient information for independent analysis.

The AI instructor may request specific assembly excerpts from the student and help evaluate their reasoning.

The actual compiled binary is the authoritative source of truth.

---

## 10. Investigation Logs

Create three Markdown files under `progress/`.

### `investigation-log.md`

Track:

* Target identifier.
* Session date.
* Functions investigated.
* Evidence collected.
* Student hypotheses.
* Confirmed findings.
* Open questions.
* Next investigation step.

### `mistakes.md`

Track:

* Incorrect assumptions.
* Misinterpreted instructions.
* Missed validation conditions.
* Data-flow errors.
* Calling-convention mistakes.
* Inefficient investigation paths.
* Corrected understanding.

Distinguish genuine mistakes from reasonable hypotheses.

### `techniques.md`

Track reusable reverse-engineering techniques and lessons learned.

Initially, these files should contain only headings and templates.

Do not prepopulate them with solutions.

---

## 11. Quality Requirements

Before declaring the project complete:

* Compile all three targets.
* Verify their PE architecture.
* Inspect their imports.
* Verify mitigation configurations.
* Run all available tests.
* Confirm the student packages contain no spoilers.
* Confirm the instructor guides match the compiled implementations.
* Generate SHA-256 hashes for the final binaries.
* Record the compiler and linker versions.

If a target cannot be validated, clearly identify the limitation.

Do not fabricate test results.

---

## 12. Final Response Requirements

The final response must be brief.

Report only:

1. Whether all three targets were generated.
2. Whether compilation succeeded.
3. Whether validation succeeded.
4. Where the executables are located.
5. How to build the project.
6. How to launch each target.
7. Any unresolved build or validation issues.

Do not reveal vulnerabilities, hidden twists, protocol specifications, file-format structures, or intended exploitation strategies.

Do not summarize the instructor documentation.

The student should discover these details independently.

---

## 13. Implementation Instructions

Implement the project rather than merely proposing an architecture.

Make reasonable engineering decisions without repeatedly requesting clarification.

Prioritize correctness, reproducibility, and realistic reverse-engineering value.

Build and validate Target 1 first, then proceed to Targets 2 and 3.

If a toolchain limitation prevents a requirement from being met, document the limitation and use the simplest technically sound alternative.

The final result should be a practical, self-contained reverse-engineering laboratory suitable for repeated OSED preparation.
