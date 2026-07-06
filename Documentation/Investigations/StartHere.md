# Binary

Name
SHA256 (if available)
Compiler (if known)
Architecture
Protections
Purpose

---

# Initial Questions

What am I trying to determine?

Examples:

- Where does attacker-controlled data enter?
- Where is the parser?
- Where are local buffers?
- How is the stack organized?
- Where is the vulnerability?
- How can the overwrite offset be derived statically?

---

# Investigation Log

Document the analysis chronologically.

Each observation should include:

Observation
Evidence
Reasoning
Confidence
Open Questions

Explicitly distinguish:

FACT

HYPOTHESIS

VERIFIED

UNKNOWN

Do not mix speculation with facts.

---

# Data Flow

Trace attacker-controlled data through the program.

Examples:

recv()

↓

heap allocation

↓

delimiter normalization

↓

custom strcpy implementation

↓

stack buffer

↓

saved return address

Document every transformation.

---

# Stack Analysis

Recover:

function arguments

local variables

saved registers

stack layout

buffer locations

saved return address

Explain how the layout was derived.

Include stack diagrams.

---

# Loop Analysis

For every important loop document:

Purpose

Loop variable

Termination condition

Memory reads

Memory writes

Equivalent C

Important observations

Do not identify loops by pattern recognition alone.

Always derive their behavior from execution.

---

# Function Analysis

For every significant function:

Arguments

Return value

Side effects

Memory ownership

Equivalent C

Library equivalent (if applicable)

Reasoning used to identify it

Confidence

---

# Compiler Idioms

Record recurring compiler behaviors observed during the investigation.

Examples:

push ebp
mov ebp, esp

strlen implementation

manual strcpy implementation

decision trees

loop structures

register allocation

stack frame construction

callee cleanup

etc.

Document why the compiler likely emitted the code.

---

# Vulnerability Analysis

Describe:

Trust boundary

Attacker-controlled inputs

Memory ownership

Missing validation

Missing bounds checks

Exploit primitive

Derived overwrite distance

Evidence supporting each conclusion

---

# Validation

Describe how static analysis was confirmed.

Examples:

WinDbg

Pattern offset

Memory inspection

Breakpoints

Register state

Stack inspection

---

# Lessons Learned

Record conceptual insights.

Examples:

"I initially assumed the stack buffer received network data directly."

"Following the data flow showed the receive buffer was heap allocated."

"The vulnerability existed in a custom strcpy implementation rather than a library call."

"Decision trees are a more useful mental model than attempting to reconstruct nested if statements."

Include mistakes made during the investigation and what corrected them.

---

# Future Questions

List topics that deserve additional study.

---

General writing guidelines

Treat this as a professional engineering notebook.

Do not rewrite history.

Record both successful reasoning and incorrect assumptions.

Preserve the chronology of discovery.

Always distinguish observations from conclusions.

Avoid hindsight bias.

The notebook should become a searchable knowledge base covering many binaries throughout the OSED journey.