# target_profile Architecture

## Mission

A reproducible pipeline for converting reverse-engineering observations into
validated execution profiles.

---

## Why This Project Exists

Static analysis can identify likely locations where attacker-controlled data
flows through a program, but it cannot determine which runtime values
correspond to those locations without execution. Runtime validation bridges
that gap by confirming candidate expressions against live execution.

Reverse engineering a target produces observations: call sites, copy routines,
transformation loops, stack buffers. Those observations need to be captured in
a form that is reproducible, versioned, and consumable by downstream tooling —
not buried in IDA databases, debugger logs, or analyst memory.

This project formalizes that workflow. The analyst performs static analysis
once per target. The results are encoded in a profile. Everything downstream —
validation, debugger command generation, bad character discovery — consumes
that profile.

---

## Pipeline Stages

```
Binary
  │
  ▼
Frontend (static analysis)
  │
  ▼
Candidate Profile
  │
  ▼
Validator
  │
  ▼
Verified Profile + Report
  │
  ▼
Backend (debugger command generation)
  │
  ▼
Consumer (analysis engine)
```

Each stage has exactly one responsibility.

| Stage     | Responsibility                                              |
|-----------|-------------------------------------------------------------|
| Frontend  | Observe the binary. Emit a candidate profile.               |
| Validator | Confirm candidates against live execution. Emit verified profile and report. |
| Backend   | Render the verified profile into debugger commands.         |
| Consumer  | Execute an analysis (bad chars, offsets, patterns) using the verified profile. |

No stage performs the work of another. The frontend does not execute code.
The validator does not render debugger commands. The backend does not analyze
bytes.

---

## The Durable Artifact

The profile is the durable artifact. Not debugger scripts. Not IDA databases.
Not logs.

A profile can be:

- read by a human without running any code
- validated against a target independently of how it was produced
- versioned and diffed like source code
- consumed by any backend or analysis engine that understands the schema

**Static analysis proposes. Runtime validates.**

That boundary is intentional. The pipeline exists because there is an
epistemological gap between "static analysis concludes this is the right
breakpoint" and "live execution confirmed controlled bytes at this expression."
The validator exists to cross that gap cleanly, with evidence.

Everything else in the project is in service of producing, validating, and
consuming profiles.
