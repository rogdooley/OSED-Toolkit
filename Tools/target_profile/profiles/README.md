# Profiles

This directory contains target profiles: structured records of
reverse-engineering observations and their runtime validation.

---

## Document Types

Three document types exist for each target. They answer different questions
and are produced by different pipeline stages. None overwrites another.

### Candidate profile — `{target}.candidate.yaml`

Produced by static analysis. Contains observations about the target binary:
copy sites, transformation loops, candidate breakpoint expressions. Represents
what analysis concluded, not what has been confirmed at runtime.

**Never mutated after creation.**

### Verified profile — `{target}.verified.yaml`

Produced by the validator. A patch over the candidate profile: given candidate
profile X, these expressions were confirmed at runtime. References the
candidate profile by path and SHA-256. Contains no duplicated facts — only
the selections that validation promoted.

### Report — `{target}.report.yaml`

Produced alongside the verified profile. Machine-readable evidence: which
expressions were tried, which passed, which failed, and why. Answers the
question "why did the validator reach that conclusion?"

---

## Schema Philosophy

The profile distinguishes between **facts** and **inferences**.

**Facts** come directly from analysis and do not change when the inference
engine improves:

```yaml
facts:
  rva: 0x1000
  source_argument:
    stack_offset: 8
```

**Inferences** are conclusions the tooling draws from facts. They carry
confidence scores and rationale so they can be re-evaluated:

```yaml
inferences:
  candidate_dump_exprs:
    - expr: poi(@esp+8)
      confidence: 0.95
      rationale:
        - source argument to copy routine
        - stack-pointer-relative addressing confirmed
```

If the inference engine improves, inferences change. Facts do not.

---

## Provenance

Every verified profile records where it came from:

```yaml
provenance:
  candidate:
    path: vulnapp2.candidate.yaml
    sha256: ...
    schema_version: 1
  validator:
    version: 1.0
    timestamp: 2026-06-25T23:14:00Z
```

Pipeline artifacts accumulate; they do not replace each other.

---

## Naming Convention

```
profiles/
    {target}.candidate.yaml      written once by static analysis
    {target}.verified.yaml       written by validator
    {target}.report.yaml         written alongside verified profile

    examples/
        {target}.candidate.yaml  canonical hand-written schema examples
```

Files in `examples/` are hand-written to verify schema expressiveness during
development. They serve as the ground truth for the schema before any
automated frontend exists.

---

## Stable Identifiers

Every significant object carries a stable `id` field:

```yaml
copy_sites:
  - id: copy_site_1
    ...
```

Downstream stages reference objects by `id`, not by list index. If static
analysis finds additional candidates and list order changes, references remain
valid.
