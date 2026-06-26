# Profiles

This directory contains target profiles: structured records of
reverse-engineering observations and their runtime validation.

---

## Artifact Types

Four artifact types exist for each target. They represent distinct knowledge
states and are produced by different pipeline stages. No artifact is mutated
after creation. Later stages produce new artifacts; they do not modify earlier
ones.

### Candidate — `{target}.candidate.yaml`

**Knowledge state:** *Static analysis concluded.*

Produced by the IDA frontend. Contains observations about the target binary:
copy sites, transformation sites, candidate breakpoint expressions, protocol
geometry. Records what static analysis found, not what runtime has confirmed.
Incomplete by design — static analysis cannot enumerate all transformation
sites with certainty.

### Located — `{target}.located.yaml`

**Knowledge state:** *Runtime confirmed where controlled bytes are.*

Produced by the address validator. Records which (breakpoint, expression) pair
from the candidate profile was confirmed at runtime to point at controlled
bytes. Contains nothing about byte values or transformations. Answers exactly
one question: where are my controlled bytes?

### Verified — `{target}.verified.yaml`

**Knowledge state:** *Runtime confirmed how bytes behave.*

Produced by the transformation validator. Records which transformation sites
from the candidate profile were confirmed at runtime. Uses the same
scope/operation model as the candidate but adds confirmation status.
A verified profile may be `verified_partial` if some transformation sites
could not be confirmed.

### Report — `{target}.report.yaml`

**Knowledge state:** *Chronological evidence record.*

Append-only audit log of all validation runs. New stage entries are appended;
nothing is overwritten. Re-running a stage produces a new entry, not a
replacement. References all other artifacts by path and SHA-256. Profiles
never reference the report — the relationship is one-directional to avoid
cycles.

---

## Lifecycle

```
{target}.candidate.yaml
        │
        ▼
  Address Validation
        │
        ▼
{target}.located.yaml
        │
        ▼
  Transformation Validation
        │
        ▼
{target}.verified.yaml
        │
        ▼
  Consumer Queries
  (bad chars, shellcode alphabet, debugger setup, ...)
```

The report accumulates evidence from all stages in a single file.

---

## Schema Philosophy

### Facts and inferences

Within a candidate profile, `facts` are directly observable from static
analysis. `inferences` are conclusions the tooling draws from facts and carry
confidence scores and rationale.

### Scope and operation

Transformations are decomposed into orthogonal concepts:

```yaml
transformation:
  scope:
    type: byte       # or: range
    value: 0x3B      # for range: start, end

  operation:
    type: replace    # or: reject, offset
    value: 0x00      # for offset: delta (signed integer)
```

This allows the schema to grow only when new transformation semantics appear,
not when new targets appear.

### Derivable fields

No field is stored if it can be mechanically derived from another field.
Bad characters, encoder alphabets, and shellcode constraints are consumer
queries against the verified profile, not profile fields.

---

## Provenance

Every artifact records its lineage:

```yaml
produced_by:
  stage: address_validation

produced_from:
  - vulnapp2.candidate.yaml

provenance:
  candidate:
    path: vulnapp2.candidate.yaml
    sha256: ...    # populated at runtime
```

A consumer can reconstruct the full pipeline DAG from these fields without
relying on filenames.

---

## Stable Identifiers

Every significant object carries a stable namespaced ID:

```
{target}.{type}.{sequence}

vulnapp2.copy.001
vulnapp2.transform.001
vulnserver.trun.copy.001
vulnserver.lter.transform.001
```

Downstream artifacts reference objects by ID, never by list index or RVA.
IDs remain stable if list order changes or static analysis is re-run.

---

## Naming Convention

```
profiles/
    {target}.candidate.yaml    written once by static analysis
    {target}.located.yaml      written by address validator
    {target}.verified.yaml     written by transformation validator
    {target}.report.yaml       append-only audit log

    examples/
        {target}.candidate.yaml    hand-written canonical examples
        {target}.located.yaml      hand-written canonical examples
        {target}.verified.yaml     hand-written canonical examples
        {target}.report.yaml       hand-written canonical examples
```

Files in `examples/` are hand-written to verify schema expressiveness
before any automated pipeline exists. They serve as the specification
that `schema.py` encodes.
