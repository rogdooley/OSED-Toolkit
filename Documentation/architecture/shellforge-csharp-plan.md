# ShellForge C# Rewrite Plan (Deferred)

## Executive Decision
- Status: Deferred.
- Implementation: Do not start C# rewrite now.
- Rationale: ShellForge is still in product discovery; rewrite would create immediate dual-maintenance overhead with low current deployment justification.

## Scope and Intent
This document preserves the C# direction for future execution without starting implementation.

Use this plan only when measurable packaging and deployment pain persists.

## Rewrite Trigger Gates
A C# rewrite may start only if one or more of the following persist for 2 consecutive failed releases:

- Windows standalone build failure rate > 5%.
- AV false-positive rate causes repeated operator friction.
- Packaged binary startup or size becomes unacceptable.
- 32-bit Windows packaging blocks real usage.
- Dependency bundling is a recurring maintenance burden.
- Support/debug time exceeds feature-development time.

## Quantitative Thresholds
### Startup (cold start)
- `x86`: target < 300 ms.
- `x64`: target < 250 ms.

### Binary size
- `x86`: acceptable < 40 MB.
- `x64`: acceptable < 50 MB.
- Hard ceiling: 100 MB (unacceptable).

## Current Strategy (Python First)
1. Continue ShellForge feature development in Python.
2. Package Windows artifacts first:
- `x86`
- `x64`
3. Build with:
- PyInstaller (required)
- Nuitka (optional comparison lane)
4. Run artifact smoke tests and contract snapshot parity tests on packaged `.exe` outputs.

## Release Validation Blueprint (Lightweight)
For each release, for each artifact (`packager` x `arch`):

- Build success/failure.
- Smoke test pass/fail.
- Contract snapshot parity pass/fail.
- Cold-start timing (ms).
- Artifact size (MB).
- AV detections or quarantine events.
- Operator-reported install/launch issues.

## Metrics Template
| release | packager | arch | build_pass | smoke_pass | contract_pass | startup_ms | size_mb | av_events | support_hours | feature_hours | gate_failed |
|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| vX.Y.Z | pyinstaller | x86 | true | true | true | 0 | 0 | 0 | 0 | 0 | false |
| vX.Y.Z | pyinstaller | x64 | true | true | true | 0 | 0 | 0 | 0 | 0 | false |
| vX.Y.Z | nuitka | x86 | true | true | true | 0 | 0 | 0 | 0 | 0 | false |
| vX.Y.Z | nuitka | x64 | true | true | true | 0 | 0 | 0 | 0 | 0 | false |

### Gate evaluation logic
Set `gate_failed=true` for an artifact when any condition is true:
- Build failure rate contribution exceeds threshold across release window.
- Startup exceeds target (`x86 >= 300`, `x64 >= 250`).
- Size exceeds acceptable target (`x86 >= 40`, `x64 >= 50`) or reaches hard ceiling (`>= 100`).
- Repeated AV friction is observed.
- Packaging on required architecture is blocked.
- `support_hours > feature_hours`.

Trigger rewrite review when any gate remains failed for 2 consecutive releases.

## Future C# Design Baseline (When Triggered)
When rewrite starts, lock this sequence before coding:

1. Freeze CLI and JSON contract surface.
2. Port contract tests first.
3. Define namespaces and package layout.
4. Select PE/disassembly/library stack.
5. Implement command parity module-by-module.
6. Ship side-by-side validation until parity is proven.

## Deferred C# Architecture Outline
- `ShellForge.Core`: models, contracts, errors.
- `ShellForge.Analysis`: PE/export/import/disassembly/analyze logic.
- `ShellForge.Transform`: hashes, encoders, output formatting.
- `ShellForge.Cli`: command handling and response envelopes.
- `ShellForge.Tests`: unit + contract snapshots.

## Priority Work While Deferred
1. Finish `analyze` capabilities.
2. Add hash cross-reference workflow (`--hash-db`).
3. Add Markdown report output.
4. Add `osed.js` export walking helpers.
