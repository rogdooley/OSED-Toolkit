# M9 Inspect System

## Roadmap Position

Inspect remains a UI-facing subsystem whose design is constrained by the earlier semantic milestones.

Canonical milestone order lives in `Documentation/Roadmap/README.md`.

## Goal

Build the feature that turns raw machine state into memory intuition.

## Why It Matters

Stepping alone is not enough.

The inspect system is the bridge between assembly syntax and the mental model students need for exploit development.

## Inspect Targets

Users should be able to inspect:

- registers
- memory addresses
- stack entries

## Inspect Output

The inspect pane should display:

- raw value
- hex bytes
- ASCII view
- numeric interpretation
- pointer interpretation
- common meaning
- shellcode relevance

## Example

For `EAX = 0x2000`, the inspect view should be able to show:

- address `0x2000`
- memory bytes `63 61 6c 63`
- ASCII `"calc"`
- DWORD `0x636c6163`
- common meaning: pointer to an ASCII string

## Design Rules

- The inspect pane is persistent, not modal
- Interpretations must be explicit, not inferred by the user
- Show both raw bytes and meaningful renderings together
- Prefer stable sections over dynamic hidden controls

## Dependencies

The inspect system depends on:

- stable machine state models
- structured explanation objects
- deterministic interpretation helpers

## Exit Criteria

This milestone is complete when:

- selecting a value reliably opens a useful interpretation
- the inspect output is testable through view models
- stack strings and pointer dereferences are easy to understand at a glance
