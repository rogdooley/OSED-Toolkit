# M9 Textual UI

## Roadmap Position

This document describes the UI phase after predict-then-reveal and state history support.

Canonical milestone order lives in `Documentation/Roadmap/README.md`.

## Goal

Provide a stable educational interface that makes state transitions legible without turning ASM-Lab into a debugger clone.

## Layout

The first UI should present:

- Register panel
- Memory panel
- Stack panel
- Instruction panel
- Explanation panel
- Persistent Inspect panel

Recommended layout:

- top: registers, memory, stack
- middle: current instruction
- lower left: lesson context
- lower center: explanation
- lower right: persistent inspect pane

## Design Rules

- The inspect pane must always be visible
- Do not use modal dialogs for inspection
- Avoid debugger-style clutter
- Keep high-density hex data aligned and stable
- Pair color highlights with text labels and before/after values

## Primary Interactions

- step to next lesson instruction
- restart lesson
- select register
- select memory address
- select stack entry

## UI Boundaries

- No execution logic in widgets
- No explanation generation in rendering code
- Widgets consume view models only

## Milestone-1 Priority

The main screen must optimize for:

- reading state changes quickly
- understanding pointer dereferences
- inspecting stack strings and frame layout

## Exit Criteria

This milestone is complete when:

- the layout renders all milestone-1 panels
- changed values are obvious
- inspect state stays visible without disrupting the lesson flow
