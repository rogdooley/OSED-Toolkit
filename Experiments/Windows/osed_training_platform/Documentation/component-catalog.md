# Component Catalog

This page explains the planned directories in the new lab design.

## `service`

Primary reverse-engineering target.

Planned responsibilities:

- socket bootstrap and accept loop
- session management and auth
- packet parsing and dispatch
- logging and error reporting

Design rule:

- keep the interesting logic split across multiple translation units so the
  student has to trace real control flow.

## `protocol`

Wire contract and cursor discipline.

Planned responsibilities:

- frame validation
- record iteration
- safe copy helpers
- endianness helpers

Design rule:

- stay strict about bounds so the later bug is localized to one specific
  parser path.

## `gadgetlib`

Module for gadget analysis and mitigation work.

Planned responsibilities:

- small exported utility functions
- enough code density for useful instruction sequences
- a separate module base from the main service

Design rule:

- force the student to choose a gadget source based on mitigation state rather
  than hardcoding one address.

## `helper`

Support DLL that makes the service look like normal shipped software.

Planned responsibilities:

- token or checksum utilities
- name formatting helpers
- diagnostic probes for module tracing

Design rule:

- be mundane enough to ignore at first glance, but useful enough that the
  student has to account for it during RE.

## `client`

Reproducible request generator.

Planned responsibilities:

- build valid packets
- replay benign workflows
- later drive offset, bad-character, and mitigation exercises

Design rule:

- keep packet construction outside the service so the target remains the only
  thing under analysis.

## `tools`

Reusable training helpers.

Planned responsibilities:

- cyclic pattern generator
- bad-character enumerator
- module inventory helper
- WinDbg command notes

Design rule:

- every repeatable analysis step should be scriptable outside the target.
