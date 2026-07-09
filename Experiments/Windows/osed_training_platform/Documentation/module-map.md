# Module Map

The module split is part of the lesson.

## `service`

This is the main analysis target.

Responsibilities:

- process startup
- socket binding and accept loop
- per-session auth
- packet dispatch
- logging and error handling

Educational value:

- teach students to locate the hot path in a normal-looking service
- force tracing across multiple source files and function boundaries

## `protocol`

The wire parser should be isolated here.

Responsibilities:

- validate the frame header
- walk nested records
- maintain cursor state
- reject malformed or truncated data

Educational value:

- teach disciplined parser analysis
- show how safe validation can exist alongside later unsafe handling

## `helper`

A benign DLL that looks like shipping support code.

Responsibilities:

- name normalization
- checksum or token utilities
- simple formatting helpers
- one or two exported probe functions for module analysis

Educational value:

- teach export inspection and cross-module tracing
- provide a realistic DLL for module inventory work

## `gadgetlib`

A separate DLL used for mitigation-phase analysis.

Responsibilities:

- small exported functions
- nontrivial import table
- enough code density to produce useful gadgets

Educational value:

- teach selecting a gadget source based on mitigation state
- make the student inspect module bases instead of relying on one fixed image

## `client`

Benign request generator and replay harness.

Responsibilities:

- build valid packets
- send known-good requests
- later, stage safe offset and bad-character experiments

Educational value:

- teach payload construction without coupling the logic into the service

## `tools`

Reusable lab helpers.

Responsibilities:

- cyclic patterns
- bad-character enumeration
- module/mitigation inventory
- debugger command snippets

Educational value:

- keep the repeatable analysis workflow outside the target binary
