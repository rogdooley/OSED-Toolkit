# Changelog

All notable changes to `osed_vuln_lab` are documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

### Changed
- Split student and instructor material so protocol recovery is required before
  exploit construction.
- Added a `student_bundle` build target containing only the service, helper DLL,
  spoiler-free brief, and reversing worksheet.
- Made `student_bundle` part of the default build so every compiled profile
  produces its student handout without a separate target invocation.
- Disabled MSVC optimization, inlining, and frame-pointer omission to preserve
  beginner-readable function boundaries and control flow in IDA Pro.
- Made the student workflow explicitly compatible with offline IDA Free 7.7
  using disassembly, imports, strings, xrefs, and graph/text views only.
- Added a deterministic x86 gadget bank, writable slot, and VirtualProtect
  wrapper to `osedhelper.dll` for easy, SEH, DEP/ROP, pivot, and ASLR exercises.
- Aligned the lab gadget template with `Tools.rop`, taught `GadgetDB` to accept
  the lab metadata envelope, and corrected the PUSHAD chain so proof bytes
  follow the serialized chain directly.
- Removed startup pointer disclosure and handler/opcode debug logging from the
  service binary.
- Added neutral `OP_PING`/`PONG` connectivity handling so the smoke test no longer exercises the ASLR disclosure primitive.
- Replaced the hardcoded exploit demo with a validated CLI for cyclic patterns, offset lookup, bad-character buffers, raw payloads, and student-supplied layouts.
- Removed the stale `vulnserver_trigger.py`, which targeted an unrelated protocol and port.

## [0.1.0] - 2026-05-17

### Added
- Profile-specific WinDbg training notes:
  - `windbg_easy.txt`
  - `windbg_dep.txt`
  - `windbg_aslr_dep.txt`
  - `windbg_seh.txt`
- `gadget_json_schema.md` to define user-maintained gadget/module JSON structure.
- `training_path.md` with staged lesson progression and expected outcomes.
- `python/protocol_smoketest.py` safe connectivity/parser test for `OP_LEAK`.
- `CHANGELOG.md` for local lab change tracking.

### Changed
- `README.md` reorganized to reference profile-specific debugging docs, training path, and schema guidance.

### Removed
- `python/rop_chain.py` (per user direction).
- `windbg_training_commands.txt` replaced with profile-specific files.
