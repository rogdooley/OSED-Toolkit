# Changelog

All notable changes to `osed_vuln_lab` are documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

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
