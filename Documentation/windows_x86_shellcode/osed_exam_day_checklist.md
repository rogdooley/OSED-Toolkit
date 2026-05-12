# OSED Exam-Day Checklist

Use this as a practical pre-flight list before starting your exam session.

## 1. Environment Readiness

- Verify your VPN and exam connectivity tools are installed and working.
- Confirm your VM snapshots are clean and restorable.
- Confirm debugger, disassembler, and scripting environment launch correctly.
- Confirm your repository is locally accessible without network dependency.

## 2. Toolkit Sanity Checks

- Run `make win32-test-smoke`.
- Run `make win32-list-snippets`.
- Run `make win32-show-asm-bind PORT=4444`.
- Run `make win32-show-asm-rev LHOST=192.168.45.174 LPORT=443`.
- Confirm expected output appears with no import/runtime errors.

## 3. Operational Discipline

- Start a timestamped notes file for each target.
- Record every command, offset, and badchar finding as you go.
- Save intermediate exploit versions incrementally.
- Keep one known-good baseline script per target before major edits.

## 4. Validation Workflow

- Validate crash reproducibility before attempting control-flow redirection.
- Re-check offsets and registers after each material change.
- Re-validate badchars after any transport/protocol adjustment.
- Validate each stage independently before chaining payload logic.

## 5. Time Management

- Timebox dead-end investigations and switch paths decisively.
- Prioritize reliable exploitation over elegant refactors.
- Reserve final time for clean reproduction and report-quality notes.

## 6. Evidence and Reporting Readiness

- Keep concise proof artifacts for each solved objective.
- Ensure writeups are reproducible from clean start conditions.
- Maintain clear separation of assumptions, findings, and final steps.
