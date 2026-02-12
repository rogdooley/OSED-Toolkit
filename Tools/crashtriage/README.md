# Crash Triage Parser

This module parses debugger crash text (WinDbg/x64dbg style) and recommends
`pattern_offset` commands for rapid overwrite triage.

## Usage

```bash
python -m Tools.crashtriage.cli.triage_crash -l 3000 --input crash.txt
python -m Tools.crashtriage.cli.triage_crash -l 3000 --json < crash.txt
```

## Output

- Detected architecture (`x86`/`x64`)
- Exception marker (`c0000005`/`access violation` when present)
- Ranked value candidates (register or exception-derived)
- Suggested normal + `--raw` `pattern_offset` commands
- Notes for ambiguity or width mismatches
