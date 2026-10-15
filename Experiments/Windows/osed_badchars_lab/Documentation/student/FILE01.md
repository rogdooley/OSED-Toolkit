# FILE-01 — file record to global input

Create a record with `generate_file.py`, then open it with `file01.exe` under
WinDbg. The utility writes the framing and declared length without changing the
candidate bytes.

1. Generate a known-good record: `python tools\\generate_file.py --challenge file01 --candidate-file candidate.bin --output probe.bcf`.
2. Run `file01.exe probe.bcf` under WinDbg and locate the global receive area.
3. Compare that intact input with the final copy destination.

Start with a short candidate. Then use a separate binary probe to determine
where an embedded byte changes the result. Keep record framing and the declared
length valid so a parser failure is not mistaken for a byte restriction.
