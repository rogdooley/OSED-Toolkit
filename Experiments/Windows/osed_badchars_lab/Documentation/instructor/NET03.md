# NET-03 instructor verification

Use the unmodified student executable as the authority for all debugger work.
Set breakpoints around the receive completion and `net03_decode_and_stage`.
Confirm that the heap candidate is intact after the exact receive, the same
allocation is transformed in place, and the decoded prefix appears in the local
stack stage. Do not derive an offset from any instrumented build.

Run both harness modes with an equivalent candidate sequence. Account for the
overflow-context prefix when selecting the comparison range; the candidate must
show the same transformation at the same logical stage.
