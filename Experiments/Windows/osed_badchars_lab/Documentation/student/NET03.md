# NET-03 — heap decode to stack staging

`net03.exe` listens on `127.0.0.1:32103`. It accepts the same length-framed
candidate format used by the TCP harness, but it uses its own receive and
processing path.

1. Start the target under WinDbg: `net03.exe 32103`.
2. Send a known-good candidate with `send_tcp.py --challenge net03 --mode probe`.
3. Find the received candidate in heap memory, then follow it through the
   processing routine to the stack staging area.
4. Compare the pre- and post-processing arrays with `compare_bytes.py`.

Use `--overflow-context` only after you can locate the probe data. Both modes
use the same parsing and processing functions; only the payload placement and
length differ. Do not infer a bad character from the TCP framing alone.
