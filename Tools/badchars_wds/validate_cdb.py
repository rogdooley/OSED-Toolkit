#!/usr/bin/env python3
"""Validate cdb startup, breakpoint hit, and dump creation explicitly."""

import argparse
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

_THIS_DIR = os.path.abspath(os.path.dirname(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from badchars_wds.analyzer import generate_candidate_bytes
from badchars_wds.cdb import CDBDriver
from badchars_wds.config import ConfigValidationError, load_config
from badchars_wds.transport import build_sender
from badchars_wds.wds import _wrap_expr


INSTALL_MARKER = "BP_SCRIPT_READY"
HIT_MARKER = "BP_HIT"
LIST_BEGIN_MARKER = "BP_LIST_BEGIN"
LIST_END_MARKER = "BP_LIST_END"
SCRIPT_FILENAME = "validate_cdb.wds"
POLL_INTERVAL_SECONDS = 0.05
SIZE_SETTLE_SECONDS = 0.02

# Public aliases used by tests and external callers.
BP_HIT = HIT_MARKER


@dataclass
class ValidationResult:
    breakpoint_command_sent: bool
    breakpoint_listed: bool
    breakpoint_hit: bool
    dump_written: bool
    dump_size: int
    driver_exited: bool
    driver_returncode: Optional[int]
    transcript_tail: str
    breakpoint_listing: List[str]
    script_path: str
    dump_path: str


class CDBValidationHarness(object):
    def __init__(self, driver, sender, stage, offset, dump_dir, magic, excluded_bytes, timeout, restart_delay):
        self._driver = driver
        self._sender = sender
        self._stage = stage
        self._offset = offset
        self._dump_dir = dump_dir
        self._magic = magic
        self._excluded_bytes = set(excluded_bytes)
        self._timeout = float(timeout)
        self._restart_delay = float(restart_delay)
        self._script_path = os.path.join(dump_dir, SCRIPT_FILENAME)
        self._dump_path = self._resolve_dump_path()

    def run(self):
        self._write_script()
        self._clear_dump()
        driver_exited = False
        driver_returncode = None
        try:
            self._driver.start()
            if self._restart_delay > 0:
                time.sleep(self._restart_delay)

            self._sender.send(self._build_payload())
            deadline = time.monotonic() + self._timeout

            while time.monotonic() < deadline:
                transcript = self._driver.transcript()
                listed = _extract_breakpoint_listing(transcript)
                dump_size = _stable_file_size(self._dump_path)
                if dump_size is None:
                    dump_written = False
                    dump_size_value = 0
                else:
                    dump_written = dump_size > 0
                    dump_size_value = dump_size

                if HIT_MARKER in transcript and dump_written:
                    return ValidationResult(
                        breakpoint_command_sent=INSTALL_MARKER in transcript,
                        breakpoint_listed=bool(listed),
                        breakpoint_hit=True,
                        dump_written=True,
                        dump_size=dump_size_value,
                        driver_exited=False,
                        driver_returncode=None,
                        transcript_tail=transcript[-4000:],
                        breakpoint_listing=listed,
                        script_path=self._script_path,
                        dump_path=self._dump_path,
                    )

                if not self._driver.is_running():
                    driver_exited = True
                    try:
                        driver_returncode = self._driver.wait(timeout=1.0)
                    except Exception:
                        driver_returncode = None
                    break

                time.sleep(POLL_INTERVAL_SECONDS)

            transcript = self._driver.transcript()
            listed = _extract_breakpoint_listing(transcript)
            dump_size = _stable_file_size(self._dump_path)
            return ValidationResult(
                breakpoint_command_sent=INSTALL_MARKER in transcript,
                breakpoint_listed=bool(listed),
                breakpoint_hit=HIT_MARKER in transcript,
                dump_written=(dump_size or 0) > 0,
                dump_size=dump_size or 0,
                driver_exited=driver_exited,
                driver_returncode=driver_returncode,
                transcript_tail=transcript[-4000:],
                breakpoint_listing=listed,
                script_path=self._script_path,
                dump_path=self._dump_path,
            )
        finally:
            self._driver.kill()

    def _write_script(self):
        os.makedirs(self._dump_dir, exist_ok=True)
        with open(self._script_path, "w", encoding="utf-8") as handle:
            handle.write(generate_validation_wds(self._stage))

    def _clear_dump(self):
        try:
            os.remove(self._dump_path)
        except OSError:
            pass

    def _build_payload(self):
        candidates = generate_candidate_bytes(self._excluded_bytes)
        return b"A" * self._offset + self._magic + candidates + (b"C" * 32)

    def _resolve_dump_path(self):
        path = self._stage.final_dump_path
        if os.path.isabs(path):
            return path
        return os.path.join(self._dump_dir, path)


def generate_validation_wds(stage):
    dump_end_expr = "({base}+0x{size:x})".format(
        base=_wrap_expr(stage.dump_expr),
        size=stage.dump_size,
    )
    bp_body = '.echo {hit}; .writemem {dump} {start} {end}; g'.format(
        hit=HIT_MARKER,
        dump=stage.final_dump_path,
        start=_wrap_expr(stage.dump_expr),
        end=dump_end_expr,
    )
    bp_body_escaped = bp_body.replace('"', '\\"')

    module_name = _breakpoint_module_name(stage.breakpoint)
    lines = [
        "sxd ibp",
        "sxd ld",
        "sxn av",
        'sxe -c ".echo BADCHAR_CRASH; q" av',
    ]
    if module_name:
        lines.append(".reload /f {0}.exe".format(module_name))
    lines.extend([
        'bp {bp} "{body}"'.format(bp=stage.breakpoint, body=bp_body_escaped),
        ".echo {0}".format(LIST_BEGIN_MARKER),
        "bl",
        ".echo {0}".format(LIST_END_MARKER),
        ".echo {0}".format(INSTALL_MARKER),
        "g",
    ])
    return "\n".join(lines) + "\n"


def _breakpoint_module_name(breakpoint):
    if "!" in breakpoint:
        return breakpoint.split("!", 1)[0].strip()
    if "+" in breakpoint:
        return breakpoint.split("+", 1)[0].strip()
    return None


def _extract_breakpoint_listing(transcript):
    lines = transcript.splitlines()
    start = None
    end = None
    for index, line in enumerate(lines):
        if LIST_BEGIN_MARKER in line:
            start = index + 1
        elif LIST_END_MARKER in line and start is not None:
            end = index
            break
    if start is None or end is None or end < start:
        return []
    return [line.rstrip() for line in lines[start:end] if line.strip()]


def _stable_file_size(path):
    if not os.path.exists(path):
        return None
    try:
        size_before = os.path.getsize(path)
        time.sleep(SIZE_SETTLE_SECONDS)
        size_after = os.path.getsize(path)
    except OSError:
        return None
    if size_before != size_after:
        return None
    return size_after


def _parse_args():
    parser = argparse.ArgumentParser(description="Validate cdb breakpoint installation, hit, and dump creation.")
    parser.add_argument("--config", default="config.badchars.local.json", help="Path to JSON config file.")
    return parser.parse_args()


def main():
    args = _parse_args()
    try:
        cfg = load_config(args.config)
    except ConfigValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    sender = build_sender(cfg.transport)
    driver = CDBDriver(
        cdb_path=cfg.driver["cdb_path"],
        target_command=cfg.driver["target_command"],
        script_path=os.path.join(cfg.dump_dir, SCRIPT_FILENAME),
        log_path=cfg.driver.get("log_path"),
        cwd=cfg.driver.get("cwd"),
        env=cfg.driver.get("env"),
    )

    harness = CDBValidationHarness(
        driver=driver,
        sender=sender,
        stage=cfg.stage,
        offset=cfg.offset,
        dump_dir=cfg.dump_dir,
        magic=cfg.magic,
        excluded_bytes=cfg.excluded_bytes,
        timeout=cfg.timeout,
        restart_delay=cfg.restart_delay,
    )
    result = harness.run()
    print("breakpoint_command_sent={0}".format(result.breakpoint_command_sent))
    print("breakpoint_listed={0}".format(result.breakpoint_listed))
    print("breakpoint_hit={0}".format(result.breakpoint_hit))
    print("dump_written={0}".format(result.dump_written))
    print("dump_size={0}".format(result.dump_size))
    print("driver_exited={0}".format(result.driver_exited))
    print("driver_returncode={0}".format(result.driver_returncode))
    print("script_path={0}".format(result.script_path))
    print("dump_path={0}".format(result.dump_path))
    if result.breakpoint_listing:
        print("breakpoint_listing:")
        for line in result.breakpoint_listing:
            print(line)
    if result.transcript_tail:
        print("transcript_tail:")
        print(result.transcript_tail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
