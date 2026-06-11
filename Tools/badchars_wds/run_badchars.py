#!/usr/bin/env python3
"""Run badchars_wds orchestrator from JSON config."""

import argparse
import os
import sys

_THIS_DIR = os.path.abspath(os.path.dirname(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from badchars_wds.cdb import CDBDriver
from badchars_wds.config import ConfigValidationError, load_config
from badchars_wds.orchestrator import BadCharOrchestrator
from badchars_wds.transport import build_sender


def _parse_args():
    parser = argparse.ArgumentParser(description="Run badchar discovery workflow.")
    parser.add_argument("--config", default="config.badchars.local.json", help="Path to JSON config file.")
    parser.add_argument("--offset", type=int, help="Override orchestrator.offset")
    parser.add_argument("--breakpoint", help="Override stage.breakpoint")
    parser.add_argument("--dump-expr", dest="dump_expr", help="Override stage.dump_expr")
    parser.add_argument("--host", help="Override transport.host")
    parser.add_argument("--port", type=int, help="Override transport.port")
    parser.add_argument("--timeout", type=float, help="Override orchestrator.timeout")
    return parser.parse_args()


def _build_overrides(args):
    overrides = {}
    if args.offset is not None:
        overrides["offset"] = args.offset
    if args.breakpoint is not None:
        overrides["breakpoint"] = args.breakpoint
    if args.dump_expr is not None:
        overrides["dump_expr"] = args.dump_expr
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    if args.timeout is not None:
        overrides["timeout"] = args.timeout
    return overrides


def main():
    args = _parse_args()
    overrides = _build_overrides(args)
    try:
        cfg = load_config(args.config, overrides=overrides)
    except ConfigValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    sender = build_sender(cfg.transport)
    script_path = os.path.join(cfg.dump_dir, "badchar_bp.wds")

    driver = CDBDriver(
        cdb_path=cfg.driver["cdb_path"],
        target_command=cfg.driver["target_command"],
        script_path=script_path,
        log_path=cfg.driver.get("log_path"),
        cwd=cfg.driver.get("cwd"),
        env=cfg.driver.get("env"),
    )

    orchestrator = BadCharOrchestrator(
        driver=driver,
        stage=cfg.stage,
        sender=sender.send,
        offset=cfg.offset,
        dump_dir=cfg.dump_dir,
        magic=cfg.magic,
        timeout=cfg.timeout,
        restart_delay=cfg.restart_delay,
        max_iterations=cfg.max_iterations,
        excluded_bytes=cfg.excluded_bytes,
        restart_policy=cfg.restart_policy,
        filler_byte=cfg.filler_byte,
        pad_byte=cfg.pad_byte,
        pad_len=cfg.pad_len,
    )

    result = orchestrator.run()
    print("Confirmed bad chars: {}".format(" ".join("0x{:02x}".format(b) for b in result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
