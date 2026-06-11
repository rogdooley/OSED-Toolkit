#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = str(Path(__file__).resolve().parents[2])
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def main(argv: list[str] | None = None) -> int:
    print(
        "ip2hex.py is deprecated; use string2hex.py ip ... instead.",
        file=sys.stderr,
    )
    from Tools.Value_Conversion_Scripts.string2hex import main as string_main

    return string_main(["ip", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    raise SystemExit(main())
