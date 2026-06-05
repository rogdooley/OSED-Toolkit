#!/usr/bin/env python3
"""Compatibility shim for the moved runner location."""

import os
import sys

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.run_badchars import main


if __name__ == "__main__":
    raise SystemExit(main())
