"""Python bridge to the `recon` Go binary.

`recon` is built as a standalone Go executable (see ``Tools/recon``). This
package lets the rest of the Python toolkit locate that binary, run it, and
consume its ``--json`` output as native dicts/lists, so recon's static-analysis
and triage results can feed the existing pattern/badchars/exploit workflow.

Programmatic use:

    from Tools.recon_bridge import pe, triage
    info = pe("target.exe")            # dict: mitigations, sections, ...
    hot = triage("target.exe", top=0)  # list of ranked functions

The `recon` console script (registered in pyproject) is a thin pass-through to
the binary, so `recon pe target.exe` works from the venv like the other tools.
"""

from .cli import cdb, find_binary, pe, triage

__all__ = ["pe", "triage", "cdb", "find_binary"]
