"""Static database of Win32 API records and struct layouts for shellcode development."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Argument:
    name: str
    type: str
    notes: str = ""


@dataclass
class APIRecord:
    module: str
    category: str
    prototype: str
    arguments: list[Argument]
    requires_structs: tuple[str, ...] = ()


@dataclass(frozen=True)
class StructField:
    offset: int
    name: str
    size: int
    notes: str = ""


@dataclass
class StructRecord:
    size: int
    alignment: int = 4
    fields: list[StructField] = field(default_factory=list)


@dataclass(frozen=True)
class ModuleInfo:
    dll: str
    load_via: str


API_DATABASE: dict[str, APIRecord] = {
    # --- kernel32.dll : process ---
    "WinExec": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)",
        arguments=[
            Argument("lpCmdLine", "LPCSTR", "pointer to command string, e.g. cmd.exe"),
            Argument("uCmdShow", "UINT", "SW_SHOWNORMAL = 1 or SW_HIDE = 0"),
        ],
    ),
    "ExitProcess": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="VOID ExitProcess(UINT uExitCode)",
        arguments=[
            Argument("uExitCode", "UINT", "0 for clean exit"),
        ],
    ),
    "CreateProcessA": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype=(
            "BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,"
            " LPSECURITY_ATTRIBUTES lpProcessAttributes,"
            " LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,"
            " DWORD dwCreationFlags, LPVOID lpEnvironment,"
            " LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,"
            " LPPROCESS_INFORMATION lpProcessInformation)"
        ),
        arguments=[
            Argument("lpApplicationName", "LPCSTR", "NULL; command in lpCommandLine"),
            Argument("lpCommandLine", "LPSTR", "pointer to cmd string, e.g. cmd.exe"),
            Argument("lpProcessAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("lpThreadAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("bInheritHandles", "BOOL", "TRUE for stdio redirection"),
            Argument("dwCreationFlags", "DWORD", "NULL"),
            Argument("lpEnvironment", "LPVOID", "NULL"),
            Argument("lpCurrentDirectory", "LPCSTR", "NULL"),
            Argument("lpStartupInfo", "LPSTARTUPINFOA", "cb=0x44, STARTF_USESTDHANDLES"),
            Argument("lpProcessInformation", "LPPROCESS_INFORMATION", "output; zero before call"),
        ],
        requires_structs=("STARTUPINFOA", "PROCESS_INFORMATION"),
    ),
    # --- kernel32.dll : filesystem ---
    "CopyFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)",
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", ""),
            Argument("lpNewFileName", "LPCSTR", ""),
            Argument("bFailIfExists", "BOOL", "FALSE to overwrite"),
        ],
    ),
    "DeleteFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL DeleteFileA(LPCSTR lpPathName)",
        arguments=[
            Argument("lpPathName", "LPCSTR", ""),
        ],
    ),
    "MoveFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)",
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", ""),
            Argument("lpNewFileName", "LPCSTR", ""),
        ],
    ),
    "CreateFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,"
            " DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,"
            " DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,"
            " HANDLE hTemplateFile)"
        ),
        arguments=[
            Argument("lpFileName", "LPCSTR", ""),
            Argument("dwDesiredAccess", "DWORD", "GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000"),
            Argument("dwShareMode", "DWORD", "0 for exclusive"),
            Argument("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("dwCreationDisposition", "DWORD", "OPEN_EXISTING=3, CREATE_ALWAYS=2"),
            Argument("dwFlagsAndAttributes", "DWORD", "FILE_ATTRIBUTE_NORMAL=0x80"),
            Argument("hTemplateFile", "HANDLE", "NULL"),
        ],
    ),
    # --- kernel32.dll : library ---
    "LoadLibraryA": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="HMODULE LoadLibraryA(LPCSTR lpLibFileName)",
        arguments=[
            Argument("lpLibFileName", "LPCSTR", "e.g. ws2_32.dll"),
        ],
    ),
    "GetProcAddress": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)",
        arguments=[
            Argument("hModule", "HMODULE", "base address of loaded module"),
            Argument("lpProcName", "LPCSTR", "function name string"),
        ],
    ),
    # --- ws2_32.dll : network ---
    "WSAStartup": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)",
        arguments=[
            Argument("wVersionRequested", "WORD", "MAKEWORD(2,2) = 0x0202"),
            Argument("lpWSAData", "LPWSADATA", "output buffer, allocate 0x190 bytes on stack"),
        ],
        requires_structs=("WSADATA",),
    ),
    "WSASocketA": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype=(
            "SOCKET WSASocketA(int af, int type, int protocol,"
            " LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags)"
        ),
        arguments=[
            Argument("af", "int", "AF_INET = 1"),
            Argument("type", "int", "SOCK_STREAM = 1"),
            Argument("protocol", "int", "IPPROTO_TCP = 6"),
            Argument("lpProtocolInfo", "LPWSAPROTOCOL_INFOA", "NULL"),
            Argument("g", "GROUP", "NULL"),
            Argument("dwFlags", "DWORD", "NULL"),
        ],
    ),
    "connect": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int connect(SOCKET s, const struct sockaddr *name, int namelen)",
        arguments=[
            Argument("s", "SOCKET", "socket handle from WSASocketA; stored at [ebp-0x40]"),
            Argument("name", "const struct sockaddr *", "pointer to sockaddr_in on stack"),
            Argument("namelen", "int", "0x10"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "WSACleanup": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSACleanup(void)",
        arguments=[],
    ),
}


STRUCT_DATABASE: dict[str, StructRecord] = {
    "STARTUPINFOA": StructRecord(
        size=0x44,
        alignment=4,
        fields=[
            StructField(0x00, "cb",         4, "must be 0x44"),
            StructField(0x2c, "dwFlags",    4, "STARTF_USESTDHANDLES = 0x100"),
            StructField(0x38, "hStdInput",  4, "socket handle"),
            StructField(0x3c, "hStdOutput", 4, "socket handle"),
            StructField(0x40, "hStdError",  4, "socket handle"),
        ],
    ),
    "PROCESS_INFORMATION": StructRecord(
        size=0x10,
        alignment=4,
        fields=[
            StructField(0x00, "hProcess",    4, "populated by Windows"),
            StructField(0x04, "hThread",     4, "populated by Windows"),
            StructField(0x08, "dwProcessId", 4, "populated by Windows"),
            StructField(0x0c, "dwThreadId",  4, "populated by Windows"),
        ],
    ),
    "sockaddr_in": StructRecord(
        size=0x10,
        alignment=4,
        fields=[
            StructField(0x00, "sin_family", 2, "AF_INET = 0x0002"),
            StructField(0x02, "sin_port",   2, "network byte order, e.g. 0x2329 = port 9001"),
            StructField(0x04, "sin_addr",   4, "network byte order IPv4 address"),
            StructField(0x08, "sin_zero",   8, "zeroed padding"),
        ],
    ),
    "WSADATA": StructRecord(
        size=0x190,
        alignment=4,
        fields=[],
    ),
}


MODULE_LOAD_ORDER: list[ModuleInfo] = [
    ModuleInfo(dll="kernel32.dll", load_via="peb"),
    ModuleInfo(dll="ws2_32.dll",   load_via="LoadLibraryA"),
]


def get_record(name: str) -> APIRecord:
    """Look up an API by name. Raises KeyError with a clear message if not found."""
    if name not in API_DATABASE:
        raise KeyError(f"'{name}' not found in API_DATABASE")
    return API_DATABASE[name]
