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
    "GetModuleHandleA": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="HMODULE GetModuleHandleA(LPCSTR lpModuleName)",
        arguments=[
            Argument("lpModuleName", "LPCSTR", "NULL returns base of current process; or e.g. kernel32.dll"),
        ],
    ),
    # --- kernel32.dll : memory ---
    "VirtualAlloc": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,"
            " DWORD flAllocationType, DWORD flProtect)"
        ),
        arguments=[
            Argument("lpAddress", "LPVOID", "NULL to let OS choose; or preferred address"),
            Argument("dwSize", "SIZE_T", "size of region in bytes"),
            Argument("flAllocationType", "DWORD", "MEM_COMMIT|MEM_RESERVE = 0x3000"),
            Argument("flProtect", "DWORD", "PAGE_EXECUTE_READWRITE = 0x40"),
        ],
    ),
    "VirtualProtect": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,"
            " DWORD flNewProtect, PDWORD lpflOldProtect)"
        ),
        arguments=[
            Argument("lpAddress", "LPVOID", "base of region to change"),
            Argument("dwSize", "SIZE_T", "size in bytes"),
            Argument("flNewProtect", "DWORD", "PAGE_EXECUTE_READ = 0x20; PAGE_EXECUTE_READWRITE = 0x40"),
            Argument("lpflOldProtect", "PDWORD", "pointer to DWORD for old protection; use a scratch slot"),
        ],
    ),
    # --- kernel32.dll : process ---
    "CreateThread": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype=(
            "HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,"
            " SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,"
            " LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)"
        ),
        arguments=[
            Argument("lpThreadAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("dwStackSize", "SIZE_T", "0 for default"),
            Argument("lpStartAddress", "LPTHREAD_START_ROUTINE", "pointer to shellcode or function"),
            Argument("lpParameter", "LPVOID", "NULL or pointer to argument"),
            Argument("dwCreationFlags", "DWORD", "0 to run immediately"),
            Argument("lpThreadId", "LPDWORD", "NULL; output thread ID, unused in shellcode"),
        ],
    ),
    "GetLastError": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="DWORD GetLastError(void)",
        arguments=[],
    ),
    # --- kernel32.dll : synchronization ---
    "WaitForSingleObject": APIRecord(
        module="kernel32.dll",
        category="synchronization",
        prototype="DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)",
        arguments=[
            Argument("hHandle", "HANDLE", "thread or process handle to wait on"),
            Argument("dwMilliseconds", "DWORD", "INFINITE = 0xFFFFFFFF; or timeout in ms"),
        ],
    ),
    "CloseHandle": APIRecord(
        module="kernel32.dll",
        category="synchronization",
        prototype="BOOL CloseHandle(HANDLE hObject)",
        arguments=[
            Argument("hObject", "HANDLE", "handle to close; returns nonzero on success"),
        ],
    ),
    # --- kernel32.dll : filesystem (additional) ---
    "ReadFile": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,"
            " LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)"
        ),
        arguments=[
            Argument("hFile", "HANDLE", "handle from CreateFileA"),
            Argument("lpBuffer", "LPVOID", "pointer to destination buffer"),
            Argument("nNumberOfBytesToRead", "DWORD", "number of bytes to read"),
            Argument("lpNumberOfBytesRead", "LPDWORD", "pointer to DWORD for bytes read; NULL if lpOverlapped set"),
            Argument("lpOverlapped", "LPOVERLAPPED", "NULL for synchronous I/O"),
        ],
    ),
    "WriteFile": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,"
            " LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)"
        ),
        arguments=[
            Argument("hFile", "HANDLE", "handle from CreateFileA"),
            Argument("lpBuffer", "LPCVOID", "pointer to source buffer"),
            Argument("nNumberOfBytesToWrite", "DWORD", "number of bytes to write"),
            Argument("lpNumberOfBytesWritten", "LPDWORD", "pointer to DWORD for bytes written; NULL if lpOverlapped set"),
            Argument("lpOverlapped", "LPOVERLAPPED", "NULL for synchronous I/O"),
        ],
    ),
    "GetTempPathA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)",
        arguments=[
            Argument("nBufferLength", "DWORD", "size of lpBuffer in chars; MAX_PATH = 260"),
            Argument("lpBuffer", "LPSTR", "pointer to buffer that receives temp path"),
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
    "bind": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int bind(SOCKET s, const struct sockaddr *addr, int namelen)",
        arguments=[
            Argument("s", "SOCKET", "listening socket from WSASocketA"),
            Argument("addr", "const struct sockaddr *", "pointer to sockaddr_in with sin_family, sin_port, sin_addr"),
            Argument("namelen", "int", "0x10 (sizeof sockaddr_in)"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "listen": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int listen(SOCKET s, int backlog)",
        arguments=[
            Argument("s", "SOCKET", "bound socket from bind()"),
            Argument("backlog", "int", "SOMAXCONN = 0x7fffffff; or small value like 1"),
        ],
    ),
    "accept": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen)",
        arguments=[
            Argument("s", "SOCKET", "listening socket; blocks until client connects"),
            Argument("addr", "struct sockaddr *", "NULL to ignore client address; or pointer to sockaddr_in"),
            Argument("addrlen", "int *", "NULL if addr is NULL; or pointer to 0x10"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "closesocket": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int closesocket(SOCKET s)",
        arguments=[
            Argument("s", "SOCKET", "socket handle to close"),
        ],
    ),
    "WSAGetLastError": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSAGetLastError(void)",
        arguments=[],
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
