# WinDbg Commands Reference for Exploit Development

## Purpose and Exploit Relevance

This document is a practical reference for WinDbg commands used in exploit development and shellcode debugging. It is NOT a cheat sheet. Every command explains WHY it behaves the way it does, what the output means, and how an exploit developer uses it to understand a running process.

WinDbg is the primary tool for:
- Verifying shellcode behavior live in a target process
- Inspecting Windows internal structures (PEB, TEB, SEH chains, PE headers)
- Setting precise breakpoints without modifying shellcode bytes (hardware breakpoints)
- Analyzing crash state after a write-what-where or buffer overflow
- Confirming API resolution logic produces correct function pointers

Understanding the commands at this level means you can diagnose incorrect shellcode, wrong offsets, and failed API lookups within seconds rather than hours.

---

## Memory Inspection Commands

### `db` — Display Bytes

**Syntax:**
```
db [address] [L count]
db esp L 40           ; show 0x40 bytes starting at ESP
db poi(esp) L 80      ; dereference ESP, then show 0x80 bytes
db poi(ecx+8) L 20    ; dereference ECX+8, show 0x20 bytes
```

**Output format:**
```
0012ff6c  41 41 41 41 42 42 42 42  43 43 43 43 44 44 44 44  AAAABBBBCCCCDDDD
0012ff7c  90 90 90 90 90 90 90 90  eb 04 5e 31 c9 b1 ff 31  ..........^1...1
0012ff8c  69 31 04 0e 83 c0 04 e2  f8 e8 dc ff ff ff 4d 65  i1............Me
```

Each output line contains:
- **Address column** (left): the memory address of the first byte on that line, always 8 hex digits for a 32-bit address
- **Hex columns** (middle): 16 bytes displayed as hex pairs, split into two groups of 8 with a double-space between them. This split makes it easy to identify alignment boundaries at offset +8
- **ASCII column** (right): the same 16 bytes interpreted as ASCII. Non-printable characters display as `.`

WinDbg displays 16 bytes per line. This is intentional: 16 bytes aligns with cache line structure and makes it easy to spot 4-byte or 8-byte aligned values visually.

**Why 8 bytes + ASCII:** The dual-column hex layout allows you to identify byte patterns (shellcode opcodes, padding bytes, null terminators) while the ASCII column helps spot embedded strings, markers like `w00tw00t`, or function prologues (`MZ` = `4d 5a`).

**Register dereferencing with `poi()`:**

`poi()` is the WinDbg pseudo-function for "pointer-sized dereference" — it reads the value at the given address and uses THAT as the address for the display command.

```
db poi(ecx+8) L 20
```
This says: read 4 bytes at address `ecx+8`, treat that value as a pointer, then display 0x20 bytes from there. This is essential for following pointer chains through structures without manually reading each intermediate value.

**Range syntax vs L count:**
- `db esp L 40` — display 0x40 (64) bytes starting at ESP. L always takes a hex count.
- `db esp esp+40` — display from ESP up to (but not including) ESP+0x40. Less common but valid.
- The L count form is preferred because it's explicit and doesn't require mental arithmetic.

**Common uses in shellcode work:**
```
db eip L 20       ; disassembly preview — see raw opcodes under instruction pointer
db esp L 100      ; inspect entire stack frame
db poi(ebp) L 40  ; inspect caller's frame via saved EBP
```

---

### `dd` — Display DWORDs

**Syntax:**
```
dd esp
dd eax L 10           ; show 16 DWORDs (64 bytes) from EAX
dd poi(fs:0)          ; dereference FS:0 (SEH chain head)
dd 0x7c800000 L 4     ; show first 4 DWORDs of kernel32 base (MZ header)
```

**Output format:**
```
0012ff6c  41414141 42424242 43434343 44444444
0012ff7c  90909090 90909090 eb045e31 c9b1ff31
0012ff8c  69310e83 c004e2f8 e8dcffff ff4d6572
```

Each line shows 4 DWORDs (16 bytes total). Each DWORD is 8 hex characters = 32 bits. Addresses advance by 0x10 per line.

**Why `dd` is preferred over `db` for pointer chains:**

Windows stores almost everything as 4-byte (DWORD) pointers in 32-bit processes. When you are following a linked list, walking a vtable, or examining a stack of return addresses, `dd` shows you the actual pointer values directly:

```
dd poi(fs:0)
```
produces:
```
0012fe80  0012fecc 0012fefc 77d2a3e0 ffffffff
```

You can read pointer values at a glance. With `db` the same data would look like:
```
cc fe 12 00 fc fe 12 00 e0 a3 d2 77 ff ff ff ff
```
and you'd have to mentally reverse the byte order for each pointer (little-endian).

**Little-endian byte order:** Windows on x86 stores multi-byte values little-endian: the least-significant byte is at the lowest address. `dd` handles this for you — the displayed DWORD is already the correct value. `db` shows the raw bytes in memory order, which means the first byte is the LSB of any pointer stored there.

Example: pointer `0x7c800000` stored in memory as bytes `00 00 80 7c`. `db` shows `00 00 80 7c`. `dd` shows `7c800000`. For shellcode work, `dd` is almost always what you want.

**Examining the SEH chain head:**
```
0:000> dd poi(fs:0)
0012fe80  0012fecc 77d2a3e0 0012ff3c 77d2a3e0
           ^Flink    ^Handler  ^next...
```

---

### `dq` and `dp` — Quad-Words and Pointer-Sized Values

**`dq` — Display Quad-Words (8 bytes each):**
```
dq rsp L 8        ; x64: show 8 QWORDs from RSP
dq 0x7ff6deadbeef L 4
```

Output format:
```
00000000`0012ff00  00007ff6`deadbeef 00000000`00000001
00000000`0012ff10  00007ff6`cafebabe 00000000`00000000
```

Use `dq` exclusively on 64-bit targets. On a 64-bit process, pointers are 8 bytes, so `dd` would show you two half-pointers per QWORD — completely misleading.

**`dp` — Display Pointer-Sized Values:**

`dp` is architecture-aware: it displays DWORDs on x86 and QWORDs on x64. This makes `dp` the correct choice when you want to write commands that work across both architectures:
```
dp esp L 10        ; correct on both x86 and x64
```

In practice, exploit developers tend to use `dd` (explicitly x86) when writing 32-bit shellcode and `dq` for 64-bit work, since architecture ambiguity is usually not a concern for a specific target.

---

### `da` and `du` — ASCII and Unicode String Display

**`da` — Display ASCII (null-terminated):**
```
da 0x7c84428b         ; display ASCII string at that address
da poi(esi+0x50)      ; dereference then display
```

Output:
```
7c84428b  "VirtualAlloc"
```

`da` walks bytes forward from the given address until it finds a null byte (`0x00`), printing them as ASCII characters. It will print up to a reasonable limit (usually 256 characters).

**`du` — Display Unicode (UTF-16LE, null-terminated):**
```
du poi(esi+0x50)      ; BaseDllName.Buffer field of LDR_DATA_TABLE_ENTRY
du 0x002d7a40
```

Output:
```
002d7a40  "kernel32.dll"
```

`du` expects UTF-16LE encoding: each character is 2 bytes, with the ASCII character in the low byte and `0x00` in the high byte. A null terminator is two zero bytes (`00 00`).

**Why `du` for UNICODE_STRING.Buffer:**

The Windows kernel uses `UNICODE_STRING` structures for almost all module and path names:
```c
typedef struct _UNICODE_STRING {
    USHORT Length;          // byte length of string (not null-terminated count)
    USHORT MaximumLength;   // byte capacity of buffer
    PWSTR  Buffer;          // pointer to UTF-16LE string
} UNICODE_STRING;
```

The `Buffer` field points to UTF-16LE data. If you use `da` on it, you see:
```
002d7a40  "k"        ; stops after 1 character because next byte is 0x00
```

Use `du` to get the correct display. The `LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer` field is the most common place this comes up in shellcode PEB-walk verification:
```
0:000> du poi(poi(ebx+0x1c)-0x8+0x28)    ; BaseDllName.Buffer
002d7a40  "kernel32.dll"
```

---

### `dps` — Display Pointer-Sized Values with Symbol Resolution

**Syntax:**
```
dps esp L 20           ; show 0x20 pointer-sized values from ESP with symbols
dps eip L 10           ; show code pointers near EIP
dps 0x0012ff00 L 40
```

**Output format:**
```
0012ff6c  0012fecc
0012ff70  77d2a3e0 ntdll!_except_handler3
0012ff74  0012ff88
0012ff78  004015a0 exploit!main+0x30
0012ff7c  7c817077 kernel32!BaseProcessStart+0x23
0012ff80  00000000
```

`dps` combines `dd`/`dq` output with symbol lookup. For each value that falls within a known module's address range, WinDbg appends the nearest symbol name with an offset. This is invaluable for:

1. **Tracing return addresses on the stack**: when you overwrite a return address and step through, `dps esp` shows you exactly what is on the stack and what functions those addresses resolve to.

2. **Identifying shellcode placement**: addresses without symbols show as bare hex — useful to see the shellcode's injected memory region standing out among legitimate module addresses.

3. **SEH chain analysis**: SEH handler addresses on the stack will resolve to their handler function names if symbols are loaded.

4. **Function call chain reconstruction**: after a crash, `dps ebp` and walking the chain backwards via saved EBPs and return addresses tells you the call history.

**Verifying ASLR rebasing:**
```
0:000> dps esp L 20
0012ff70  74f2a3e0 ntdll!_except_handler3    ; ntdll loaded at 0x74f20000 (rebased)
```
If you expected ntdll at `0x7c920000` (pre-ASLR XP base) but see `0x74f20000`, ASLR has moved it. `dps` makes this immediately visible.

---

## Structure Display Commands

### `dt` — Display Type

`dt` reads Windows debug type information (PDB symbols) to display a structure's layout, fields, offsets, and values at a given address.

**Syntax forms:**
```
dt ntdll!_PEB @$peb                       ; show PEB at the $peb pseudo-register
dt ntdll!_PEB_LDR_DATA poi(@$peb+0xc)    ; PEB_LDR_DATA at PEB.Ldr
dt ntdll!_LDR_DATA_TABLE_ENTRY           ; show type layout only (no address)
dt -r ntdll!_PEB @$peb                   ; recursive expansion of all sub-structures
dt -r2 ntdll!_PEB @$peb                  ; expand 2 levels deep
```

**Basic output — type layout without address:**
```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x008 InMemoryOrderLinks : _LIST_ENTRY
   +0x010 InInitializationOrderLinks : _LIST_ENTRY
   +0x018 DllBase          : Ptr32 Void
   +0x01c EntryPoint       : Ptr32 Void
   +0x020 SizeOfImage      : Uint4B
   +0x024 FullDllName      : _UNICODE_STRING
   +0x02c BaseDllName      : _UNICODE_STRING
   +0x034 Flags            : Uint4B
   +0x038 LoadCount        : Uint2B
   +0x03a TlsIndex         : Uint2B
   +0x03c HashLinks        : _LIST_ENTRY
   +0x044 TimeDateStamp    : Uint4B
```

The `+0x000` style offsets are the byte offset from the structure base. These are exactly the offsets used in shellcode PEB-walking assembly. When your shellcode accesses `[ebx+0x18]` to get `DllBase`, you can verify this is correct by checking `dt ntdll!_LDR_DATA_TABLE_ENTRY` and confirming `DllBase` is at `+0x018`.

**With address — show actual values:**
```
0:000> dt ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''     ← set to 1 when under debugger
   +0x003 BitField         : 0 ''
   +0x008 Mutant           : 0xffffffff Void
   +0x00c Ldr              : 0x77a94d00 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x00331f28 _RTL_USER_PROCESS_PARAMETERS
   +0x018 SubSystemData    : (null)
   +0x02c ProcessHeap      : 0x00330000 Void
   +0x038 FastPebLock      : 0x77aa4900 _RTL_CRITICAL_SECTION
```

**The `@$peb` pseudo-register:**

WinDbg provides `@$peb` as a built-in pseudo-register that resolves to the address of the current process's PEB. Internally it reads `fs:[0x30]` on x86 (the TEB has a pointer to the PEB at offset 0x30). You can verify this:
```
0:000> ? poi(@$teb+0x30)
Evaluate expression: 2130558976 = 7efde000
0:000> ? @$peb
Evaluate expression: 2130558976 = 7efde000
```

**Navigating nested structures:**

To walk from PEB to a specific module entry:
```
0:000> dt ntdll!_PEB @$peb              ; see Ldr at +0x00c = 0x77a94d00
0:000> dt ntdll!_PEB_LDR_DATA 0x77a94d00  ; see InInitializationOrderModuleList at +0x01c
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY 0x002d7a20-0x10  ; first entry (subtract InInitOrder offset)
```

**The `-r` flag for recursive expansion:**

```
0:000> dt -r ntdll!_PEB @$peb
```

This recursively expands all nested structure fields. This can produce hundreds of lines for complex structures like `_PEB`. Use `-r2` or `-r3` to limit recursion depth when you only want to go a few levels deep:

```
0:000> dt -r2 ntdll!_PEB_LDR_DATA 0x77a94d00
```

**Using `dt` to verify offsets against WinDbg type info:**

When writing PEB-walking shellcode, confirm every hardcoded offset:
```
; Shellcode accesses PEB.Ldr at +0x0c:
mov eax, [eax+0x0c]    ; EAX should now be _PEB_LDR_DATA*

; Verify in WinDbg:
0:000> dt ntdll!_PEB @$peb Ldr
   +0x00c Ldr : 0x77a94d00 _PEB_LDR_DATA *
```
The offset `+0x00c` confirms the shellcode's `[eax+0x0c]` is correct.

---

## Module and Symbol Commands

### `lm` — List Modules

**Syntax:**
```
lm                      ; list all loaded modules
lm m kernel32           ; filter by module name (wildcard supported)
lm v m kernel32         ; verbose output
lmf m ntdll             ; show file path
lm m ws2*               ; wildcard: ws2_32, etc.
```

**Basic output:**
```
start    end      module name
00400000 00415000   exploit    (deferred)
7c800000 7c8f4000   kernel32   (pdb symbols)
7c920000 7c9b2000   ntdll      (pdb symbols)
74320000 743e1000   ws2_32     (export symbols)
```

Columns:
- **start**: the base address where the module is loaded (image base after ASLR rebasing)
- **end**: first address beyond the module's memory range
- **module name**: the short name used for symbol resolution
- **(pdb symbols)**: symbol loading status

**Verifying ASLR rebasing:**

On a pre-ASLR system (Windows XP without patches, or with ASLR disabled), kernel32 loads at its preferred base `0x7C800000`. On a modern system with ASLR, it will load at a randomized address. `lm` tells you immediately:
```
lm m kernel32
start    end      module name
75a00000 75ad6000   kernel32
```
kernel32 is at `0x75A00000` instead of `0x7C800000`. Any hardcoded address-based shellcode will fail; only name/hash-based PEB-walk shellcode will work.

**Verbose output:**
```
0:000> lm v m kernel32
start    end      module name
7c800000 7c8f4000   kernel32   (pdb symbols)
    Loaded symbol image file: kernel32.pdb
    Image path: C:\WINDOWS\system32\kernel32.dll
    Image name: kernel32.dll
    Timestamp:        Thu Mar 21 15:04:24 2019
    CheckSum:         000F3CE5
    ImageSize:        000F4000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
```

The **Timestamp** is critical for exploit development: different patch levels of kernel32 have different layouts, function addresses, and ROP gadget offsets. Two systems with the same OS version but different timestamps may have different offsets.

---

### `!dh` — Display PE Headers

**Syntax:**
```
!dh kernel32              ; by module name
!dh 0x7c800000            ; by base address
!dh -f kernel32           ; show file header only
!dh -s kernel32           ; show section headers only
!dh -e kernel32           ; show export directory
```

**Full annotated output:**
```
0:000> !dh kernel32

File Type: DLL
FILE HEADER VALUES
     14C machine (i386)                 ← x86 architecture
       4 number of sections
3B7D84E5 time date stamp Thu Aug 16 15:56:21 2001
       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
    2102 characteristics                ← IMAGE_FILE_DLL | IMAGE_FILE_32BIT_MACHINE
           Executable
           32 bit word machine
           DLL

OPTIONAL HEADER VALUES
     10B magic #                        ← PE32 (not PE32+ = 0x20B)
    7.00 linker version
   E2000 size of code
   1E600 size of initialized data
       0 size of uninitialized data
    10EB entry point                    ← RVA from image base
    1000 base of code
   E3000 base of data
7C800000 image base                    ← preferred load address
    1000 section alignment             ← sections aligned to 0x1000 (page size)
     200 file alignment
    5.00 operating system version
    5.01 image version
    5.01 subsystem version
      20 Win32 version
   F4000 size of image
    1000 size of headers
   F3CE5 checksum
       2 subsystem (Windows GUI)
     140 DLL characteristics
   40000 size of stack reserve
    1000 size of stack commit
  100000 size of heap reserve
    1000 size of heap commit
       0 loader flags
      10 number of directories

DATA DIRECTORIES
              0 [       0] address [size] of Export Directory        ← *** CRITICAL ***
          10000 [    B060] address [size] of Export Directory
          1BC60 [    2168] address [size] of Import Directory
          E3000 [    D800] address [size] of Resource Directory
              0 [       0] address [size] of Exception Directory
              0 [       0] address [size] of Security Directory
          F0000 [    2798] address [size] of Base Relocation Directory
           1CF8 [      38] address [size] of Debug Directory
              0 [       0] address [size] of Architecture Directory
              0 [       0] address [size] of Global Pointer Directory
              0 [       0] address [size] of TLS Directory
              0 [       0] address [size] of Load Configuration Directory
           1CC0 [      28] address [size] of Bound Import Directory
          10000 [     528] address [size] of Import Address Table Directory
              0 [       0] address [size] of Delay Load Directory
              0 [       0] address [size] of COR20 Header Directory
              0 [       0] address [size] of Reserved Directory

SECTION HEADER #1
   .text name
   E1D26 virtual size
    1000 virtual address                ← .text starts at RVA 0x1000
   E2000 size of raw data
     400 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
60000020 flags                         ← CODE | EXECUTE | READ
         Code
         (no align specified)
         Execute Read

SECTION HEADER #2
  .data name
    5B88 virtual size
   E3000 virtual address
    3E00 size of raw data
   E2400 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
C0000040 flags                         ← INITIALIZED_DATA | READ | WRITE
         Initialized Data
         Read Write
```

**What each field means for exploit development:**

- **Export Directory** (DataDirectory[0]): The RVA `0x10000` is the offset from image base to the `IMAGE_EXPORT_DIRECTORY` structure. Add image base to get the VA: `0x7C800000 + 0x10000 = 0x7C810000`. This is your starting point for manual export walking.

- **Import Address Table Directory** (DataDirectory[12]): The IAT is where imported functions are patched at load time. Overwriting IAT entries is an older exploitation technique.

- **Section flags `60000020`**: `0x20` = IMAGE_SCN_CNT_CODE, `0x20000000` = IMAGE_SCN_MEM_EXECUTE, `0x40000000` = IMAGE_SCN_MEM_READ. A section with flags `0xE0000020` would be read/write/execute — suspicious and typical of packed code.

- **Image base `0x7C800000`**: Compare against the actual load address from `lm`. If different, ASLR or rebasing has occurred.

---

### `x` — Examine Symbols

**Syntax:**
```
x kernel32!Virtual*          ; all exports starting with "Virtual"
x ntdll!Nt*                  ; all Nt-prefixed functions
x /a kernel32!LoadLibraryA   ; show address of specific symbol
x /d kernel32!*              ; show all kernel32 exports with type info
```

**Output:**
```
0:000> x kernel32!Virtual*
7c809af1          kernel32!VirtualFree
7c809ae4          kernel32!VirtualAlloc
7c80aa11          kernel32!VirtualQuery
7c80a918          kernel32!VirtualProtect
7c85e4b3          kernel32!VirtualAllocEx
7c85e471          kernel32!VirtualFreeEx
7c80aa66          kernel32!VirtualProtectEx
7c80aa99          kernel32!VirtualQueryEx
7c810d18          kernel32!VirtualLock
7c810d2c          kernel32!VirtualUnlock
```

**Use in shellcode verification:**

When your shellcode's PEB-walk hash function resolves `VirtualAlloc`, the final pointer stored should be `0x7c809ae4` (on this system). Use `x /a kernel32!VirtualAlloc` to get the expected value, then compare against what your shellcode stored:

```
0:000> x /a kernel32!VirtualAlloc
7c809ae4          kernel32!VirtualAlloc
0:000> dd ebp+0x04 L 1         ; your shellcode's stored VirtualAlloc pointer
0012ff80  7c809ae4               ← matches — resolution is correct
```

**Wildcard searching for ROP gadgets:**

```
x ntdll!Rtl*       ; find all Rtl-prefixed utilities in ntdll
```

This helps find functions useful as ROP gadgets or import chain pivots.

---

## Exception and SEH Commands

### `!exchain` — Display SEH Chain

**Syntax:**
```
!exchain
```

**Output:**
```
0:000> !exchain
0012fe80: exploit!_except_handler3+0 (004018c0)
  CRT scope  0, filter: exploit!main+4a (004012aa)
                 func:   exploit!main+60 (004012c0)
0012ff54: exploit!_except_handler3+0 (004018c0)
  CRT scope  0, filter: exploit!main+4a (004012aa)
                 func:   exploit!main+60 (004012c0)
0012ffb0: kernel32!_except_handler3+0 (7c839ae0)
  CRT scope  0, filter: kernel32!BaseProcessStart+0x29 (7c817093)
                 func:   kernel32!BaseProcessStart+0x54 (7c8170be)
0012ffe0: ntdll!_except_handler4+0 (7c91e900)
```

**How to read this output:**

Each entry shows one node in the SEH linked list, reading from the top of the stack downward:
- **`0012fe80`**: the address on the stack where this `EXCEPTION_REGISTRATION_RECORD` lives
- **`exploit!_except_handler3+0`**: the handler function at `0x004018c0`

The chain is a singly-linked list. The last entry always has its `Next` field set to `0xFFFFFFFF` (EXCEPTION_CHAIN_END), which you can verify with `dd`:
```
0:000> dd 0012ffe0 L 2
0012ffe0  ffffffff 7c91e900
           ^Next    ^Handler (ntdll!_except_handler4)
```

**In SEH overwrite exploitation:**

After a controlled write that overwrites a `EXCEPTION_REGISTRATION_RECORD` on the stack:
```
0:000> !exchain
0012fe80: 41414141   ← NEXT overwritten with AAAA
0012fe84: 42424242   ← HANDLER overwritten with BBBB
```
The SEH chain now shows corrupted entries. When an exception fires, execution will jump to `0x42424242` (your shellcode after a POP POP RET gadget sequence).

---

### `.exr` — Display Exception Record

**Syntax:**
```
.exr -1             ; display the most recent exception
.exr <address>      ; display exception record at a specific address
```

**Output:**
```
0:000> .exr -1
ExceptionAddress: 41414141
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000    ← access type: 0 = read, 1 = write, 8 = DEP
   Parameter[1]: 41414141    ← the address that was accessed
```

**Common ExceptionCode values:**

| Code | Meaning |
|------|---------|
| `0xC0000005` | ACCESS_VIOLATION — read/write to invalid address |
| `0xC0000094` | INTEGER_DIVIDE_BY_ZERO |
| `0x80000003` | BREAKPOINT — int3 hit |
| `0x80000004` | SINGLE_STEP — trap flag set |
| `0xC0000409` | STACK_BUFFER_OVERRUN — /GS cookie failure |

**Parameter[0] for ACCESS_VIOLATION:**
- `0` = attempted read
- `1` = attempted write
- `8` = DEP (attempted execution)

When you see `Parameter[0] = 1` with an address like `0x00000041`, you're writing 1 byte past the end of a buffer into address `0x00000041` — typical short write during a format string or heap overflow.

---

### `.cxr` — Set Context from Context Record

**Syntax:**
```
.cxr @$cxr          ; use the current exception's context record
.cxr <address>      ; use context record at a specific memory address
r                   ; after .cxr: show registers from that context
kb                  ; after .cxr: show call stack from that context
```

**Why `.cxr` is necessary:**

When an exception occurs, Windows saves the register state (EIP, ESP, EBP, EAX, etc.) in a `CONTEXT` structure before calling the SEH handler. The debugger's current register view shows the handler's context (EIP pointing to the handler function), NOT the context at the moment of the exception.

`.cxr` tells WinDbg to interpret all subsequent commands using the saved CONTEXT record instead of the live one. After `.cxr`:

```
0:000> .cxr @$cxr
eax=41414141 ebx=00000000 ecx=0012ff6c edx=7c9232bc esi=00000000 edi=00000000
eip=41414141 esp=0012fe74 ebp=0012fecc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
```

Now EIP shows `0x41414141` — the address the overwritten return address was pointing to. This is the actual crash state. Use this to verify your payload precisely overwrote EIP.

To restore normal context: `.cxr 0` or `.ecxr`.

---

### `!analyze -v` — Automated Crash Analysis

**Syntax:**
```
!analyze -v          ; verbose automated analysis
!analyze -v -show    ; show disassembly context
```

WinDbg runs automated heuristics to characterize the crash. Output sections:

```
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Access violation

FAULTING_IP:
exploit+0x1234
41414141 ??              ???

EXCEPTION_RECORD:  (...)
  ExceptionAddress: 41414141
     ExceptionCode: c0000005

CONTEXT:  (...)
  eax=41414141 ebx=...

STACK_TEXT:
0012fe80 41414141 41414141 41414141 41414141 0x41414141
0012ff54 00000000 0012fecc ...

FOLLOWUP_NAME: MachineOwner
```

**How `!analyze -v` identifies key information:**

1. **Faulting IP**: Where EIP was when the exception occurred. `0x41414141` confirms EIP control.
2. **SEH chain state**: Reports whether the SEH chain appears corrupted.
3. **Stack pointer validity**: Checks whether ESP points to readable memory.
4. **Module attribution**: If EIP falls within a module, attributes the crash to that module and reports if it's a known crash signature.

This is typically the first command run after a target crashes during fuzzing or controlled overflow to quickly confirm EIP control and understand the fault type.

---

## Breakpoint Commands

### `bp` — Software Breakpoint

**Syntax:**
```
bp kernel32!VirtualAlloc              ; break at function entry
bp 0x41414141                         ; break at arbitrary address
bp kernel32!WriteFile "r eax; g"      ; break, print EAX, continue automatically
bp /1 kernel32!LoadLibraryA           ; one-shot breakpoint (auto-cleared)
```

`bp` inserts an `int3` (opcode `0xCC`) byte at the target address by temporarily modifying process memory. When EIP reaches that address, the CPU raises exception `0x80000003`, WinDbg catches it, restores the original byte, and stops execution.

**Conditional breakpoints with commands:**

```
bp kernel32!VirtualAlloc ".if (poi(esp+4) == 0) {.echo 'NULL lpAddress'} .else {g}"
```

This breaks at VirtualAlloc, checks if the first argument is NULL, prints a message if so, and otherwise continues. Complex conditions are written in WinDbg's MASM expression syntax.

**Limitations of software breakpoints for shellcode:**

Software breakpoints work by modifying code bytes. If your shellcode computes a hash over itself or uses self-modifying code, inserting `0xCC` corrupts the expected values. Use hardware breakpoints (`ba`) instead.

---

### `ba` — Hardware Access Breakpoint

**Syntax:**
```
ba e 1 <address>    ; break on EXECUTE of 1 byte (execution breakpoint)
ba r 4 <address>    ; break on READ of 4 bytes
ba w 1 <address>    ; break on WRITE of 1 byte
ba w 4 0x0012ff6c   ; break when 4 bytes at 0x0012ff6c are written
```

**Access types:**
- `e` — Execute: fires when EIP reaches this address
- `r` — Read or Write: fires when any read or write of the specified width occurs
- `w` — Write only: fires only on writes

**Width parameter:**
The width must be `1`, `2`, or `4` bytes (hardware limitation). For execution breakpoints, width is always `1`.

**Why hardware breakpoints for shellcode:**

Hardware breakpoints use the CPU's debug registers (DR0-DR3 for addresses, DR7 for control). No code modification happens — the memory at the breakpoint address is completely unmodified. This means:
1. Hash-checking shellcode will not detect the breakpoint
2. NX/DEP memory (execute-only pages) can have execution breakpoints set
3. Breakpoints in ROM or read-only sections work correctly

**Hardware breakpoint limit:**

There are only 4 debug address registers (DR0-DR3). Setting a 5th `ba` breakpoint fails:
```
0:000> ba e 1 0x7c809ae4
0:000> ba e 1 0x7c920000
0:000> ba e 1 0x7c921000
0:000> ba e 1 0x7c922000
0:000> ba e 1 0x7c923000    ; error — only 4 hardware breakpoints
```

Disable one with `bd` before setting a new one.

---

### Breakpoint Management

**List breakpoints:**
```
bl
```
Output:
```
 0 e 7c809ae4     0001 (0001)  0:**** kernel32!VirtualAlloc
 1 e 0012ff6c     0001 (0001)  0:**** [no symbol]
 2 d 7c917685     0001 (0001)  0:**** ntdll!NtAllocateVirtualMemory
```

Columns: index, state (`e`=enabled, `d`=disabled), address, pass count, thread filter, symbol.

**Clear breakpoint:**
```
bc 0             ; clear breakpoint 0
bc *             ; clear all breakpoints
```

**Disable/enable without clearing:**
```
bd 2             ; disable breakpoint 2 (preserves it for re-enabling)
be 2             ; re-enable breakpoint 2
```

**Typical workflow:**
1. `bp kernel32!VirtualAlloc` — set initial break
2. Run: `g`
3. Hit break: inspect state with `dd esp L 4`, `r`
4. `bc 0` — clear the VirtualAlloc break
5. `ba e 1 eax` — set hardware break on returned allocation address
6. `g` — run until shellcode reaches its allocated buffer

---

## Common Mistakes

**Mistake 1: Using `db` when you need `dd` for pointer chains.**

When following linked lists or vtables, `db` shows raw bytes in memory order. You must manually reverse 4-byte groups to get pointer values. Use `dd` for any data that is a collection of DWORD pointers.

```
; Wrong — confusing byte order
0:000> db poi(fs:0) L 8
0012fe80  cc fe 12 00 e0 a3 d2 77  ......w    ; what is the first pointer?

; Right — direct DWORD values
0:000> dd poi(fs:0) L 2
0012fe80  0012fecc 77d2a3e0                   ; Next=0012fecc Handler=77d2a3e0
```

**Mistake 2: Forgetting that `L` counts are hexadecimal.**

`dd esp L 10` shows 0x10 = 16 DWORDs (64 bytes), NOT 10 DWORDs. Beginners frequently type `dd esp L 10` expecting 10 entries and see 16 instead. All WinDbg numeric literals are hex by default unless prefixed with `0n` (decimal) or `0y` (binary).

```
dd esp L 0n10    ; show exactly 10 (decimal) DWORDs
dd esp L 10      ; show 16 (hex) DWORDs
```

**Mistake 3: Not using `.cxr` after an exception before reading registers.**

After an exception fires and the SEH handler runs, all `r` commands show the handler's register context, NOT the crash context. This leads to confusion when EIP looks like a valid address in the handler rather than your `0x41414141` payload:

```
; Without .cxr — shows handler context (misleading)
0:000> r eip
eip=004018c0    ; this is the SEH handler, not the crash point

; Correct — set context from exception CONTEXT record first
0:000> .cxr @$cxr
0:000> r eip
eip=41414141    ; this is the actual crash context
```

**Mistake 4: Using `ba r` instead of `ba w` for write-after-free detection.**

`ba r` fires on BOTH reads AND writes. If you set `ba r 4 <freed_pointer>` to catch use-after-free writes, you will also break on every legitimate read of nearby data. Use `ba w 4 <freed_pointer>` to catch only writes, dramatically reducing false breaks.

**Mistake 5: Ignoring the ASLR-rebased base when comparing to `!dh` output.**

`!dh kernel32` shows RVA-based offsets (relative to image base). When kernel32 is loaded at `0x75A00000` instead of its preferred `0x7C800000`, all RVA-to-VA conversions must use the actual load base. Always run `lm m kernel32` FIRST to get the actual base, THEN add RVAs from `!dh`.

```
; Export directory RVA from !dh = 0x10000
; Actual kernel32 base from lm = 0x75A00000
; Correct VA = 0x75A00000 + 0x10000 = 0x75A10000
```
