# WinDbg Structure Inspection Reference
## OSED / Windows Exploit Development

**Audience:** OSED students and advanced Windows exploit developers  
**Scope:** Kernel and user-mode data structure inspection during shellcode analysis and exploit development  
**Debugger:** WinDbg (classic) and WinDbg Preview — commands identical unless noted

---

## Table of Contents

1. [dt (Display Type) Fundamentals](#1-dt-display-type-fundamentals)
2. [PEB Inspection](#2-peb-inspection)
3. [PEB_LDR_DATA Inspection](#3-peb_ldr_data-inspection)
4. [LDR_DATA_TABLE_ENTRY Inspection](#4-ldr_data_table_entry-inspection)
5. [EXCEPTION_REGISTRATION_RECORD Inspection](#5-exception_registration_record-inspection)
6. [CONTEXT Structure Inspection](#6-context-structure-inspection)
7. [Heap Inspection](#7-heap-inspection)
8. [TEB Inspection](#8-teb-inspection)
9. [Memory Display Commands](#9-memory-display-commands)
10. [s (Search) Command](#10-s-search-command)
11. [Inspecting PE Headers in Memory](#11-inspecting-pe-headers-in-memory)
12. [ln (List Nearest)](#12-ln-list-nearest)
13. [x (Examine Symbols)](#13-x-examine-symbols)
14. [Anti-Debug Detection Structure Fields](#14-anti-debug-detection-structure-fields)

---

## 1. `dt` (Display Type) Fundamentals

`dt` is the cornerstone command for structure inspection in WinDbg. It uses PDB symbol information to overlay a named type definition on raw memory, giving you field names, offsets, and interpreted values.

### Basic Syntax

```
dt [module!]TypeName [Address]
```

If no address is supplied, `dt` prints only the type layout (offsets and field names) without reading live memory.

### Syntax Variants

| Form | Purpose |
|------|---------|
| `dt ntdll!_PEB` | Print type layout only (no memory read) |
| `dt ntdll!_PEB @$peb` | Read PEB from the `$peb` pseudo-register |
| `dt ntdll!_PEB 7ffd5000` | Read PEB from a literal address |
| `dt -r ntdll!_PEB @$peb` | Recursive expansion of all pointer fields |
| `dt -r2 ntdll!_PEB @$peb` | Recursive up to 2 levels deep |
| `dt -v ntdll!_PEB @$peb` | Verbose: show bit fields, padding, total size |
| `dt -a ntdll!_UNICODE_STRING` | Treat address as array (requires count: `-a[n]`) |
| `dt -b ntdll!_PEB @$peb` | Show raw bytes alongside symbolic output |
| `dt -n ntdll!_PEB` | Force name match (useful with ambiguous names) |

### Understanding Symbolic Output vs. Raw Memory

`dt` interprets memory using type information from symbols. Without symbols (`.pdb` unavailable), you must fall back to manual offset arithmetic using `dd`/`db`.

**With symbols:**
```
0:000> dt ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''       ← set when under a debugger
   +0x003 BitField         : 0 ''
   +0x00c Ldr              : 0x77ca2c40 _PEB_LDR_DATA
   +0x018 ProcessParameters : 0x002c17b8 _RTL_USER_PROCESS_PARAMETERS
   +0x068 NtGlobalFlag     : 0x70         ← heap flags set by debugger
   ...
```

**Without symbols** (stripped binary, no internet access):
```
0:000> dd @$peb L10
7ffd5000  00000000 00000001 00010000 77ca2c40
7ffd5010  002c17b8 00000000 00000001 00000000
...
```
You must know field offsets from memory to interpret values. This reference provides those offsets throughout.

### Using `dt` with PDB Symbols vs. Without

**Check loaded symbols:**
```
0:000> lm m ntdll
start    end        module name
77c10000 77da0000   ntdll      (pdb symbols)  C:\symbols\ntdll.pdb\...
```

**Force symbol reload:**
```
0:000> .reload /f ntdll.dll
```

**If no symbols are available** — use hardcoded offsets documented in this file and the `dd`/`db` commands rather than `dt`.

### Complete `dt -r` Session

```
0:000> dt -r2 ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0 ''
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x00400000 Void
   +0x00c Ldr              : 0x77ca2c40 _PEB_LDR_DATA
      +0x000 Length           : 0x28
      +0x004 Initialized      : 0x1 ''
      +0x008 SsHandle         : (null)
      +0x00c InLoadOrderModuleList : _LIST_ENTRY
         [ 0x271560 - 0x271a20 ]
      +0x014 InMemoryOrderModuleList : _LIST_ENTRY
         [ 0x271568 - 0x271a28 ]
      +0x01c InInitializationOrderModuleList : _LIST_ENTRY
         [ 0x2715b8 - 0x271a38 ]   ← head of the list used by shellcode
   ...
```

**Analyst note:** The `-r2` depth limit prevents runaway output from deeply nested structures like the full loader data tree.

---

## 2. PEB Inspection

The Process Environment Block (PEB) is the primary user-mode structure describing a running process. It is the entry point for shellcode PEB walks used to locate `kernel32.dll`.

### Quick Extension View

```
0:000> !peb
PEB at 7ffd5000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes        ← anti-debug flag
    ImageBaseAddress:         00400000
    Ldr                       77ca2c40
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 002715b8 . 00271a38
    Ldr.InLoadOrderModuleList:           00271560 . 00271a20
    ...
    NtGlobalFlag:             70         ← heap flag indicator
    ...
```

### Full `dt` Session — x86 (32-bit)

```
0:000> dt ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace   : 0 ''
   +0x001 ReadImageFileExecOptions: 0 ''
   +0x002 BeingDebugged           : 0x1 ''   ← PEB+0x02
   +0x003 BitField                : 0 ''
   +0x004 Mutant                  : 0xffffffff Void
   +0x008 ImageBaseAddress        : 0x00400000 Void
   +0x00c Ldr                     : 0x77ca2c40 _PEB_LDR_DATA  ← PEB+0x0C
   +0x010 ProcessParameters       : 0x002c17b8 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData           : (null)
   +0x018 ProcessHeap             : 0x00270000 Void  ← PEB+0x18
   +0x01c FastPebLock             : 0x77ca1da0 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr        : (null)
   +0x024 IFEOKey                 : (null)
   +0x028 CrossProcessFlags       : 0
   +0x02c KernelCallbackTable     : (null)
   +0x030 SystemReserved          : [1] 0
   +0x034 AtlThunkSListPtr32      : 0
   +0x038 ApiSetMap               : 0x00070000 Void
   +0x03c TlsBitmap               : 0x77ca22e0 Void
   +0x040 TlsBitmapBits           : [2] 0x3
   +0x048 ReadOnlySharedMemoryBase: 0x7efe0000 Void
   +0x04c HotpatchInformation     : (null)
   +0x050 ReadOnlyStaticServerData: 0x7efe0a70 Void
   +0x054 AnsiCodePageData        : 0x7efb0000 Void
   +0x058 OemCodePageData         : 0x7efb0000 Void
   +0x05c UnicodeCaseTableData    : 0x7efc0000 Void
   +0x060 NumberOfProcessors      : 4
   +0x064 NtGlobalFlag            : 0x70        ← PEB+0x68 (x86)
   +0x068 CriticalSectionTimeout  : _LARGE_INTEGER ...
   +0x070 HeapSegmentReserve      : 0x100000
   +0x074 HeapSegmentCommit       : 0x2000
   +0x078 HeapDeCommitTotalFreeThreshold : 0x10000
   +0x07c HeapDeCommitFreeBlockThreshold : 0x1000
   +0x080 NumberOfHeaps           : 3
   +0x084 MaximumNumberOfHeaps    : 0x10
   +0x088 ProcessHeaps            : 0x77ca4460 Void
   ...
```

### Key PEB Field Offsets — x86 vs. x64

| Field | x86 Offset | x64 Offset | Notes |
|-------|-----------|-----------|-------|
| `BeingDebugged` | `+0x002` | `+0x002` | BYTE |
| `ImageBaseAddress` | `+0x008` | `+0x010` | PVOID |
| `Ldr` | `+0x00C` | `+0x018` | PPEB_LDR_DATA |
| `ProcessParameters` | `+0x010` | `+0x020` | PRTL_USER_PROCESS_PARAMETERS |
| `ProcessHeap` | `+0x018` | `+0x030` | PVOID |
| `NtGlobalFlag` | `+0x068` | `+0x0BC` | ULONG |
| `TlsStorage` | `+0x02C` | `+0x058` | PVOID |

### x64 PEB Session

```
0:000> dt ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace   : 0 ''
   +0x001 ReadImageFileExecOptions: 0 ''
   +0x002 BeingDebugged           : 0x1 ''
   +0x003 BitField                : 0 ''
   +0x004 Padding0                : [4] ""
   +0x008 Mutant                  : 0xffffffffffffffff Void
   +0x010 ImageBaseAddress        : 0x00007ff6`00400000 Void
   +0x018 Ldr                     : 0x00007ffa`d8a1c4c0 _PEB_LDR_DATA
   +0x020 ProcessParameters       : 0x000001e2`3c2817b8 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData           : (null)
   +0x030 ProcessHeap             : 0x000001e2`3c000000 Void
   +0x0bc NtGlobalFlag            : 0x70        ← PEB+0x0BC (x64)
   ...
```

### Reading Individual Fields Without Full `dt`

When you just want one value:

```
0:000> db @$peb+2 L1
7ffd5002  01                                          .
```

```
0:000> dd @$peb+0xc L1
7ffd500c  77ca2c40       ← Ldr pointer
```

```
0:000> dd @$peb+0x68 L1
7ffd5068  00000070       ← NtGlobalFlag = 0x70 (heap flags from debugger)
```

---

## 3. PEB_LDR_DATA Inspection

`PEB_LDR_DATA` is pointed to by `PEB.Ldr`. It contains three doubly-linked lists enumerating loaded modules. Shellcode PEB walks typically use `InInitializationOrderModuleList`.

### Get the Ldr Address

```
0:000> dd @$peb+0xc L1
7ffd500c  77ca2c40
```

### Display the Structure

```
0:000> dt ntdll!_PEB_LDR_DATA 77ca2c40
   +0x000 Length                          : 0x28
   +0x004 Initialized                     : 0x1 ''
   +0x008 SsHandle                        : (null)
   +0x00c InLoadOrderModuleList           : _LIST_ENTRY [ 0x271560 - 0x271a20 ]
   +0x014 InMemoryOrderModuleList         : _LIST_ENTRY [ 0x271568 - 0x271a28 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x2715b8 - 0x271a38 ]
```

### The Three Module Lists

| List Name | Sorted by | Common shellcode use |
|-----------|----------|----------------------|
| `InLoadOrderModuleList` | Load order | ntdll first (after process stub) |
| `InMemoryOrderModuleList` | Virtual address | Least used directly |
| `InInitializationOrderModuleList` | Init order | **kernel32 is typically index 1** (ntdll is 0) |

### Walking InInitializationOrderModuleList with `dl`

`dl` displays a doubly-linked list. The FLINK of the list head is the first entry.

```
0:000> dt ntdll!_PEB_LDR_DATA 77ca2c40
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x2715b8 - 0x271a38 ]
                                               ↑ FLINK = first entry
```

`0x2715b8` is a pointer embedded within an `_LDR_DATA_TABLE_ENTRY` at its `InInitializationOrderLinks` field. On x86, `InInitializationOrderLinks` is at offset `+0x008` within `_LDR_DATA_TABLE_ENTRY`, so the structure base is:

```
0x2715b8 - 0x008 = 0x2715b0
```

```
0:000> dl 2715b8
002715b8  002716b8 77ca2c5c 00271590 77ca2c60
002716b8  00271918 002715b8 002716f0 77ca2c60
00271918  77ca2c5c 002716b8 00271950 77ca2c60
77ca2c5c  002715b8 77ca2c5c ...
```

The last entry whose FLINK points back to the list head (`77ca2c5c`) signals end-of-list.

### Display the Full Module List (Structured)

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY 2715b8-8
   +0x000 InLoadOrderLinks              : _LIST_ENTRY [ 0x271560 - 0x271a20 ]
   +0x008 InMemoryOrderLinks            : _LIST_ENTRY [ 0x271568 - 0x271a28 ]
   +0x010 InInitializationOrderLinks    : _LIST_ENTRY [ 0x2715b8 - 0x271a38 ]   ← this entry
   +0x018 DllBase                       : 0x77c10000 Void      ← ntdll.dll load base
   +0x01c EntryPoint                    : 0x77c89a80 Void
   +0x020 SizeOfImage                   : 0x18f000
   +0x024 FullDllName                   : _UNICODE_STRING "C:\Windows\SysWOW64\ntdll.dll"
   +0x02c BaseDllName                   : _UNICODE_STRING "ntdll.dll"
   +0x034 Flags                         : 0xa2c4
   ...
```

**Analyst note:** When shellcode accesses `InInitializationOrderModuleList.FLINK`, the first real module is index 0 = ntdll.dll. index 1 = kernel32.dll. This is the module shellcode searches for `GetProcAddress` / `LoadLibraryA`.

---

## 4. LDR_DATA_TABLE_ENTRY Inspection

This structure is the per-module descriptor in all three loader lists.

### Key Field Offsets (x86)

| Field | Offset | Type | Purpose |
|-------|--------|------|---------|
| `InLoadOrderLinks` | `+0x000` | `_LIST_ENTRY` | Load-order list links |
| `InMemoryOrderLinks` | `+0x008` | `_LIST_ENTRY` | Memory-order list links |
| `InInitializationOrderLinks` | `+0x010` | `_LIST_ENTRY` | Init-order list links |
| `DllBase` | `+0x018` | `PVOID` | Module load address |
| `EntryPoint` | `+0x01C` | `PVOID` | DllMain address |
| `SizeOfImage` | `+0x020` | `ULONG` | Image size in bytes |
| `FullDllName` | `+0x024` | `_UNICODE_STRING` | Full path |
| `BaseDllName` | `+0x02C` | `_UNICODE_STRING` | Filename only |

### Key Field Offsets (x64)

| Field | Offset | Type |
|-------|--------|------|
| `InLoadOrderLinks` | `+0x000` | `_LIST_ENTRY` |
| `InMemoryOrderLinks` | `+0x010` | `_LIST_ENTRY` |
| `InInitializationOrderLinks` | `+0x020` | `_LIST_ENTRY` |
| `DllBase` | `+0x030` | `PVOID` |
| `EntryPoint` | `+0x038` | `PVOID` |
| `SizeOfImage` | `+0x040` | `ULONG` |
| `FullDllName` | `+0x048` | `_UNICODE_STRING` |
| `BaseDllName` | `+0x058` | `_UNICODE_STRING` |

### Complete Inspection Session

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY 002716b0
   +0x000 InLoadOrderLinks              : _LIST_ENTRY [ 0x271660 - 0x271560 ]
   +0x008 InMemoryOrderLinks            : _LIST_ENTRY [ 0x271668 - 0x271568 ]
   +0x010 InInitializationOrderLinks    : _LIST_ENTRY [ 0x2716b8 - 0x2715b8 ]
   +0x018 DllBase                       : 0x75a80000 Void   ← kernel32.dll base
   +0x01c EntryPoint                    : 0x75b1c9e0 Void
   +0x020 SizeOfImage                   : 0xf0000
   +0x024 FullDllName                   : _UNICODE_STRING "C:\Windows\SysWOW64\kernel32.dll"
   +0x02c BaseDllName                   : _UNICODE_STRING "kernel32.dll"
   +0x034 Flags                         : 0x8a2c4
   +0x038 LoadCount                     : 0xffff
   +0x03a TlsIndex                      : 0
   +0x03c HashLinks                     : _LIST_ENTRY [ 0x77ca4108 - 0x77ca4108 ]
   +0x044 TimeDateStamp                 : 0x4ce7b96e
```

### Reading DllBase Directly

```
0:000> dd 002716b0+18 L1
002716c8  75a80000    ← kernel32.dll is loaded at 0x75a80000
```

### Printing the BaseDllName String

`_UNICODE_STRING` has layout: `USHORT Length; USHORT MaximumLength; PWSTR Buffer;`

```
0:000> dt ntdll!_UNICODE_STRING 002716b0+2c
   +0x000 Length      : 0x18      ← 24 bytes = 12 UTF-16 chars = "kernel32.dll"
   +0x002 MaximumLength : 0x1a
   +0x004 Buffer      : 0x00271720 "kernel32.dll"
```

Print the wide string:
```
0:000> du 00271720
00271720  "kernel32.dll"
```

Or directly via the buffer pointer in the structure:
```
0:000> du poi(002716b0+2c+4)
00271720  "kernel32.dll"
```

---

## 5. EXCEPTION_REGISTRATION_RECORD Inspection

The SEH chain is a singly-linked list of `_EXCEPTION_REGISTRATION_RECORD` structures on the stack, rooted at `TEB.NtTib.ExceptionList` (accessible via `FS:[0]` on x86).

### Structure Layout

```
0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next    : Ptr32 _EXCEPTION_REGISTRATION_RECORD  ← next handler in chain
   +0x004 Handler : Ptr32     void                         ← handler function pointer
```

Total size: 8 bytes (x86).

### Getting the Chain Head via `$teb`

```
0:000> dt ntdll!_TEB @$teb
   +0x000 NtTib : _NT_TIB
      +0x000 ExceptionList : 0x0019ffa4 _EXCEPTION_REGISTRATION_RECORD
```

Or read it directly:
```
0:000> dd @$teb L1
0019f000  0019ffa4      ← ExceptionList = FS:[0] = first SEH record
```

### Walking the SEH Chain Manually

```
0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0019ffa4
   +0x000 Next    : 0x0019ffe4 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler : 0x0040da10 void  ← application SEH handler

0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0019ffe4
   +0x000 Next    : 0x0019fff0 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler : 0x75aa6320 void  ← kernel32!_except_handler4

0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0019fff0
   +0x000 Next    : 0xffffffff _EXCEPTION_REGISTRATION_RECORD  ← end of chain
   +0x004 Handler : 0x77c3e720 void  ← ntdll!FinalExceptionHandler
```

`Next == 0xffffffff` signals the end of the SEH chain.

### Using `!exchain`

```
0:000> !exchain
0019ffa4: 0040da10
0019ffe4: kernel32!_except_handler4+0 (75aa6320)
  CRT scope  0, filter: kernel32!BaseThreadInitThunk+38 (75b1c9e8)
                func:   kernel32!BaseThreadInitThunk+3f (75b1c9ef)
0019fff0: ntdll!FinalExceptionHandler+0 (77c3e720)
```

**Exploit development note:** Overwriting a `Handler` pointer with a controlled address and then triggering an exception is the basis of classic SEH exploitation. Use this walkthrough to verify your overwrite landed at the right record.

### Inspecting SEH at Time of Exception

After hitting an access violation:
```
0:000> !exchain
0019f39c: 00412345   ← overwritten handler — your shellcode pointer?
0019ffe4: kernel32!_except_handler4+0 (75aa6320)
0019fff0: ntdll!FinalExceptionHandler+0 (77c3e720)
```

Compare the overwritten handler address to your payload buffer address with `!address` or `!vprot` to confirm it is within your controlled allocation.

---

## 6. CONTEXT Structure Inspection

When an exception occurs, the OS saves register state in a `CONTEXT` structure. The third argument to a vectored or structured exception handler is `PCONTEXT`.

### Structure Dimensions

On x86, `sizeof(CONTEXT) == 0x2CC`. On x64, `sizeof(CONTEXT) == 0x4D0`.

### Display Type Layout (x86)

```
0:000> dt ntdll!_CONTEXT
   +0x000 ContextFlags : Uint4B
   +0x004 Dr0          : Uint4B   ← hardware breakpoint registers
   +0x008 Dr1          : Uint4B
   +0x00c Dr2          : Uint4B
   +0x010 Dr3          : Uint4B
   +0x014 Dr6          : Uint4B
   +0x018 Dr7          : Uint4B
   +0x01c FloatSave    : _FLOATING_SAVE_AREA
   +0x08c SegGs        : Uint4B
   +0x090 SegFs        : Uint4B
   +0x094 SegEs        : Uint4B
   +0x098 SegDs        : Uint4B
   +0x09c Edi          : Uint4B
   +0x0a0 Esi          : Uint4B
   +0x0a4 Ebx          : Uint4B
   +0x0a8 Esp          : Uint4B
   +0x0ac Ebp          : Uint4B
   +0x0b0 Eip          : Uint4B   ← instruction pointer at exception
   +0x0b4 SegCs        : Uint4B
   +0x0b8 EFlags       : Uint4B
   +0x0bc Esp          : Uint4B   (old ESP)
   +0x0c0 SegSs        : Uint4B
   +0x0c4 ExtendedRegisters : [512] UChar
```

### Inspecting CONTEXT at an Exception Handler Breakpoint

In a classic SEH exploit, the `EXCEPTION_HANDLER` function signature is:
```c
EXCEPTION_DISPOSITION Handler(
    PEXCEPTION_RECORD ExcRecord,   // [esp+4]
    PVOID EstablisherFrame,        // [esp+8]
    PCONTEXT ContextRecord,        // [esp+C]  ← this is what we inspect
    PVOID DispatcherContext        // [esp+10]
);
```

When BP fires on the handler:
```
0:000> dd esp L5
0019f3a0  0019f3c4 0019f39c 0019f9d0 0019f9f0 ...
           ExcRecord  Frame    ContextRecord ← at esp+0xC = 0019f9d0
```

```
0:000> dt ntdll!_CONTEXT 0019f9d0
   +0x000 ContextFlags : 0x10007
   +0x09c Edi  : 0x00000000
   +0x0a0 Esi  : 0x00000000
   +0x0a4 Ebx  : 0x7ffd5000    ← PEB base (often)
   +0x0a8 Esp  : 0x0019fba0
   +0x0ac Ebp  : 0x0019fc00
   +0x0b0 Eip  : 0x41414141    ← the overwritten EIP that caused the AV
   +0x0b8 EFlags : 0x10246
```

**OSED use:** Modify `ContextRecord.Eip` to redirect execution:
```
0:000> ed 0019f9d0+0xb0 <new_eip>
```

---

## 7. Heap Inspection

### Quick Heap Overview

```
0:000> !heap
Index   Address  Name      Debugging options enabled
  1:   00270000 (default heap)
  2:   00350000
  3:   004a0000
```

### Detailed Heap Info

```
0:000> !heap -a 00270000
Index:   1
VAD Tag: HEAP
HEAP at 00270000
  flags:           0x40000062   ← includes HEAP_TAIL_CHECKING | HEAP_FREE_CHECKING
  forceflags:      0x40000060   ← debugger sets these (anti-debug indicator)
  granularity:     8 bytes (0x8)
  reservation:     0x00100000
  committed:       0x00006000
  allocated:       0x000032c8
  free:            0x000017c8
  segments:        1
    00270000: Base=00270000 (size 0x100000), ...
  UCRs:    1
  Freelists: ...
```

### Display Heap Structure

```
0:000> dt ntdll!_HEAP 00270000
   +0x000 Entry                    : _HEAP_ENTRY
   +0x008 SegmentSignature         : 0xffeeffee
   +0x00c SegmentFlags             : 0
   +0x010 SegmentListEntry         : _LIST_ENTRY
   +0x018 Heap                     : 0x00270000 _HEAP
   +0x01c BaseAddress              : 0x00270000 Void
   +0x020 NumberOfPages            : 0x100
   +0x024 FirstEntry               : 0x00270588 _HEAP_ENTRY
   +0x028 LastValidEntry           : 0x00370000 _HEAP_ENTRY
   +0x02c NumberOfUnCommittedPages : 0xfa
   +0x030 NumberOfUnCommittedRanges: 1
   +0x034 SegmentAllocatorBackTraceIndex : 0
   +0x036 Reserved                 : 0
   +0x038 UCRSegmentList           : _LIST_ENTRY
   +0x040 Flags                    : 0x40000062   ← ForceFlags is nearby
   +0x044 ForceFlags               : 0x40000060   ← PEB+0x44 (XP), see §14
   +0x048 CompatibilityFlags       : 0x20000000
   +0x04c EncodeFlagMask           : 0x100000
   +0x050 Encoding                 : _HEAP_ENTRY
   +0x058 Interceptor              : 0
   +0x05c VirtualMemoryThreshold  : 0xfe00
   +0x060 Signature                : 0xeeffeeff
   ...
```

### Finding the ForceFlags Field by Windows Version

| Windows Version | `_HEAP.Flags` offset | `_HEAP.ForceFlags` offset |
|-----------------|---------------------|--------------------------|
| Windows XP | `+0x040` | `+0x044` |
| Windows Vista | `+0x040` | `+0x044` |
| Windows 7 (x86) | `+0x040` | `+0x044` |
| Windows 7 (x64) | `+0x070` | `+0x074` |
| Windows 10 (x86) | `+0x040` | `+0x044` |
| Windows 10 (x64) | `+0x070` | `+0x074` |

### Heap Chunk Inspection with `!heap -p`

```
0:000> !heap -p -a 002716b0
    address 002716b0 found in
    _HEAP @ 270000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        002716a8 0006 0000  [00]   002716b0    00028 - (busy)
                 Trace: ...
```

---

## 8. TEB Inspection

The Thread Environment Block (TEB) is accessible at `FS:[0]` (x86) or `GS:[0]` (x64) and contains per-thread state.

### Key Field Offsets

| Field | x86 Offset | x64 Offset | Notes |
|-------|-----------|-----------|-------|
| `NtTib.ExceptionList` | `+0x000` | `+0x000` | Head of SEH chain (x86 only active) |
| `NtTib.StackBase` | `+0x004` | `+0x008` | Top of thread stack (high addr) |
| `NtTib.StackLimit` | `+0x008` | `+0x010` | Bottom guard page |
| `NtTib.Self` | `+0x018` | `+0x028` | Self-pointer to TEB |
| `EnvironmentPointer` | `+0x01C` | `+0x038` | Usually NULL |
| `ClientId.UniqueProcess` | `+0x020` | `+0x040` | PID |
| `ClientId.UniqueThread` | `+0x024` | `+0x048` | TID |
| `ActiveRpcHandle` | `+0x028` | `+0x050` | |
| `ThreadLocalStoragePointer` | `+0x02C` | `+0x058` | TLS array |
| `ProcessEnvironmentBlock` | `+0x030` | `+0x060` | PEB pointer |
| `LastErrorValue` | `+0x034` | `+0x068` | `GetLastError()` |
| `TlsSlots[64]` | `+0x0E10` | `+0x1480` | TLS slot array |

### Full dt Session (x86)

```
0:000> dt ntdll!_TEB @$teb
   +0x000 NtTib : _NT_TIB
      +0x000 ExceptionList  : 0x0019ffa4 _EXCEPTION_REGISTRATION_RECORD
      +0x004 StackBase      : 0x00200000 Void   ← stack top
      +0x008 StackLimit     : 0x0019e000 Void   ← stack bottom (guard page)
      +0x00c SubSystemTib   : (null)
      +0x010 FiberData      : 0x00001e00 Void
      +0x014 ArbitraryUserPointer : (null)
      +0x018 Self           : 0x0019f000 _NT_TIB  ← self-reference
   +0x01c EnvironmentPointer : (null)
   +0x020 ClientId :
      +0x000 UniqueProcess  : 0x00000f34 Void   ← PID = 0xf34
      +0x004 UniqueThread   : 0x00000f38 Void   ← TID = 0xf38
   +0x02c ThreadLocalStoragePointer : (null)
   +0x030 ProcessEnvironmentBlock : 0x7ffd5000 _PEB   ← PEB pointer
   +0x034 LastErrorValue  : 0
   +0x038 CountOfOwnedCriticalSections : 0
   ...
```

### Reading the PEB from the TEB

```
0:000> dd @$teb+0x30 L1
0019f030  7ffd5000     ← PEB address, same as @$peb
```

### Stack Range Confirmation

```
0:000> dd @$teb+4 L2
0019f004  00200000 0019e000
```

`ESP` must be between `0019e000` and `00200000`. Useful for verifying stack pivot landing.

---

## 9. Memory Display Commands

Choosing the right display command avoids misinterpreting memory.

### Command Reference

| Command | Unit | Best Used For |
|---------|------|---------------|
| `db addr` | Byte (hex + ASCII) | Shellcode bytes, string content |
| `dw addr` | WORD (16-bit) | Unicode characters, flags |
| `dd addr` | DWORD (32-bit) | Pointers (x86), DWORD fields |
| `dq addr` | QWORD (64-bit) | Pointers (x64), 64-bit values |
| `dp addr` | Pointer-sized | Auto-selects DWORD/QWORD by target |
| `da addr` | ASCII string | Null-terminated ASCII |
| `du addr` | Unicode string | Null-terminated UTF-16 |
| `dW addr` | WORD hex | 16-bit values with spacing |
| `dc addr` | DWORD + ASCII | Combines dd and db in one view |

### Count Modifier `L`

Append `Ln` to display `n` units:
```
0:000> dd esp L8      ← first 8 DWORDs on the stack
0:000> db 00410000 L40  ← 64 bytes at that address
```

### Practical Examples

**View shellcode bytes:**
```
0:000> db 01a00000 L20
01a00000  fc 48 83 e4 f0 e8 c8 00-00 00 41 51 41 50 52 51  .H........AQAPRQ
01a00010  56 48 31 d2 65 48 8b 52-00 48 8b 52 18 48 8b 52  VH1.eH.R.H.R.H.R
```

**View x86 pointer table (IAT, GOT, vtable):**
```
0:000> dd 75a80000+3c L1       ← e_lfanew
75a8003c  00000100
0:000> dd 75a80100 L5          ← NT headers start
75a80100  00004550 0000014c 4ce7b96e 00000000 ...
```

**Display a UNICODE_STRING buffer:**
```
0:000> du 00271720
00271720  "kernel32.dll"
```

**View x64 stack:**
```
0:000> dq rsp L10
000000c0`e01af9b0  00007ffa`d87c4d91 00007ffa`d8a21020
000000c0`e01af9c0  000001e2`3c271a00 000000c0`e01af9f0
...
```

### `dc` — Combined DWORD/ASCII View

```
0:000> dc 0019f000 L10
0019f000  0019ffa4 00200000 0019e000 00001e00  .....  .........
0019f010  00000000 0019f018 00000000 00000f34  ........4.......
```

---

## 10. `s` (Search) Command

Search is critical for locating shellcode anchors, PE magic values, strings, and injected data.

### Syntax

```
s [options] StartAddress EndAddress|L<length> Pattern
```

### Search Modes

| Flag | Type | Description |
|------|------|-------------|
| `-b` | Byte pattern | `s -b start end aa bb cc` |
| `-w` | WORD | 16-bit value |
| `-d` | DWORD | `s -d start end 0x41414141` |
| `-q` | QWORD | 64-bit value |
| `-a` | ASCII string | `s -a start end "kernel32"` |
| `-u` | Unicode string | `s -u start end "kernel32"` |

### Finding a PE Header (`MZ` = `4d 5a`)

```
0:000> s -b 75a00000 75c00000 4d 5a
75a80000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
```

Found kernel32.dll's MZ header at `75a80000`. This matches `DllBase` from the LDR entry.

### Finding a Specific DWORD

```
0:000> s -d 0019e000 00200000 41414141
0019fa20  41414141    ← overflow filler found on stack
0019fa24  41414141
0019fa28  41414141
```

### Finding a String in Process Memory

```
0:000> s -a 00400000 00500000 "This program"
00402010  "This program cannot be run in DOS mode"
```

```
0:000> s -u 00400000 00500000 "kernel32"
0040a1c8  6b 00 65 00 72 00 6e 00-65 00 6c 00 33 00 32 00  k.e.r.n.e.l.3.2.
```

### Finding a Return Address or Code Pattern

Find a `jmp esp` (`ff e4`) for classic shellcode redirection:
```
0:000> s -b 75a80000 75b70000 ff e4
75a8b98c  ff e4 ...   ← JMP ESP gadget in kernel32.dll
```

Find a `pop pop ret` sequence for SEH exploits:
```
0:000> s -b 00400000 00410000 5b 5b c3
00401a80  5b 5b c3    ← pop ebx; pop ebx; ret
```

### Searching the Entire User-Mode Address Space

```
0:000> s -a 0 80000000 "password"
```

**Warning:** This can be slow on a live process. Prefer narrow ranges when possible.

### Searching with Wildcards (via Script)

WinDbg does not support pattern wildcards in `s`, but you can loop:
```
0:000> .for (r $t0=0; $t0 < 10; r $t0=$t0+1) { s -b 0019f000 0019ffff 90 90 90 90 }
```

---

## 11. Inspecting PE Headers in Memory

Manual PE header navigation is essential when symbols are absent or when verifying the export table during shellcode write/debug.

### Step 1: Confirm MZ Header

```
0:000> db 75a80000 L2
75a80000  4d 5a     ← 'MZ'
```

### Step 2: Read e_lfanew (Offset to PE Signature)

`e_lfanew` is at offset `+0x3C` in the DOS header:
```
0:000> dd 75a80000+3c L1
75a8003c  00000100    ← PE signature is at 75a80000 + 0x100 = 75a80100
```

### Step 3: Verify PE Signature

```
0:000> db 75a80100 L4
75a80100  50 45 00 00    ← 'PE\0\0'
```

### Step 4: COFF File Header (immediately after PE signature)

```
0:000> dt ntdll!_IMAGE_FILE_HEADER 75a80104
   +0x000 Machine              : 0x14c      ← IMAGE_FILE_MACHINE_I386 (x86)
   +0x002 NumberOfSections     : 0x4
   +0x004 TimeDateStamp        : 0x4ce7b96e
   +0x008 PointerToSymbolTable : 0
   +0x00c NumberOfSymbols      : 0
   +0x010 SizeOfOptionalHeader : 0xe0
   +0x012 Characteristics      : 0x2102
```

### Step 5: Optional Header + DataDirectory

Optional Header starts at `PE_sig_addr + 4 (PE sig) + 0x14 (COFF header) = +0x18` from PE sig:
```
0:000> dt ntdll!_IMAGE_OPTIONAL_HEADER 75a80118
   +0x000 Magic                  : 0x10b    ← PE32 (0x20b = PE32+)
   +0x010 AddressOfEntryPoint    : 0x9c9e0  ← RVA to entry point
   +0x01c ImageBase              : 0x75a80000
   +0x038 NumberOfRvaAndSizes    : 0x10
   +0x03c DataDirectory          : [16] _IMAGE_DATA_DIRECTORY
```

### Step 6: Export Directory RVA

DataDirectory[0] is the export directory:
```
0:000> dt ntdll!_IMAGE_DATA_DIRECTORY 75a80118+3c
   +0x000 VirtualAddress : 0x7e2e0    ← RVA of export dir
   +0x004 Size           : 0x73a44
```

Export directory VA = `75a80000 + 0x7e2e0 = 75afe2e0`

### Step 7: Export Directory

```
0:000> dt ntdll!_IMAGE_EXPORT_DIRECTORY 75afe2e0
   +0x000 Characteristics       : 0
   +0x004 TimeDateStamp         : 0x4ce7b96e
   +0x008 MajorVersion          : 0
   +0x00a MinorVersion          : 0
   +0x00c Name                  : 0x7f5c0     ← RVA to module name string
   +0x010 Base                  : 1
   +0x014 NumberOfFunctions     : 0x3e5        ← 997 exported functions
   +0x018 NumberOfNames         : 0x3e5
   +0x01c AddressOfFunctions    : 0x7e4e4      ← RVA to EAT (function pointer array)
   +0x020 AddressOfNames        : 0x7f0b0      ← RVA to name pointer array
   +0x024 AddressOfNameOrdinals : 0x7fc7c      ← RVA to ordinal array
```

### Step 8: Resolve a Function by Name

Look up `VirtualAlloc` in the Export Name Table:

```
0:000> da 75a80000+7f0b0
75aff0b0  pointer array of RVAs to names ...

0:000> dd 75a80000+7f0b0 L5
75aff0b0  00083af0 00083afc 00083b06 00083b12 00083b1f

0:000> da 75a80000+83af0
75b03af0  "AcquireSRWLockExclusive"
0:000> da 75a80000+83afc
75b03afc  "AcquireSRWLockShared"
```

In practice, shellcode's `find_function` loops through all name RVAs, hashing each name and comparing to the target hash. We trace this in `Shellcode_Debugging.md`.

### Step 9: Module Name String

```
0:000> da 75a80000+7f5c0
75aff5c0  "KERNEL32.DLL"   ← module name as stored in the PE
```

---

## 12. `ln` (List Nearest)

`ln` resolves an address to the nearest symbol. Essential when EIP/RIP lands somewhere unexpected after an overflow.

### Basic Usage

```
0:000> ln eip
Browse module
Use `lm` to see all symbols
(75b1c9e0)   kernel32!BaseThreadInitThunk+0x0   |   (75b1ca40)   kernel32!BaseThreadInitThunk
Exact matches:
    kernel32!BaseThreadInitThunk = <no type information>
```

### EIP in Unknown Territory

After a controlled crash:
```
0:000> g
(f34.f38): Access violation ...
eip=41414141
...
0:000> ln eip
                                         ← no symbol found; raw address
0:000> !address eip
Usage:                  Free
BaseAddress:            40000000
EndAddress:             50000000
RegionSize:             10000000
State:                  00010000  MEM_FREE
```

**Analysis:** EIP landed in free address space. The offset from the start of your buffer is likely wrong, or bad characters caused premature termination.

### Useful ln Patterns

```
0:000> ln esp                    ← where is the stack pointer?
0:000> ln poi(esp)               ← what does the return address point to?
0:000> ln 75a8b98c               ← identify a gadget address
(75a8b98c)   kernel32+0xb98c     ← no symbol, but at kernel32+offset
```

### After a Successful `find_function`

```
0:000> ln eax
(75ac2340)   kernel32!VirtualAlloc   ← confirmed correct resolution
```

---

## 13. `x` (Examine Symbols)

`x` searches the symbol table for names matching a pattern. It is the fastest way to find function addresses without looking them up externally.

### Basic Pattern Matching

```
0:000> x kernel32!Virtual*
75ac2340 kernel32!VirtualAlloc
75ac2420 kernel32!VirtualAllocEx
75ac24a0 kernel32!VirtualAllocExNuma
75ad1020 kernel32!VirtualFree
75ad1090 kernel32!VirtualFreeEx
75ac3120 kernel32!VirtualLock
75ac3180 kernel32!VirtualProtect
75ac3200 kernel32!VirtualProtectEx
75ac32a0 kernel32!VirtualQuery
75ac3340 kernel32!VirtualQueryEx
75ac3400 kernel32!VirtualUnlock
```

```
0:000> x ntdll!Nt*
77c4a890 ntdll!NtAllocateVirtualMemory
77c4a990 ntdll!NtProtectVirtualMemory
77c4ab00 ntdll!NtCreateThreadEx
77c4ad10 ntdll!NtOpenProcess
...
```

### Sort by Address

```
0:000> x /a kernel32!*
75a80000 kernel32!_ImageBase
75a80010 kernel32!_IMPORT_DESCRIPTOR_api-ms-win-core-...
...
75b70000 kernel32!<last symbol>
```

### Sort by Name

```
0:000> x /D kernel32!Create*
75ab4200 kernel32!CreateConsoleScreenBuffer
75ab5320 kernel32!CreateDirectoryA
75ab5390 kernel32!CreateDirectoryExA
...
75adf5b0 kernel32!CreateThread
75ae1420 kernel32!CreateToolhelp32Snapshot
```

### Find Exact Symbol Address

```
0:000> x kernel32!WinExec
75adf120 kernel32!WinExec
```

Use this to verify hardcoded addresses in shellcode match the live process's load addresses (relevant if ASLR is off and you hard-coded the address).

### Cross-Reference with `ln`

```
0:000> x kernel32!LoadLibraryA
75adf450 kernel32!LoadLibraryA

0:000> ln 75adf450
(75adf450)   kernel32!LoadLibraryA
```

---

## 14. Anti-Debug Detection Structure Fields

Debugger-presence detection often checks three main indicators. Each can be cleared directly in WinDbg.

### 14.1 PEB.BeingDebugged (PEB+0x002)

Set to `0x01` when a debugger is attached. Classic `IsDebuggerPresent` check.

**Detect:**
```
0:000> db @$peb+2 L1
7ffd5002  01                      ← debugger present!
```

**Bypass (clear it):**
```
0:000> eb @$peb+2 0
0:000> db @$peb+2 L1
7ffd5002  00                      ← cleared
```

### 14.2 PEB.NtGlobalFlag (PEB+0x068 on x86, PEB+0x0BC on x64)

When a process is created under a debugger, `NtGlobalFlag` has several bits set that alter heap behavior. Normal value: `0x00`. Debugger value: typically `0x70` (= `FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`).

**Detect (x86):**
```
0:000> dd @$peb+0x68 L1
7ffd5068  00000070    ← heap debug flags set
```

**Bypass (x86):**
```
0:000> ed @$peb+0x68 0
0:000> dd @$peb+0x68 L1
7ffd5068  00000000    ← cleared
```

**Detect (x64):**
```
0:000> dd @$peb+0xbc L1
... 00000070
```

**Bypass (x64):**
```
0:000> ed @$peb+0xbc 0
```

### 14.3 Heap ForceFlags

The default process heap's `ForceFlags` field is set to values that indicate the heap is being debugged. Normal value: `0x00`. Debugger value: `0x40000060` or `0x70`.

**Locate the default heap:**
```
0:000> dd @$peb+0x18 L1
7ffd5018  00270000    ← ProcessHeap pointer
```

**Check ForceFlags on x86 (offset +0x044):**
```
0:000> dd 00270000+0x44 L1
00270044  40000060    ← debugger-set flags
```

**Bypass (x86):**
```
0:000> ed 00270000+0x44 0
0:000> ed 00270000+0x40 2    ← also clear Flags, leave only HEAP_GROWABLE
```

**Check ForceFlags on x64 (offset +0x074):**
```
0:000> dd <heap_base>+0x74 L1
```

**Bypass (x64):**
```
0:000> ed <heap_base>+0x74 0
0:000> ed <heap_base>+0x70 2
```

### 14.4 NtQueryInformationProcess / CheckRemoteDebuggerPresent

These API calls internally read `PEB.BeingDebugged` or use `NtQueryInformationProcess(ProcessDebugPort)`. After clearing `BeingDebugged`, the API-level check still returns a debug port. To fully bypass:

```
0:000> bp ntdll!NtQueryInformationProcess "r eax=0; g"
```

This forces the syscall to return `STATUS_SUCCESS` with a zeroed result.

### 14.5 Heap Magic Signature Check

Some advanced anti-debug checks verify the heap segment signature. The `_HEAP.SegmentSignature` should be `0xffeeffee` in all cases, but some checks additionally test that the heap encoding cookie matches. These are highly version-specific; inspect the binary's anti-debug routine directly rather than patching blindly.

### Complete Anti-Debug Bypass Session

```
0:000> .sympath+ srv*c:\symbols*https://msdl.microsoft.com/download/symbols
0:000> .reload /f

; Step 1: Clear BeingDebugged
0:000> eb @$peb+2 0

; Step 2: Clear NtGlobalFlag (x86)
0:000> ed @$peb+0x68 0

; Step 3: Clear heap debug flags
0:000> dd @$peb+0x18 L1
7ffd5018  00270000
0:000> ed 00270000+0x44 0
0:000> ed 00270000+0x40 2

; Step 4: Verify all cleared
0:000> db @$peb+2 L1
7ffd5002  00
0:000> dd @$peb+0x68 L1
7ffd5068  00000000
0:000> dd 00270000+0x44 L1
00270044  00000000

; Now run the anti-debug check in the target and it should pass
0:000> g
```

**Analyst note:** If the target uses `rdtsc` timing or hardware-assisted detection (e.g., checking exception counts), these structural patches are not sufficient. You would need to set conditional BPs on the detection routines themselves.

---

## Appendix: Quick Offset Reference Card

### x86 PEB Critical Offsets

```
PEB+0x000  InheritedAddressSpace    BYTE
PEB+0x002  BeingDebugged            BYTE   ← anti-debug
PEB+0x008  ImageBaseAddress         DWORD
PEB+0x00C  Ldr                      DWORD  ← -> PEB_LDR_DATA
PEB+0x018  ProcessHeap              DWORD  ← -> _HEAP
PEB+0x068  NtGlobalFlag             DWORD  ← anti-debug
```

### x86 PEB_LDR_DATA Critical Offsets

```
Ldr+0x00C  InLoadOrderModuleList.Flink        DWORD
Ldr+0x014  InMemoryOrderModuleList.Flink      DWORD
Ldr+0x01C  InInitializationOrderModuleList.Flink  DWORD  ← shellcode uses this
```

### x86 LDR_DATA_TABLE_ENTRY Critical Offsets (from InitOrder link)

```
Entry-0x08  DllBase          DWORD  ← subtract 0x08 from InitOrder link for struct base
Entry+0x10  InInitOrderLinks._LIST_ENTRY
Entry+0x18  DllBase          DWORD  ← absolute, from struct base
Entry+0x24  FullDllName      _UNICODE_STRING (Length WORD, MaxLen WORD, Buffer DWORD)
Entry+0x2C  BaseDllName      _UNICODE_STRING
```

### x86 PE Header Navigation

```
Module+0x3C              e_lfanew       → offset to PE signature
Module+e_lfanew+0x00     PE signature   "PE\0\0"
Module+e_lfanew+0x04     COFF header
Module+e_lfanew+0x18     Optional header
Module+e_lfanew+0x18+0x60  DataDirectory[0] (export dir RVA + size)
Module+ExportDirRVA+0x14  NumberOfFunctions
Module+ExportDirRVA+0x18  NumberOfNames
Module+ExportDirRVA+0x1C  AddressOfFunctions (EAT)
Module+ExportDirRVA+0x20  AddressOfNames
Module+ExportDirRVA+0x24  AddressOfNameOrdinals
```

---

*Reference compiled for OSED preparation and Windows exploit development. All addresses shown are representative; actual values vary by OS version, ASLR state, and patch level. Always verify with live `dt`/`dd` output in your debug session.*
