# 15. DEP and Page Protections

## Executable vs. Non-Executable Memory

DEP (Data Execution Prevention) / NX (No-eXecute) marks memory pages as
non-executable. Code on the stack or heap will fault when the CPU attempts to
fetch instructions from those pages.

## Why Stack Shellcode Faults

Without DEP: overflow the return address to point at shellcode on the stack;
the CPU executes it.

With DEP: the stack page is marked NX. When EIP points into the stack, the
CPU raises an access violation on the next instruction fetch, not on data
access.

## VirtualProtect

```c
BOOL VirtualProtect(
    LPVOID lpAddress,       // address in the region to change
    SIZE_T dwSize,          // size of the region
    DWORD  flNewProtect,    // new protection constant
    PDWORD lpflOldProtect   // pointer to DWORD receiving old protection
);
```

Changes the protection on committed pages in the calling process. Used in DEP
bypass to mark the shellcode's page as executable.

**lpflOldProtect must point to writable memory.** VirtualProtect writes the
old protection value to this address. If the pointer is invalid, the call
fails. A common writable location is any address in a writable data section
(e.g., `.data` or a stack address).

VirtualProtect operates on page granularity internally (4 KB pages), but the
caller does not need to provide a page-aligned lpAddress. The API rounds down
to the page boundary containing lpAddress and rounds up to cover all pages
spanned by the range `[lpAddress, lpAddress + dwSize)`.

## VirtualAlloc

```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,       // desired address (or NULL for auto)
    SIZE_T dwSize,          // size of the region
    DWORD  flAllocationType,// allocation type
    DWORD  flProtect        // protection
);
```

Allocates new memory with the specified protection. Can be used to allocate
executable memory and copy shellcode into it.

## Protection Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| PAGE_EXECUTE_READWRITE | 0x40 | Read, write, and execute |
| PAGE_EXECUTE_READ | 0x20 | Read and execute |
| PAGE_READWRITE | 0x04 | Read and write (no execute) |
| PAGE_READONLY | 0x02 | Read only |
| PAGE_NOACCESS | 0x01 | No access |

## Allocation Type Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| MEM_COMMIT | 0x1000 | Commit pages (back with physical storage) |
| MEM_RESERVE | 0x2000 | Reserve address space without committing |
| MEM_COMMIT \| MEM_RESERVE | 0x3000 | Reserve and commit in one call |

## WinDbg Verification

```
0:000> !vprot <address>
BaseAddress:       00c0f000
AllocationBase:    00b70000
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE
```

Before the bypass: Protect = 0x04 (PAGE_READWRITE).
After VirtualProtect: Protect = 0x40 (PAGE_EXECUTE_READWRITE).
