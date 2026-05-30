# PEB — Process Environment Block (`_PEB`)

## Purpose

The Process Environment Block is a per-process data structure maintained by the Windows kernel and exposed in user-mode address space. Every process has exactly one PEB. It serves as the central user-mode descriptor of a process: it records what executable image was loaded, which DLLs are mapped, what the process heap is, whether a debugger is attached, the current working directory, environment variables, and dozens of loader and runtime state fields.

The kernel creates the PEB during process initialization, before the first thread's entry point runs. The memory-management subsystem (`MmCreatePeb`) allocates the PEB from the process's virtual address space at a fixed but randomized base (ASLR applies to the PEB itself on Vista+). On x86 Windows the PEB is placed in the low 2 GB of address space; on x64 it is similarly in user space but typically at a higher address.

**Why the OS needs it:** Rather than making a syscall every time user-mode code needs to know the image base, the module list, or the process heap, all of this information is cached in a single structure that user-mode can read without a privilege boundary crossing. `ntdll.dll` uses the PEB constantly — for heap allocation, for the loader's module list, for locale data, for the critical section that serializes the loader.

**Where it lives:** The PEB address is stored at a well-known offset inside the Thread Environment Block (TEB). On x86, `FS:[0x30]` is a pointer to the PEB. On x64, `GS:[0x60]` holds the same pointer. The pointer itself is also stored in the kernel-mode `EPROCESS` structure at `EPROCESS.Peb`, but that is inaccessible from user mode.

---

## How to Reach the PEB from Shellcode

### x86 — `FS` Segment Register

```asm
; x86: retrieve PEB pointer
xor   ecx, ecx          ; ECX = 0 (avoids null-byte in offset if encoding matters)
mov   eax, fs:[ecx+30h] ; EAX = PEB pointer
```

**Why `FS` and why offset `0x30`:**

The `FS` segment register on x86 Windows is set by the kernel to point at the current thread's TEB (Thread Environment Block) every time a context switch occurs. The kernel stores the TEB base address in the FS segment descriptor in the GDT (Global Descriptor Table). Each processor core has its own GDT, and each thread's descriptor is updated by the scheduler so that `FS` always resolves to *this* thread's TEB, regardless of which core is running.

The TEB starts with an `NT_TIB` (Native Thread Information Block) overlay, and at offset `0x18` within `NT_TIB` is the `Self` field — a pointer back to the TEB itself. At offset `0x30` within the TEB is the `ProcessEnvironmentBlock` field — a pointer to the PEB shared across all threads in the process.

So `FS:[0x30]` dereferences: (segment base of FS = TEB base) + 0x30 bytes = `TEB.ProcessEnvironmentBlock` = the PEB address.

### x64 — `GS` Segment Register

```asm
; x64: retrieve PEB pointer
mov   rax, gs:[60h]     ; RAX = PEB pointer (64-bit address)
```

**Why the switch from `FS` to `GS`:**

On x64 Windows, Microsoft reassigned segment register conventions. `GS` now points to the TEB (the `KPCR`/`KPRCB` in kernel mode uses `GS` differently — it only points to the TEB in user mode). The PEB pointer moved from TEB offset `0x30` (x86) to TEB offset `0x60` (x64) because all pointer-sized fields doubled in size. The TEB `Self` field is now at `0x30` on x64, and `ProcessEnvironmentBlock` is at `0x60`.

The `FS` register on x64 is still present but is used differently (thread-local storage in some runtimes, or unused in Windows kernel context). The OS sets up `GS` for the TEB at thread creation via the `SWAPGS` instruction paradigm.

---

## Exploit Relevance

The PEB is the **entry point for position-independent shellcode** that needs to resolve API addresses at runtime. The canonical technique is:

1. Read `FS:[0x30]` to get the PEB address.
2. Read `PEB.Ldr` (+0x00C x86) to get a pointer to `PEB_LDR_DATA`.
3. Walk `PEB_LDR_DATA.InInitializationOrderModuleList` to find `kernel32.dll` (or `ntdll.dll`).
4. Read `LDR_DATA_TABLE_ENTRY.DllBase` to get the module's image base.
5. Parse the PE export directory at that base to find function addresses by name or hash.

Without this walk, shellcode cannot call `LoadLibrary`, `GetProcAddress`, or any other API, because it does not know where the executable was loaded (ASLR). The PEB walk is what makes shellcode relocatable.

Secondary uses:
- **Anti-debugging:** `PEB.BeingDebugged` and `PEB.NtGlobalFlag` reveal debugger presence.
- **Heap access:** `PEB.ProcessHeap` gives a valid heap handle for `HeapAlloc` calls in stager shellcode.
- **Version checks:** `PEB.OSMajorVersion` / `PEB.OSMinorVersion` allow shellcode to branch on OS version.
- **Image base:** `PEB.ImageBaseAddress` gives the host process's loaded image base for in-memory patching.

---

## Full Structure Layout

All offsets are from the start of the `_PEB` structure. Pointer fields are 4 bytes wide on x86 and 8 bytes on x64. Non-pointer fields retain their sizes. Padding is inserted by the compiler to maintain natural alignment.

| Field Name | Type | x86 Offset (hex/dec) | x64 Offset (hex/dec) | Purpose |
|---|---|---|---|---|
| `InheritedAddressSpace` | BOOLEAN | 0x000 / 0 | 0x000 / 0 | TRUE if address space was inherited from parent |
| `ReadImageFileExecOptions` | BOOLEAN | 0x001 / 1 | 0x001 / 1 | Read image execution options from registry |
| `BeingDebugged` | BOOLEAN | 0x002 / 2 | 0x002 / 2 | Set to 1 by debuggers; anti-debug check target |
| `BitField` / `NtGlobalFlag2` | UCHAR/flags | 0x003 / 3 | 0x003 / 3 | Packed flags; `SpareBits` or `ImageUsesLargePages` etc. |
| *(padding on x64)* | — | — | 0x004–0x007 | 4 bytes alignment padding before first pointer |
| `Mutant` | HANDLE | 0x004 / 4 | 0x008 / 8 | Process mutex handle (usually -1 = no mutex) |
| `ImageBaseAddress` | PVOID | 0x008 / 8 | 0x010 / 16 | Base address of the main executable image |
| `Ldr` | `*PEB_LDR_DATA` | 0x00C / 12 | 0x018 / 24 | Pointer to loader data (module list heads) |
| `ProcessParameters` | `*RTL_USER_PROCESS_PARAMETERS` | 0x010 / 16 | 0x020 / 32 | Command line, image path, environment, handles |
| `SubSystemData` | PVOID | 0x014 / 20 | 0x030 / 48 | Subsystem-specific data pointer |
| `ProcessHeap` | PVOID | 0x018 / 24 | 0x038 / 56 | Default process heap handle |
| `FastPebLock` | `*RTL_CRITICAL_SECTION` | 0x01C / 28 | 0x040 / 64 | Critical section protecting PEB modifications |
| `AtlThunkSListPtr` / `SparePtr1` | PVOID | 0x020 / 32 | 0x050 / 80 | ATL thunk list or spare pointer |
| `IFEOKey` / `SparePtr2` | PVOID | 0x024 / 36 | 0x058 / 88 | Image file execution options key handle |
| `CrossProcessFlags` | ULONG | 0x028 / 40 | 0x060 / 96 | Packed cross-process state flags |
| *(padding x64)* | — | — | 0x064–0x067 | 4 bytes for pointer alignment |
| `KernelCallbackTable` | PVOID | 0x02C / 44 | 0x068 / 104 | Table of kernel→user callback functions |
| `SystemReserved[0]` | ULONG | 0x030 / 48 | 0x070 / 112 | Reserved |
| `AtlThunkSListPtr32` | ULONG | 0x034 / 52 | 0x074 / 116 | WOW64 ATL thunk list (32-bit pointer stored as ULONG) |
| `ApiSetMap` | PVOID | 0x038 / 56 | 0x078 / 120 | API set schema map (api-ms-win-* redirection) |
| `TlsExpansionCounter` | ULONG | 0x03C / 60 | 0x080 / 128 | Count of expanded TLS slots |
| *(padding x64)* | — | — | 0x084–0x087 | 4 bytes for pointer alignment |
| `TlsBitmap` | PVOID | 0x040 / 64 | 0x088 / 136 | Bitmap of used TLS slots |
| `TlsBitmapBits[2]` | ULONG[2] | 0x044 / 68 | 0x090 / 144 | 64 TLS slot bits |
| `ReadOnlySharedMemoryBase` | PVOID | 0x04C / 76 | 0x098 / 152 | Shared read-only data segment |
| `SharedData` / `HotpatchInformation` | PVOID | 0x050 / 80 | 0x0A0 / 160 | Hotpatch table or shared session data |
| `ReadOnlyStaticServerData` | PVOID* | 0x054 / 84 | 0x0A8 / 168 | Pointer to array of pointers |
| `AnsiCodePageData` | PVOID | 0x058 / 88 | 0x0B0 / 176 | Pointer to ANSI code page table |
| `OemCodePageData` | PVOID | 0x05C / 92 | 0x0B8 / 184 | Pointer to OEM code page table |
| `UnicodeCaseTableData` | PVOID | 0x060 / 96 | 0x0C0 / 192 | Pointer to Unicode case-fold table |
| `NumberOfProcessors` | ULONG | 0x064 / 100 | 0x0C8 / 200 | Logical processor count |
| `NtGlobalFlag` | ULONG | 0x068 / 104 | 0x0BC / 188 | Global debug/heap flags; 0x70 under debugger |
| `CriticalSectionTimeout` | LARGE_INTEGER | 0x070 / 112 | 0x0D0 / 208 | Default CS timeout (-7 days) |
| `HeapSegmentReserve` | ULONG_PTR | 0x078 / 120 | 0x0E0 / 224 | Reserved virtual memory per heap segment |
| `HeapSegmentCommit` | ULONG_PTR | 0x07C / 124 | 0x0E8 / 232 | Committed memory per heap segment |
| `HeapDeCommitTotalFreeThreshold` | ULONG_PTR | 0x080 / 128 | 0x0F0 / 240 | Threshold before heap decommit |
| `HeapDeCommitFreeBlockThreshold` | ULONG_PTR | 0x084 / 132 | 0x0F8 / 248 | Free block size threshold for decommit |
| `NumberOfHeaps` | ULONG | 0x088 / 136 | 0x100 / 256 | Count of heaps in `ProcessHeaps` array |
| `MaximumNumberOfHeaps` | ULONG | 0x08C / 140 | 0x104 / 260 | Capacity of `ProcessHeaps` array |
| `ProcessHeaps` | PVOID* | 0x090 / 144 | 0x108 / 264 | Array of all heap handles |
| `GdiSharedHandleTable` | PVOID | 0x094 / 148 | 0x110 / 272 | GDI shared object handle table |
| `ProcessStarterHelper` | PVOID | 0x098 / 152 | 0x118 / 280 | Unused / reserved |
| `GdiDCAttributeList` | ULONG | 0x09C / 156 | 0x120 / 288 | GDI DC attribute count |
| *(padding x64)* | — | — | 0x124–0x127 | 4 bytes alignment |
| `LoaderLock` | `*RTL_CRITICAL_SECTION` | 0x0A0 / 160 | 0x128 / 296 | Loader critical section (serializes DLL loading) |
| `OSMajorVersion` | ULONG | 0x0A4 / 164 | 0x130 / 304 | e.g. 10 for Windows 10/11 |
| `OSMinorVersion` | ULONG | 0x0A8 / 168 | 0x134 / 308 | e.g. 0 for Windows 10 |
| `OSBuildNumber` | USHORT | 0x0AC / 172 | 0x138 / 312 | e.g. 19045 for 22H2 |
| `OSCSDVersion` | USHORT | 0x0AE / 174 | 0x13A / 314 | Service pack encoded as (Major<<8)|Minor |
| `OSPlatformId` | ULONG | 0x0B0 / 176 | 0x13C / 316 | VER_PLATFORM_WIN32_NT = 2 |
| `ImageSubsystem` | ULONG | 0x0B4 / 180 | 0x140 / 320 | Subsystem type from PE header |
| `ImageSubsystemMajorVersion` | ULONG | 0x0B8 / 184 | 0x144 / 324 | Required subsystem version |
| `ImageSubsystemMinorVersion` | ULONG | 0x0BC / 188 | 0x148 / 328 | Required subsystem minor version |
| *(padding x64)* | — | — | 0x14C–0x14F | 4 bytes alignment |
| `ActiveProcessAffinityMask` | ULONG_PTR | 0x0C0 / 192 | 0x150 / 336 | Processor affinity bitmask |
| `GdiHandleBuffer` | ULONG[34/60] | 0x0C4 / 196 | 0x158 / 344 | GDI handle cache (34 DWORDs x86, 60 DWORDs x64) |
| `PostProcessInitRoutine` | PVOID | 0x14C / 332 | 0x230 / 560 | Called after process init; usually NULL |
| `TlsExpansionBitmap` | PVOID | 0x150 / 336 | 0x238 / 568 | Bitmap for TLS expansion slots |
| `TlsExpansionBitmapBits[32]` | ULONG[32] | 0x154 / 340 | 0x240 / 576 | 1024 expansion TLS slot bits |
| `SessionId` | ULONG | 0x1D4 / 468 | 0x2C0 / 704 | Terminal Services session ID |

---

## Deep Field Explanations

### `BeingDebugged` (+0x002)

This single-byte boolean is written to `1` by the Windows debug subsystem when a debugger attaches to or creates the process. Specifically, `NtSetInformationProcess` with `ProcessDebugPort` causes the kernel to set this byte via `DbgkMapViewOfSection` and `PspSetProcessDebugPort`. The `IsDebuggerPresent()` Win32 API does nothing more than read this byte:

```asm
; Equivalent to IsDebuggerPresent() — no API call needed
mov   eax, fs:[30h]     ; EAX = PEB
movzx eax, byte [eax+2] ; EAX = PEB.BeingDebugged (0 or 1)
test  eax, eax
jnz   debugger_detected
```

**Why shellcode checks this:** If a debugger is present, the shellcode may wish to take a different execution path, loop indefinitely, or corrupt its own stack to prevent analysis. The check is a cheap, single-read anti-analysis primitive.

**False positive risk:** Some process injection frameworks (e.g., certain EDR user-mode hooks) set `BeingDebugged` as a side effect of attaching a lightweight debug port for monitoring — not because a human analyst is present. Additionally, `OutputDebugString` loops that check for a debugger listener will cause `BeingDebugged` to be set in processes that use the debug output mechanism. Shellcode relying solely on this field may trigger on non-debugger processes in hardened environments.

**Bypass from the defender side:** NTDLL-hooking tools can intercept the memory read or patch the PEB so `BeingDebugged` always reads as 0 during sandboxed execution. Shellcode countering this uses `NtQueryInformationProcess(ProcessDebugPort)` instead, which is harder to fake.

### `Ldr` (+0x00C x86 / +0x018 x64)

This is a pointer to the `PEB_LDR_DATA` structure, which the Windows loader (`ntdll!LdrpInitializeProcess`) populates during process startup before the application entry point runs. The `Ldr` field is the shellcode's **gateway to the loaded module list**.

The `PEB_LDR_DATA` structure contains three doubly-linked list heads. Each list connects all loaded `LDR_DATA_TABLE_ENTRY` structures in a different traversal order. By walking these lists, shellcode can enumerate every DLL loaded into the process and read each DLL's base address, from which it can parse the PE export table.

The pointer at `PEB.Ldr` is valid for the entire life of the process. The loader acquires `PEB.LoaderLock` (a critical section at +0x0A0 on x86) when modifying the module list, so reading `Ldr` and its lists is safe as long as no DLL load/unload is happening concurrently — a concern for multi-threaded shellcode but not for typical single-threaded payloads.

### `ProcessHeap` (+0x018 x86 / +0x038 x64)

This is a `HANDLE` to the process's default heap, created by `RtlCreateHeap` during process initialization. When shellcode calls `HeapAlloc(GetProcessHeap(), ...)`, `GetProcessHeap()` simply returns this value. Stager shellcode can use it directly:

```asm
; x86: allocate 0x1000 bytes from the default process heap
mov   eax, fs:[30h]         ; EAX = PEB
mov   eax, [eax+0x18]       ; EAX = ProcessHeap handle
push  0x1000                ; dwBytes
push  0x00000008            ; dwFlags = HEAP_ZERO_MEMORY
push  eax                   ; hHeap
call  dword ptr [ebp+HeapAlloc_slot]
```

**Why this matters:** Shellcode that needs a persistent, writable buffer (for a decoded stage-2, for a socket receive buffer, etc.) needs a heap. Rather than `VirtualAlloc` (which triggers many AV/EDR hooks due to the RWX permission), using `HeapAlloc` on the existing process heap is lower-profile because the heap memory is already committed as readable/writable.

### `NtGlobalFlag` (+0x068 x86 / +0x0BC x64)

This ULONG holds a bitmask of system-wide flags that affect runtime behavior. The critical anti-debug value is `0x70`, which is the combination of:

- `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10) — adds sentinel bytes at the end of heap allocations
- `FLG_HEAP_ENABLE_FREE_CHECK` (0x20) — validates heap blocks on free
- `FLG_HEAP_VALIDATE_PARAMETERS` (0x40) — validates heap parameters

When a process is created under a debugger (specifically when a process is created with `DEBUG_PROCESS` or when a debugger creates the process via `CreateProcess`), the Windows Debug Heap feature sets these three flags in `NtGlobalFlag`. As a consequence, the heap behaves differently — allocation patterns change and extra metadata is written. Shellcode can read this field and check for the `0x70` mask:

```asm
; x86: check NtGlobalFlag for debug heap indicator
mov   eax, fs:[30h]         ; EAX = PEB
mov   eax, [eax+0x68]       ; EAX = NtGlobalFlag
and   eax, 0x70
cmp   eax, 0x70
je    debugger_detected     ; All three debug-heap flags set
```

**Important nuance:** Windows 10 version 1903+ introduced changes to the Debug Heap logic. On newer systems, `NtGlobalFlag` may not reliably be set to `0x70` under all debuggers, especially when using `gflags.exe` is not involved. WinDbg in some configurations does not enable the debug heap. However, when `gflags.exe /i <image> +hpa` (heap page allocator) is set, additional flags appear.

### `ImageBaseAddress` (+0x008 x86 / +0x010 x64)

This is the virtual address at which the main executable (not any DLL) was loaded. For a standard process it matches the `ImageBase` in the executable's PE optional header, though ASLR can change it. Shellcode that runs inside a host process (injected) rarely cares about `ImageBaseAddress` because it is trying to find kernel32/ntdll, not the host. However, malware that needs to locate and patch the host's IAT (Import Address Table), or that performs reflective hollowing against the host image, reads this field to find the PE header of the host executable.

### `OSMajorVersion` / `OSMinorVersion` / `OSBuildNumber`

These fields allow shellcode to make version-dependent decisions without calling `GetVersionEx` (deprecated) or `VerifyVersionInfo`. For example, shellcode exploiting a kernel vulnerability can check whether the current build supports a particular mitigation (CFG, HVCI, etc.) and choose a different code path:

```asm
; x86: check if Windows 10+
mov   eax, fs:[30h]
mov   eax, [eax+0xA4]       ; PEB.OSMajorVersion
cmp   eax, 0x0A             ; 10 decimal
jb    pre_win10_path
```

The `OSBuildNumber` (USHORT at +0x0AC) is particularly useful for distinguishing Windows 10 feature updates (19041, 19045, 22000, 22621, etc.) which changed internal structures and mitigations.

---

## x86 vs x64 Differences

### Pointer Size and Padding

On x86, every pointer in the PEB is 4 bytes. On x64, every pointer is 8 bytes. This cascades through the entire structure: fields that follow pointers shift to higher offsets on x64. The `BeingDebugged` byte at offset `0x002` and `ReadImageFileExecOptions` at `0x001` are identical on both architectures because they precede the first pointer. But starting with `Mutant` (the first HANDLE), the x64 layout inserts 4 bytes of alignment padding at `0x004`–`0x007` to align the 8-byte HANDLE to an 8-byte boundary, pushing `Mutant` to `0x008` rather than `0x004`.

### The `GdiHandleBuffer` Size Change

On x86, `GdiHandleBuffer` is an array of 34 DWORDs (136 bytes). On x64, it expands to 60 DWORDs (240 bytes). This single field accounts for a large portion of the structural size difference between architectures, and it shifts all fields after it significantly on x64.

### Fields Added in Vista / Windows 7 / Windows 10

The PEB has grown with every major Windows version. Fields like `ApiSetMap` (the API set redirection schema), `AppCompatFlags`, and `FlsCallback` were added or moved. The offsets listed in this document reflect Windows 10 21H2 and later for the canonical values. Windows 7 x64 has minor differences (e.g., `NtGlobalFlag` is at `0x0BC` on Windows 7 x64 and the same on Windows 10 x64 — this field has been stable).

### WOW64 (32-bit Process on 64-bit Windows)

A 32-bit process running under WOW64 has two PEBs: the 32-bit PEB (accessible via `FS:[0x30]` in the 32-bit code) and a 64-bit PEB (accessible by switching to the 64-bit code segment and reading `GS:[0x60]`). Shellcode running in WOW64 mode reads the 32-bit PEB and sees the 32-bit module list, which contains the WOW64 shim DLLs (wow64.dll, wow64win.dll, wow64cpu.dll) in addition to the 32-bit kernel32.dll. This is generally what 32-bit shellcode wants.

---

## WinDbg Verification

### Dump the PEB with `!peb`

```
0:000> !peb
PEB at 0064f000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes         <-- debugger attached
    ImageBaseAddress:         00400000
    NtGlobalFlag:             70          <-- debug heap flags set
    NtGlobalFlag2:            00000000
    BeingDebugged:            01
    Ldr                       77c75880
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 00841fa8 . 00842248
    Ldr.InLoadOrderModuleList: 00841f20 . 008421c0
    Ldr.InMemoryOrderModuleList: 00841f28 . 008421c8
    Base TimeStamp                        Module
    400000 5fab3d90 Nov 10 2020          C:\test\target.exe
    77b00000 b1d81b94 May 25 1969        C:\Windows\SysWOW64\ntdll.dll
    75c40000 0fce24be Jan 11 2022        C:\Windows\SysWOW64\kernel32.dll
    ...
```

**What to look for:** `BeingDebugged: Yes` and `NtGlobalFlag: 70` confirm you are under a debugger. The `Ldr.InInitializationOrderModuleList` shows the start/end addresses of the init-order list — the first address is the Flink of the list head, pointing at the first real entry.

### Use `dt` for the Raw Structure

```
0:000> dt ntdll!_PEB @$peb
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x00400000 Void
   +0x00c Ldr              : 0x77c75880 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x007f1c80 _RTL_USER_PROCESS_PARAMETERS
   +0x018 ProcessHeap      : 0x00840000 Void
   +0x068 NtGlobalFlag     : 0x70
   +0x0a4 OSMajorVersion   : 0xa
   +0x0a8 OSMinorVersion   : 0
   +0x0ac OSBuildNumber    : 0x4a61
```

**Reading the output:** The `@$peb` pseudo-register is WinDbg's shorthand for the current process's PEB address. Each line shows the hex offset, field name, and value. The `_PEB_LDR_DATA` pointer at `+0x00c` is what shellcode walks.

### Navigate to the Ldr

```
0:000> dt ntdll!_PEB_LDR_DATA 0x77c75880
   +0x000 Length           : 0x28
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null)
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x841f20 - 0x8421c0 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x841f28 - 0x8421c8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x841fa8 - 0x842248 ]
```

The three list entries each contain a `Flink` and `Blink`. The `Flink` of each is the address of the first real `_LDR_DATA_TABLE_ENTRY`'s corresponding list field (not the entry start — see `LDR_DATA_TABLE_ENTRY.md` for the delta calculation).

### Verify PEB Address from TEB

```
0:000> dt ntdll!_TEB @$teb ProcessEnvironmentBlock
   +0x030 ProcessEnvironmentBlock : 0x0064f000 _PEB
0:000> ? poi(@$teb+0x30)
Evaluate expression: 6614016 = 0064f000
```

Confirm that `FS:[0x30]` matches what WinDbg shows:

```
0:000> dd @$teb+0x30 L1
0012ffd0  0064f000
```

---

## Assembly Walkthrough

The following is the canonical x86 PEB-walk shellcode prologue, heavily commented to explain every instruction's purpose:

```asm
; ─── x86 PEB Walk: Find kernel32.dll Base Address ───────────────────────────
;
; On entry: nothing assumed. On exit: EBX = kernel32.dll ImageBase
;
; Register usage:
;   ESI = current LDR_DATA_TABLE_ENTRY (InInitializationOrderLinks pointer)
;   EBX = module base address (result)
;   EDI = BaseDllName.Buffer (unicode string pointer)
;   ECX = 0 (used for null-byte-free segment access)

find_kernel32:
    xor   ecx, ecx              ; ECX = 0 — avoids encoding 0x30 as an immediate
                                ; with a zero in the operand, some encoders zero-extend;
                                ; using ecx+30h means the byte is 0x30, not 0x00 0x30
    mov   esi, fs:[ecx+0x30]    ; ESI = PEB pointer (TEB.ProcessEnvironmentBlock)
                                ; FS base = TEB; +0x30 = ProcessEnvironmentBlock field

    mov   esi, [esi+0x0c]       ; ESI = PEB.Ldr (pointer to PEB_LDR_DATA)
                                ; +0x0C is the offset of Ldr within _PEB on x86

    mov   esi, [esi+0x1c]       ; ESI = PEB_LDR_DATA.InInitializationOrderModuleList.Flink
                                ; +0x1C within PEB_LDR_DATA is the InInitializationOrder
                                ; list head. Dereferencing gives us the Flink, which points
                                ; INTO the first LDR_DATA_TABLE_ENTRY at its
                                ; InInitializationOrderLinks field (+0x10 in the entry).
                                ; This is NOT the entry start — see below.

next_module:
    ; At this point ESI points to LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks
    ; which is at offset +0x10 within the entry. So:
    ;   ESI+0x00 = InInitializationOrderLinks.Flink  (next module in init order)
    ;   ESI+0x04 = InInitializationOrderLinks.Blink  (prev module in init order)
    ;   ESI+0x08 = DllBase   (because DllBase is at +0x18 in entry, and 0x18 - 0x10 = 0x08)
    ;   ESI+0x10 = EntryPoint (at +0x20 in entry, delta = 0x20 - 0x10 = 0x10)
    ;   ESI+0x18 = SizeOfImage (at +0x28 in entry, delta = 0x18)
    ;   ESI+0x20 = BaseDllName.Length (at +0x30 in entry via UNICODE_STRING at +0x2C,
    ;              but BaseDllName is at +0x2C, and 0x2C - 0x10 = 0x1C in delta terms;
    ;              BaseDllName.Buffer is at +0x2C+0x04 = +0x30 in entry = +0x20 delta)

    mov   ebx, [esi+0x08]       ; EBX = DllBase (module base address, delta 0x08 from
                                ; InInitializationOrderLinks pointer)

    mov   edi, [esi+0x20]       ; EDI = BaseDllName.Buffer (pointer to wide-char name)
                                ; BaseDllName is UNICODE_STRING at entry+0x2C
                                ; UNICODE_STRING.Buffer is at +0x04 within it = entry+0x30
                                ; Delta from InInitializationOrder link: 0x30 - 0x10 = 0x20

    mov   esi, [esi]            ; ESI = Flink of current InInitializationOrderLinks
                                ; Advance to next module BEFORE the compare, so that
                                ; if the compare fails, ESI is already positioned for
                                ; the next iteration of next_module

    ; Identify kernel32.dll by checking that the 13th wide character (index 12)
    ; is a null terminator — kernel32.dll has exactly 12 characters, so
    ; position 12 (zero-indexed) should be 0x0000 in UTF-16LE.
    ; Each wide char is 2 bytes, so index 12 is at byte offset 12*2 = 24 = 0x18
    cmp   [edi+12*2], cx        ; Compare WORD at name[12] with 0 (CX=0)
    jne   next_module           ; Not 12 characters long, try next
    ; Note: this check is a length heuristic, not a full string compare.
    ; Modules with a 12-character name that happen to come before kernel32.dll
    ; in initialization order could cause a false match — see Common Mistakes.
```

### x64 Equivalent

```asm
; x64 PEB Walk: Find kernel32.dll Base Address
; On exit: RBX = kernel32.dll ImageBase

find_kernel32_x64:
    xor   rcx, rcx
    mov   rax, gs:[rcx+0x60]    ; RAX = PEB (GS base = TEB64; +0x60 = PEB pointer)
    mov   rax, [rax+0x18]       ; RAX = PEB.Ldr (x64 offset 0x18)
    mov   rsi, [rax+0x30]       ; RSI = Ldr.InInitializationOrderModuleList.Flink
                                ; +0x30 in PEB_LDR_DATA on x64

next_module_x64:
    mov   rbx, [rsi+0x10]       ; RBX = DllBase (delta from InInitOrderLinks on x64)
                                ; InInitOrderLinks at +0x20 in entry (x64)
                                ; DllBase at +0x30 in entry (x64)
                                ; Delta: 0x30 - 0x20 = 0x10

    mov   rdi, [rsi+0x40]       ; RDI = BaseDllName.Buffer (x64 delta calculation)
                                ; BaseDllName UNICODE_STRING at entry+0x58 (x64)
                                ; Buffer at +0x08 within UNICODE_STRING = entry+0x60
                                ; Delta from InInitOrderLinks (entry+0x20): 0x60-0x20=0x40

    mov   rsi, [rsi]            ; Advance to next module

    cmp   word [rdi+12*2], cx   ; Check for null at position 12 (kernel32.dll length)
    jne   next_module_x64
```

---

## Common Mistakes

### Mistake 1: Using the Wrong `Ldr` List and Wrong Delta

Most shellcode tutorials use `InInitializationOrderModuleList` and access `DllBase` at `ESI+0x08`. This delta of 8 is only correct when navigating via `InInitializationOrderLinks`. If you switch to `InLoadOrderModuleList` (e.g., to get a different traversal order), the Flink pointer points at the `InLoadOrderLinks` field which is at offset `+0x00` in the entry — so the DllBase delta changes to `0x18` (x86) or `0x30` (x64). Mixing list traversal with the wrong base delta produces garbage addresses that typically crash.

### Mistake 2: Relying on Init-Order Position for Kernel32

Classic shellcode literature states kernel32.dll is the second entry in the initialization order list (index 1, after ntdll.dll at index 0). This was reliable on Windows XP and Vista. On Windows 7+, additional DLLs such as `API-MS-Win-Core-*` shim DLLs and `kernelbase.dll` appear in the list, and their relative ordering can vary by system configuration. On some Windows 10 builds under WOW64, the order is ntdll → kernelbase → kernel32. The "check for 12-character name" heuristic is more robust than assuming a fixed index, but it is still vulnerable to a module whose name has the same length. A hash of the module name (ROR-13 hash is classic) is more reliable.

### Mistake 3: Confusing `PEB.Ldr` Value with the List Head Itself

`PEB.Ldr` is a **pointer to `PEB_LDR_DATA`**. You must dereference it before you can access the list heads. A common error is:

```asm
; WRONG:
mov   esi, fs:[30h]     ; ESI = PEB address (correct)
mov   esi, [esi+0x1c]   ; WRONG: 0x1c is offset in PEB_LDR_DATA, not PEB
                        ; You skipped the Ldr dereference!

; CORRECT:
mov   esi, fs:[30h]     ; ESI = PEB address
mov   esi, [esi+0x0c]   ; ESI = PEB.Ldr = &PEB_LDR_DATA
mov   esi, [esi+0x1c]   ; ESI = PEB_LDR_DATA.InInitializationOrderModuleList.Flink
```

### Mistake 4: Not Handling the Null Module Entry

The `InInitializationOrderModuleList` is a circular doubly-linked list. The list head (inside `PEB_LDR_DATA`) is the sentinel node. When iterating, if you walk past the last real entry and into the sentinel, `DllBase` and `BaseDllName.Buffer` will be zero or garbage. Shellcode should limit the number of iterations or check that `DllBase != 0` before reading the name buffer.

### Mistake 5: Assuming `NtGlobalFlag` Offset is 0x068 on All Windows

The `NtGlobalFlag` offset (`0x068` on x86 Windows 7/10, `0x0BC` on x64) is correct for all modern Windows versions. However, on Windows XP x86, the PEB layout differs slightly — `NtGlobalFlag` is at `0x068` there too, but several fields between `0x038` and `0x068` have different meanings or did not exist. If targeting XP specifically, verify against a Windows XP SDK or use WinDbg's `dt ntdll!_PEB` output on the target OS.

---

## Defensive Caveats

**What EDRs and AV engines look for:**

1. **Memory access pattern:** The sequence `FS:[0x30]` → `[+0x0C]` → `[+0x1C]` → walking list entries is a well-known shellcode signature. Endpoint products that monitor memory access patterns (via ETW or kernel callbacks) flag this sequence, especially when it occurs inside a non-image memory region (heap-allocated or RWX page).

2. **PEB patching as a detection technique:** Some EDR products deliberately modify the PEB in monitored processes — for example, removing modules from the loader lists (`unlinking` them) so that PEB-walk shellcode cannot find them. A PEB walk looking for kernel32 in a process where the EDR has unlinked it will fail silently or crash. This is why mature shellcode falls back to scanning the process's VAS for PE headers when the PEB walk returns nothing.

3. **`BeingDebugged` and `NtGlobalFlag` patching:** Analysis sandboxes typically zero out `BeingDebugged` and `NtGlobalFlag` in the target process's PEB to defeat anti-debug checks. Red team tools that check only these fields will incorrectly conclude they are running without a sandbox when they are.

4. **ETW telemetry on `NtQueryInformationProcess`:** More sophisticated anti-debug using `NtQueryInformationProcess(ProcessDebugPort)` generates `EtwTi` (ETW Threat Intelligence) events that many EDR products log. The PEB-based checks avoid this telemetry, which is why they remain in active use despite being detectable.

**For red team practice:** Always test shellcode against actual EDR products in controlled lab environments. PEB walk techniques should be considered "known bad" from a signature perspective — their value lies in their reliability and position-independence, not in evasion. Layer additional obfuscation (indirect syscalls, sleep + check, API hammering) on top of PEB walk primitives.
