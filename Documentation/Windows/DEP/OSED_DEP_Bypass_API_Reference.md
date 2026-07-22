# DEP Bypass API Reference — x86 Windows

Quick reference for APIs that can disable or circumvent DEP on 32-bit Windows. Organized by technique category.

## Classic Six (Corelan Table)

| API | Technique | Key args |
|-----|-----------|----------|
| `VirtualProtect` | Mark existing memory RWX | `lpAddress`, `dwSize`, `PAGE_EXECUTE_READWRITE`, `&oldProtect` |
| `VirtualAlloc` | Allocate new RWX region | `lpAddress`, `dwSize`, `MEM_COMMIT`, `PAGE_EXECUTE_READWRITE` |
| `WriteProcessMemory` | Copy shellcode to executable region | `hProcess(-1)`, `lpBaseAddress`, `lpBuffer`, `nSize`, `&written` |
| `HeapCreate` | Create executable heap | `HEAP_CREATE_ENABLE_EXECUTE`, `dwInitialSize`, `dwMaxSize` |
| `SetProcessDEPPolicy` | Disable DEP for process | `0` (disable). Pre-Win8 only; fails if permanent DEP is set. |
| `NtSetInformationProcess` | Disable DEP via ntdll | `hProcess`, `ProcessExecuteFlags(0x22)`, `&flags(0x2)`, `sizeof(ULONG)` |

## ntdll Syscall Equivalents

These call the same kernel syscall but bypass kernel32-level hooks. Increasingly useful against EDR that hooks kernel32 but not ntdll.

| API | Equivalent to | Notes |
|-----|--------------|-------|
| `NtAllocateVirtualMemory` | `VirtualAlloc` | Args are pointers-to-values (NTSTATUS convention). `ZwAllocateVirtualMemory` is the same address in usermode. |
| `NtProtectVirtualMemory` | `VirtualProtect` | Same pointer-to-value convention. |
| `NtWriteVirtualMemory` | `WriteProcessMemory` | Use process handle `-1` for self. |

## Memory-Mapping Primitives

Bypass `VirtualProtect` entirely by creating executable mappings.

| API(s) | Technique |
|--------|-----------|
| `CreateFileMapping` + `MapViewOfFile` | `CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, ...)` creates an anonymous section. `MapViewOfFile()` maps it RWX. Copy shellcode, jump. |
| `NtCreateSection` + `NtMapViewOfSection` | ntdll equivalent. Same two-call pattern, avoids kernel32. |

## Copy Primitives

Pair these with an existing or newly allocated RWX region.

| API | Notes |
|-----|-------|
| `RtlMoveMemory` | ntdll `memcpy`. Common in `VirtualAlloc` + copy + jump chains. |
| `RtlCopyMemory` | Same as above (macro resolving to `memcpy` in most builds). |
| `RtlDecompressBuffer` | Decompress into RWX buffer. Avoids obvious `memcpy` signatures. |

## Code-Loading (Sidestep DEP)

These don't make stack/heap memory executable — they load or launch properly-formed executable content.

| API | Technique | Trade-off |
|-----|-----------|-----------|
| `LoadLibraryA` / `LdrLoadDll` | Load DLL from disk or UNC path. PE `.text` section is executable by design. | Requires file-write or network path. |
| `WinExec` | `WinExec("cmd /c ...", 0)`. Launches a process. | Not a memory-level bypass. Simple chain (2 args). |
| `CreateProcessA` | Full process creation. | More args to set up but more control. |

## Modern Policy APIs

| API | Notes |
|-----|-------|
| `SetProcessMitigationPolicy` | Win8+. Can modify `ProcessDEPPolicy`. Fails if permanent DEP is already set (default for modern processes). Same practical limitation as `SetProcessDEPPolicy`. |

## PUSHAD Register Map (VirtualProtect)

For the standard PUSHAD-based chain targeting `VirtualProtect`:

```
EDI = RET gadget              (consumed by PUSHAD;RET sequence)
ESI = &VirtualProtect          (function to call)
EBP = JMP ESP                  (return addr → redirects to shellcode)
ESP = (automatic)              (lpAddress — captured by PUSHAD)
EBX = dwSize                   (e.g., 0x201)
EDX = 0x40                     (PAGE_EXECUTE_READWRITE)
ECX = writable DWORD           (lpflOldProtect — any .data addr)
EAX = 0x90909090               (NOP sled at JMP ESP landing zone)
```

Stack after PUSHAD (top to bottom):
```
[EDI]  ← RET pops → slides
[ESI]  ← 2nd RET pops → VirtualProtect executes
[EBP]  ← VP return addr (JMP ESP)
[ESP]  ← lpAddress (auto)
[EBX]  ← dwSize
[EDX]  ← flNewProtect
[ECX]  ← lpflOldProtect
[EAX]  ← NOP sled
[shellcode...]
```

## Chain Construction Checklist

1. **Inventory** gadgets from all non-ASLR modules (`!mona rop`, `ROPgadget`, `ropper`)
2. **Classify** each register load: direct POP, indirect (NEG/XCHG via EAX), combo (multi-POP), deref (IAT)
3. **Order** phases: registers loaded via EAX scratch come before EAX's final load. Draw a clobber graph if complex.
4. **Pad** for extra POPs — every unlabeled missing padding shifts the chain by 4 bytes
5. **Verify** in debugger: breakpoint on PUSHAD, confirm all 8 registers, step through RET→RET→VirtualProtect→JMP ESP

## Gadget Search Commands

```bash
# mona.py (Immunity Debugger)
!mona rop -m vulnapp.dll
!mona rop -m vulnapp.dll -cp nonull
!mona jmp -r esp -m vulnapp.dll

# ROPgadget
ROPgadget --binary vulnapp.dll --only "pop|ret|xchg|neg|pushad|jmp"
ROPgadget --binary vulnapp.dll --ropchain

# ropper
ropper -f vulnapp.dll --search "pop edx"
ropper -f vulnapp.dll --search "jmp esp"
```

## OS Compatibility Notes

- `SetProcessDEPPolicy` and `NtSetInformationProcess` only work when DEP is **OptIn** or **OptOut**, not **AlwaysOn**. Modern Windows defaults make these unreliable.
- `VirtualProtect`, `VirtualAlloc`, and `WriteProcessMemory` work across all Windows versions. They are the most reliable targets.
- ntdll equivalents share the same kernel-level enforcement — they bypass usermode hooks, not kernel policy.
- Code-loading techniques (`LoadLibrary`, `WinExec`) work regardless of DEP policy since they don't execute from the stack/heap.