# 17. Windows Process Structures and PEB Walking

## The Path

```
FS:[0x30]  ->  PEB
PEB+0x0C   ->  PEB_LDR_DATA
PEB_LDR_DATA+0x14  ->  InMemoryOrderModuleList (Flink)
```

## TEB (Thread Environment Block)

The FS segment register base points to the TEB. Key offsets:

| Offset | Field |
|--------|-------|
| FS:[0x00] | EXCEPTION_REGISTRATION_RECORD pointer (SEH chain head) |
| FS:[0x04] | StackBase (top of stack, highest address) |
| FS:[0x08] | StackLimit (bottom of committed stack) |
| FS:[0x18] | Self (linear address of TEB) |
| FS:[0x30] | PEB pointer |

## PEB (Process Environment Block)

| Offset | Field |
|--------|-------|
| +0x02 | BeingDebugged (BOOLEAN) |
| +0x08 | ImageBaseAddress |
| +0x0C | Ldr (PEB_LDR_DATA pointer) |

## PEB_LDR_DATA

| Offset | Field |
|--------|-------|
| +0x0C | InLoadOrderModuleList.Flink |
| +0x14 | InMemoryOrderModuleList.Flink |
| +0x1C | InInitializationOrderModuleList.Flink |

## _LDR_DATA_TABLE_ENTRY

This structure contains information about each loaded module. The three lists
thread through this structure at different offsets:

| Field | Offset from entry base |
|-------|----------------------|
| InLoadOrderLinks | +0x00 |
| InMemoryOrderLinks | +0x08 |
| InInitializationOrderLinks | +0x10 |
| DllBase | +0x18 |
| EntryPoint | +0x1C |
| SizeOfImage | +0x20 |
| FullDllName | +0x24 |
| BaseDllName | +0x2C |

## List Entry Pointers and Structure Offsets

The Flink pointer in a linked list entry points to the **LIST_ENTRY field**
in the next structure, NOT to the base of the next structure. To reach the
base of the containing structure, subtract the field's offset:

| List | Links field offset | Subtract to reach entry base |
|------|-------------------|------------------------------|
| InLoadOrder (+0x0C) | +0x00 | 0x00 |
| InMemoryOrder (+0x14) | +0x08 | 0x08 |
| InInitializationOrder (+0x1C) | +0x10 | 0x10 |

For InMemoryOrderModuleList: the Flink points to `next_entry + 0x08`. To
access DllBase (at +0x18 from entry base), you can read `[Flink + 0x10]`
(because 0x18 - 0x08 = 0x10).

## Assembly Walkthrough

```asm
; Get PEB
xor ecx, ecx
mov eax, fs:[ecx+0x30]      ; EAX = PEB

; Get PEB_LDR_DATA
mov eax, [eax+0x0C]          ; EAX = PEB->Ldr

; Get first entry in InMemoryOrderModuleList
mov esi, [eax+0x14]          ; ESI = Flink (points to first entry's InMemoryOrderLinks)

; Walk the list to find kernel32.dll
; ESI points to InMemoryOrderLinks (offset +0x08 within the entry)
; DllBase is at entry+0x18, which is [ESI+0x10] from the links pointer

next_module:
    mov ebx, [esi+0x10]      ; EBX = DllBase
    mov edi, [esi+0x28]      ; EDI = BaseDllName.Buffer (Unicode string)
                              ; BaseDllName is at entry+0x2C; from ESI (at entry+0x08)
                              ; that is 0x24, plus 0x04 to skip the UNICODE_STRING header
    mov esi, [esi]            ; ESI = Flink (next entry)
    ; compare name at EDI with target module name...
    ; if match: EBX = module base
```

## Module Order (Windows 7/10 32-bit, typical)

Using InMemoryOrderModuleList:
1. The executable itself
2. ntdll.dll
3. kernel32.dll (or KernelBase.dll on newer systems)

Using InInitializationOrderModuleList:
1. ntdll.dll
2. kernel32.dll
3. KernelBase.dll

The exact order can vary by Windows version. Shellcode that assumes "the second
entry is always kernel32" is fragile. Comparing module names is more reliable.

## WinDbg Verification

```
0:000> !peb
0:000> !teb
0:000> dt ntdll!_PEB @$peb
0:000> dt ntdll!_PEB_LDR_DATA poi(@$peb+0xc)
0:000> !dlls
```
