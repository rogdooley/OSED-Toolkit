# Windows x86 Shellcode — PEB & PE Export Resolution

> **Goal:** Resolve arbitrary Win32 API addresses at runtime without imports, reloc tables, or hardcoded addresses.  
> Walk PEB → find loaded module → parse PE export directory → match function name → return VA.

---

## 1. PEB Traversal

### Relevant Structures & Important Offsets

```
fs:[0x30]                      → PEB *
PEB + 0x0C                     → PEB_LDR_DATA *
PEB_LDR_DATA + 0x1C            → InInitializationOrderModuleList.Flink
                                  (= first_entry + 0x10)

_LDR_DATA_TABLE_ENTRY (init-order layout):
  +0x00  LIST_ENTRY  InInitializationOrderLinks  (Flink/Blink)
  +0x08  PVOID       DllBase
  +0x10  PVOID       EntryPoint
  +0x14  ULONG       SizeOfImage
  +0x18  UNICODE_STRING FullDllName
  +0x20  UNICODE_STRING BaseDllName  (Buffer at +0x20, Length at +0x22)
```

### Why Subtracting 0x10 Works

`InInitializationOrderLinks` is at offset `+0x10` within the entry. The Flink pointer therefore points to `next_entry + 0x10`. To reach the entry base (where `DllBase` lives at `+0x08`), subtract `0x10`.

| List | Flink offset within entry | Subtract to reach base |
|------|--------------------------|------------------------|
| `InLoadOrder` (LDR+0x0C) | +0x00 | 0x00 |
| `InMemoryOrder` (LDR+0x14) | +0x08 | 0x08 |
| `InInitializationOrder` (LDR+0x1C) | +0x10 | **0x10** |

### Init-Order Module Sequence (XP/7 32-bit)

```
[0] ntdll.dll
[1] kernel32.dll
[2] KernelBase.dll
...
terminal: Flink == address of list head (LDR+0x1C)
```

### ASCII Structure Diagram

```
FS:[0x30]
   │
   ▼
┌──────────────┐
│     PEB      │  +0x0C → PEB_LDR_DATA *
└──────────────┘
                    │
                    ▼
            ┌──────────────────┐
            │  PEB_LDR_DATA    │  +0x1C → InInitializationOrderModuleList.Flink
            └──────────────────┘
                               │
                               ▼  (points to entry+0x10 of first module)
                     ┌──────────────────────────────┐
                ─0x10├──────────────────────────────┤ ← entry base
                +0x00│ InInitOrderLinks (Flink/Blink)│
                +0x08│ DllBase                       │
                +0x20│ BaseDllName.Buffer (UNICODE *) │
                     └──────────────────────────────┘
                               │
                               └─ Flink → next_entry+0x10 → sub 0x10 → next base
```

---

## 2. PE Parsing

### Header Chain & Important Offsets

```
DllBase + 0x00       IMAGE_DOS_HEADER.e_magic   ("MZ" = 0x5A4D)
DllBase + 0x3C       IMAGE_DOS_HEADER.e_lfanew  (RVA to IMAGE_NT_HEADERS)

DllBase + e_lfanew:
  +0x00  DWORD  Signature            ("PE\0\0" = 0x00004550)
  +0x04  IMAGE_FILE_HEADER           (20 bytes)
  +0x18  IMAGE_OPTIONAL_HEADER32
    +0x18+0x60  DataDirectory[0]     → Export Directory
      +0x00  VirtualAddress (RVA)    ← add DllBase to get VA
      +0x04  Size
```

> `DataDirectory[0]` is at `OptionalHeader base + 0x60`.  
> Absolute: `DllBase + e_lfanew + 0x18 + 0x60` = `DllBase + e_lfanew + 0x78`

```
DllBase + DataDirectory[0].VirtualAddress = IMAGE_EXPORT_DIRECTORY *
```

### ASCII Structure Diagram

```
DllBase
  │ +0x3C → e_lfanew
  ▼
IMAGE_DOS_HEADER
  │ e_lfanew → IMAGE_NT_HEADERS
  ▼
IMAGE_NT_HEADERS
  │ +0x78 (OptHdr+0x60) → DataDirectory[0].VirtualAddress (RVA)
  ▼                        DataDirectory[0].Size
IMAGE_EXPORT_DIRECTORY  (= DllBase + DataDirectory RVA)
  │
  ├─ +0x18  NumberOfNames
  ├─ +0x1C  AddressOfFunctions    → RVA[] (DWORD per entry)
  ├─ +0x20  AddressOfNames        → RVA[] (DWORD per entry, name strings)
  └─ +0x24  AddressOfNameOrdinals → WORD[] (index into Functions[])
```

---

## 3. IMAGE_EXPORT_DIRECTORY

### Offsets

```
+0x10  DWORD  Base
+0x14  DWORD  NumberOfFunctions
+0x18  DWORD  NumberOfNames
+0x1C  DWORD  AddressOfFunctions    (RVA → DWORD[] of function RVAs)
+0x20  DWORD  AddressOfNames        (RVA → DWORD[] of name string RVAs)
+0x24  DWORD  AddressOfNameOrdinals (RVA → WORD[] of ordinals)
```

### Array Relationships

```
AddressOfNames[i]         → RVA to name string (ASCII)
AddressOfNameOrdinals[i]  → WORD ordinal (unbiased; direct index into Functions[])
AddressOfFunctions[ordinal] → RVA to function

i       : 0 .. NumberOfNames-1     (name index)
ordinal : 0 .. NumberOfFunctions-1 (function index, no bias subtraction needed)

function VA = DllBase + Functions[ NameOrdinals[i] ]
```

> **Every RVA** in the export directory requires `+ DllBase` before dereference — no exceptions.

### Forwarded Exports

If `Functions[ordinal]` RVA falls **within** the export directory's address range (`DataDirectory[0].VA` to `VA + Size`), it is a **forwarded name string** (e.g., `NTDLL.RtlAllocateHeap`), not a code pointer. Cannot be called directly; must resolve the forward.

---

## 4. Export Resolution Workflow

```
 1.  fs:[0x30]                → PEB *
 2.  PEB[0x0C]                → LDR *
 3.  LDR[0x1C]                → Flink (= target_entry + 0x10)
 4.  Flink - 0x10             → _LDR_DATA_TABLE_ENTRY base
 5.  entry[0x08]              → DllBase                      (lock in EBX)
 6.  DllBase[0x3C]            → e_lfanew
 7.  DllBase + e_lfanew       → IMAGE_NT_HEADERS
 8.  NT[0x78]                 → ExportDir RVA
 9.  DllBase + ExportDir RVA  → IMAGE_EXPORT_DIRECTORY       (EAX)
10.  EAX[0x20] + DllBase      → AddressOfNames VA            (EDI)
11.  EAX[0x24] + DllBase      → AddressOfNameOrdinals VA     (EDX)
12.  EAX[0x1C] + DllBase      → AddressOfFunctions VA        (ESI)
13.  for i = NumberOfNames-1 downto 0:
       name_va = DllBase + Names[i]
       if hash(name_va) == target_hash: break
14.  ordinal   = NameOrdinals[i]     (WORD → ECX)
15.  func_rva  = Functions[ordinal]  (DWORD)
16.  func_va   = DllBase + func_rva  → CALL TARGET
```

> Steps 10–12 all require `+ DllBase`.  
> Steps 8 and 15 produce RVAs. Steps 9 and 16 convert them to VAs.

---

## 5. Register State Transitions

```nasm
; ── Stage 1: PEB → DllBase ────────────────────────────────────────
mov eax, fs:[0x30]        ; EAX = PEB *
mov eax, [eax + 0x0C]    ; EAX = PEB_LDR_DATA *
mov esi, [eax + 0x1C]    ; ESI = InInitOrder Flink (= first_entry + 0x10)
sub esi, 0x10            ; ESI = first _LDR_DATA_TABLE_ENTRY base
mov ebx, [esi + 0x08]    ; EBX = DllBase  ← LOCK THIS IN EBX

; ── Stage 2: DllBase → EXPORT DIRECTORY ───────────────────────────
mov eax, [ebx + 0x3C]    ; EAX = e_lfanew
add eax, ebx             ; EAX = IMAGE_NT_HEADERS VA
mov eax, [eax + 0x78]    ; EAX = DataDirectory[0].VirtualAddress (RVA)
add eax, ebx             ; EAX = IMAGE_EXPORT_DIRECTORY VA

; ── Stage 3: extract array pointers ───────────────────────────────
; EAX = IMAGE_EXPORT_DIRECTORY
; EBX = DllBase (preserved)
mov ecx, [eax + 0x18]    ; ECX = NumberOfNames
mov edi, [eax + 0x20]    ; EDI = AddressOfNames RVA
add edi, ebx             ; EDI = AddressOfNames VA
mov edx, [eax + 0x24]    ; EDX = AddressOfNameOrdinals RVA
add edx, ebx             ; EDX = AddressOfNameOrdinals VA
mov esi, [eax + 0x1C]    ; ESI = AddressOfFunctions RVA
add esi, ebx             ; ESI = AddressOfFunctions VA

; ── Register contract at loop entry ───────────────────────────────
; EBX = DllBase
; ECX = loop counter (NumberOfNames → 0)
; EDI = AddressOfNames VA
; EDX = AddressOfNameOrdinals VA
; ESI = AddressOfFunctions VA
; EAX = scratch / current name RVA

; ── Stage 4: name walk + hash match ───────────────────────────────
.loop:
  dec ecx
  mov eax, [edi + ecx*4]      ; EAX = Names[ecx] (RVA)
  add eax, ebx                ; EAX = name string VA
  ; compare hash or bytes
  ; e.g., cmp dword [eax], 0x456e6957  ; "WinE" (little-endian)
  jnz .loop

; ── Stage 5: ordinal → function VA ────────────────────────────────
movzx ecx, word [edx + ecx*2] ; ECX = NameOrdinals[i] (WORD, zero-extended)
mov eax, [esi + ecx*4]        ; EAX = Functions[ordinal] (RVA)
add eax, ebx                  ; EAX = function VA  ← CALL TARGET
```

---

## 6. Assembly Patterns — Operational Meaning

| Instruction | Operational Meaning | Notes |
|---|---|---|
| `mov esi, [edi + ecx*4]` | Load DWORD from `Names[]` at index ECX | Each entry is 4 bytes (RVA); ECX is name index |
| `add esi, ebx` | Convert RVA → VA using DllBase in EBX | All export RVAs require this |
| `movzx ecx, word [edx + ecx*2]` | Load WORD ordinal from `NameOrdinals[i]` | WORD array (2 bytes/entry); always use `movzx` |
| `mov eax, [esi + ecx*4]` | Load function RVA from `AddressOfFunctions[ordinal]` | ESI = Functions VA; ECX = unbiased ordinal |
| `sub esi, 0x10` | Adjust Flink → `_LDR_DATA_TABLE_ENTRY` base | Init-order Flink points to `+0x10` of next entry |
| `mov ebx, [esi + 0x08]` | Read DllBase from LDR entry | `+0x08` in init-order entry layout |

> **Critical:** Never use `mov cx, [edx + ecx*2]`. If ECX has high-word garbage, the ordinal is corrupted. Always `movzx ecx, word [...]`.

---

## 7. Common Mistakes

```
1. Wrong list subtract:
   InLoadOrder      (LDR+0x0C) → subtract 0x00
   InMemoryOrder    (LDR+0x14) → subtract 0x08
   InInitOrder      (LDR+0x1C) → subtract 0x10   ← required here
   Mixing them silently corrupts DllBase.

2. Missing +DllBase on AddressOfNames / AddressOfNameOrdinals /
   AddressOfFunctions before dereferencing. RVA symptom: value
   < 0x10000000 when DllBase is 0x7C800000+.

3. Dirty ECX high-word before WORD ordinal read.
   Use movzx ecx, word [...] — never mov cx, [...].

4. Off-by-one in loop counter. Decrement before access, or
   pre-set ECX to NumberOfNames and decrement at top.

5. Forwarded export: Functions[ordinal] RVA falls inside export
   section range → name string, not code. Calling it crashes.

6. Case-sensitive name matching: export table names are ASCII,
   exact case. "WinExec" ≠ "winexec". Hash must match exactly.

7. Scanning ordinals instead of names. Functions[] is sparse;
   walk by name index (0..NumberOfNames-1) only.

8. EBX clobbered across a nested call. DllBase is lost.
   Caller must save/restore or use a stack slot.

9. e_lfanew read as signed. It is a DWORD offset. Use 32-bit
   add, not movsx. Incorrect sign extension corrupts NT_HEADERS.

10. No loop termination check. InInitOrder list is circular.
    Stop when Flink == list head address (LDR+0x1C); otherwise
    infinite loop or null-deref if target module not loaded.
```

---

## 8. Debugger-Oriented Notes (WinDbg)

### Useful Commands

```
!peb                            ; PEB fields summary
dt ntdll!_PEB @$peb             ; structured PEB view
dt ntdll!_PEB_LDR_DATA          ; LDR offsets
dt ntdll!_LDR_DATA_TABLE_ENTRY  ; entry layout
!lmi kernel32                   ; quick module info
lmvm kernel32                   ; base + size + path
dpa esp                         ; dump stack slots
dps ebx+0x3c l1                 ; read e_lfanew
dpa ebx+<e_lfanew_val>+0x78    ; DataDir[0] RVA
da ebx+<ExportDir_RVA>+<Names[0]_RVA>  ; first export name string
x kernel32!WinExec              ; expected VA to compare against computed result
```

### Validating Each Stage

| Stage | Validation |
|---|---|
| PEB found | `dt ntdll!_PEB @$peb` → `Ldr` field matches computed LDR address |
| DllBase | `lmvm kernel32` → start address matches EBX |
| NT Headers | `dps ebx+<e_lfanew> l1` → reads `0x00004550` ("PE\0\0") |
| Export Dir RVA | `dps ebx+<e_lfanew>+0x78 l1` → value is small (RVA, not VA) |
| Export Dir VA | `db ebx+<ExportDir_RVA>` → first DWORD is export dir characteristics |
| Names array | `da ebx+<Names[0]_RVA>` → reads ASCII function name |
| Final VA | Compare against `x kernel32!WinExec` |

### Distinguishing RVA vs VA Mistakes

```
Symptom: reading garbage at what should be a string
Cause:   Names[i] still an RVA; forgot add eax, ebx
Fix:     add eax, ebx before dereference

Symptom: function VA = 0xCCCCCCCC or access violation immediately
Cause:   ECX high-word dirty before NameOrdinals read
Fix:     movzx ecx, word [edx + ecx*2]

Symptom: DllBase = 0 or small integer
Cause:   Forgot sub esi, 0x10 (or used wrong list offset)
Fix:     Verify which list (InInitOrder = -0x10)

Symptom: value lands inside export directory range
Cause:   Forwarded export; not a function pointer
Fix:     Check if func_rva is within [ExportDir.VA, ExportDir.VA + Size]
```

---

## 9. Typical Shellcode Architecture Patterns

### Call-Pop Prologue (Position Independence)

```nasm
  call get_pc
get_pc:
  pop  ebp            ; EBP = address of get_pc label (current EIP)
```

### Helper Routine: Hash-Based Name Matching

Avoids null bytes from inline ASCII strings. ROR13-add is the standard (Metasploit-compatible).

```python
# Precompute offline
def ror13(s):
    h = 0
    for c in s:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

print(hex(ror13("WinExec")))   # e.g. 0x98FE8A0E
```

### Register Contract (Single Resolver)

```
EBX = DllBase            (callee-saved; never clobbered)
EAX = return value       (function VA)
ECX = loop counter / ordinal (caller-saved)
EDX = scratch            (caller-saved)
ESI = AddressOfFunctions VA
EDI = AddressOfNames VA
EBP = shellcode base / frame (set once, preserved)
```

### EBP-Relative Stack Slot Storage

```nasm
; At shellcode entry — allocate frame:
  sub esp, 0x28          ; 10 DWORD slots
  mov ebp, esp           ; EBP = frame base

; After each resolution, cache VA:
  mov [ebp + 0x00], eax  ; WinExec
  mov [ebp + 0x04], eax  ; ExitProcess (second pass)
  mov [ebp + 0x08], eax  ; LoadLibraryA

; Call via slot:
  push 1                 ; SW_SHOWNORMAL
  push cmd_ptr
  call [ebp + 0x00]      ; CALL WinExec
```

### Why Register-Only Designs Stop Scaling

With 7 GPRs minus EBP (frame) and ESP (stack), 5 registers are freely usable.

Resolving one API consumes: DllBase + loop counter + 3 array pointers = **5 registers exactly**. No headroom for anything else.

Resolving 2+ APIs or making intermediate calls forces push/pop anyway — ad-hoc and undocumented. Stack slots are explicit, documentable, and debuggable.

**Recommended pattern for >3 APIs:**

1. `resolve_all()` loops the module list once, resolves all needed APIs into a contiguous stack table.
2. Remaining shellcode treats the table as a function pointer array.
3. Never re-resolve at runtime unless the module was not yet loaded.

---

## Quick Reference: Offset Cheat Sheet

```
fs:[0x30]              → PEB *
PEB[0x0C]              → PEB_LDR_DATA *
LDR[0x1C]              → InInitOrderModuleList.Flink
Flink - 0x10           → _LDR_DATA_TABLE_ENTRY base
entry[0x08]            → DllBase
entry[0x20]            → BaseDllName.Buffer (UNICODE *)

DllBase[0x3C]          → e_lfanew
DllBase+e_lfanew[0x78] → ExportDir RVA   (+DllBase = ExportDir VA)

ExportDir[0x18]        → NumberOfNames
ExportDir[0x1C]        → AddressOfFunctions RVA   (DWORD[])
ExportDir[0x20]        → AddressOfNames RVA        (DWORD[])
ExportDir[0x24]        → AddressOfNameOrdinals RVA (WORD[])

func VA = DllBase + Functions[ NameOrdinals[i] ]
```