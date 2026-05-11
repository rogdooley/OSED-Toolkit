# Windows Loader Traversal, PE Parsing, and Manual API Resolution (x86)

# Purpose

This document explains how Windows shellcode manually resolves APIs such as:

- `WinExec`
- `LoadLibraryA`
- `GetProcAddress`

without using imports.

The goal is to understand:

```text
TEB
 └── PEB
      └── PEB_LDR_DATA
           └── Loaded Module Lists
                └── kernel32.dll base
                     └── PE Headers
                          └── Export Directory
                               └── Export Tables
                                    └── WinExec RVA
                                         └── WinExec VA
```

This is foundational Windows exploit development knowledge.

---

# Core Mental Model

Shellcode is fundamentally:

```text
pointer
→ offset
→ dereference
→ repeat
```

Most shellcode is simply:

```text
manual memory navigation
```

NOT:

```text
Windows API programming
```

---

# Why Shellcode Does This

Normal programs use imports:

```c
WinExec("calc.exe", SW_SHOW);
```

The Windows loader resolves this automatically through:

- Import Address Table (IAT)
- PE loader
- Import descriptors

Shellcode does NOT have:

- imports
- a PE loader
- relocations
- automatic API resolution

Therefore shellcode must manually:

1. Find loaded modules
2. Locate kernel32.dll
3. Parse PE headers
4. Parse exports
5. Resolve API addresses

This is effectively a custom implementation of:

```text
GetProcAddress
```

---

# Part 1 — TEB → PEB → LDR

---

# TEB (Thread Environment Block)

The TEB is thread-local process state.

In x86:

```nasm
mov esi, fs:[0x30]
```

retrieves:

```text
PEB address
```

because:

```text
FS:[0x30] == TEB->ProcessEnvironmentBlock
```

---

## TEB Structure (x86)

| Offset | Size | Field | Notes |
|---|---|---|---|
| `+0x00` | DWORD | ExceptionList | SEH chain |
| `+0x04` | DWORD | StackBase | Top of stack |
| `+0x08` | DWORD | StackLimit | Bottom of stack |
| `+0x18` | DWORD | Self | TEB pointer |
| `+0x30` | DWORD | ProcessEnvironmentBlock | → PEB |

---

# PEB (Process Environment Block)

The PEB contains process-wide runtime state.

Important field:

| Offset | Field |
|---|---|
| `+0x0C` | Ldr |

which points to:

```text
PEB_LDR_DATA
```

---

## PEB Structure (x86)

| Offset | Size | Field | Notes |
|---|---|---|---|
| `+0x02` | BYTE | BeingDebugged | Anti-debug flag |
| `+0x0C` | DWORD | Ldr | → PEB_LDR_DATA |
| `+0x10` | DWORD | ProcessParameters | |
| `+0x18` | DWORD | ProcessHeap | |
| `+0x68` | DWORD | NtGlobalFlag | Debug heap flags |

---

## Shellcode Example

```nasm
mov esi, fs:[0x30]   ; ESI = PEB
mov esi, [esi+0x0C]  ; ESI = PEB_LDR_DATA
```

---

# PEB_LDR_DATA

Contains loaded module linked lists.

---

## PEB_LDR_DATA Structure (x86)

| Offset | Field | Notes |
|---|---|---|
| `+0x0C` | InLoadOrderModuleList | Ordered by load time |
| `+0x14` | InMemoryOrderModuleList | Ordered by VA |
| `+0x1C` | InInitializationOrderModuleList | Classic shellcode target |

---

# LIST_ENTRY

Windows linked lists use intrusive linked lists.

```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY;
```

---

## Important Concept

The linked-list node is EMBEDDED inside another structure.

The `Flink` does NOT point to structure base.

It points to:

```text
&entry->SomeListField
```

This is the single biggest conceptual hurdle for most people learning Windows loader internals.

---

# Intrusive List Layout

```text
PEB_LDR_DATA
    +0x1C InInitializationOrderModuleList
            |
            v
        LIST_ENTRY head
            |
            +--> Flink ----+
                            |
                            v
                LDR_DATA_TABLE_ENTRY
                    +0x10 InInitializationOrderLinks
                            |
                            +--> Flink ----+
                                            |
                                            v
                                next module entry
```

---

# LDR_DATA_TABLE_ENTRY

Represents a loaded module.

---

## LDR_DATA_TABLE_ENTRY Structure (x86)

| Offset | Size | Field |
|---|---|---|
| `+0x00` | LIST_ENTRY | InLoadOrderLinks |
| `+0x08` | LIST_ENTRY | InMemoryOrderLinks |
| `+0x10` | LIST_ENTRY | InInitializationOrderLinks |
| `+0x18` | DWORD | DllBase |
| `+0x1C` | DWORD | EntryPoint |
| `+0x20` | DWORD | SizeOfImage |
| `+0x24` | UNICODE_STRING | FullDllName |
| `+0x2C` | UNICODE_STRING | BaseDllName |

---

# Recovering Structure Base

Because:

```text
InInitializationOrderLinks = +0x10
```

the structure base is:

```text
entry_base = flink - 0x10
```

---

# Critical Offset Rules

| List Walked | Subtract |
|---|---|
| InLoadOrderLinks | `0x00` |
| InMemoryOrderLinks | `0x08` |
| InInitializationOrderLinks | `0x10` |

This mistake breaks a huge amount of beginner shellcode.

---

# Walking Modules

Shellcode:

```nasm
mov esi, [esi]
```

means:

```text
follow Flink to next module
```

Then:

```text
subtract offset
read DllBase
read BaseDllName
repeat
```

---

# UNICODE_STRING

---

## Structure

| Offset | Field |
|---|---|
| `+0x00` | Length |
| `+0x02` | MaximumLength |
| `+0x04` | Buffer |

---

## Important Notes

`Length` is:

```text
bytes
```

NOT:

```text
characters
```

UTF-16 uses:

```text
2 bytes per character
```

Therefore:

```python
char_count = length // 2
```

---

# RVA vs VA vs File Offset

This distinction is critical.

---

## RVA (Relative Virtual Address)

Offset relative to image base.

Example:

```text
Export RVA = 0x75480
```

---

## VA (Virtual Address)

Actual mapped memory address.

Formula:

```text
VA = ImageBase + RVA
```

Example:

```text
kernel32 base = 0x75680000
export RVA    = 0x00075480

export VA =
0x75680000 + 0x00075480
=
0x756F5480
```

---

# Part 2 — PE Parsing

Once kernel32 base is known:

```text
kernel32 = 0x75680000
```

we parse PE structures manually.

---

# IMAGE_DOS_HEADER

At module base:

```text
0x75680000
```

Expected bytes:

```text
4D 5A
```

which is:

```text
MZ
```

---

## Important Field

| Offset | Field |
|---|---|
| `+0x3C` | e_lfanew |

This points to:

```text
IMAGE_NT_HEADERS
```

---

# Example

```text
e_lfanew = 0xF8
```

Meaning:

```text
NT headers start at:
module_base + 0xF8
```

---

# IMAGE_NT_HEADERS32

Compute:

```text
nt_headers = module_base + e_lfanew
```

---

## Expected Signature

At NT headers:

```text
50 45 00 00
```

which is:

```text
PE\0\0
```

or:

```text
0x00004550
```

---

# NT Header Layout

```text
IMAGE_NT_HEADERS
├── Signature
├── IMAGE_FILE_HEADER
└── IMAGE_OPTIONAL_HEADER32
```

---

# IMAGE_OPTIONAL_HEADER32

Starts at:

```text
nt_headers + 0x18
```

Contains:

```text
DataDirectory[]
```

---

# Important Optional Header Fields

| Offset | Field |
|---|---|
| `+0x10` | AddressOfEntryPoint |
| `+0x1C` | ImageBase |
| `+0x60` | Export Directory RVA |
| `+0x64` | Export Directory Size |

---

# Export Directory

Compute:

```text
export_dir_va =
kernel32_base + export_rva
```

---

# Part 3 — IMAGE_EXPORT_DIRECTORY

At:

```text
export_dir_va
```

lives:

```text
IMAGE_EXPORT_DIRECTORY
```

---

## Structure

| Offset | Field |
|---|---|
| `+0x14` | NumberOfFunctions |
| `+0x18` | NumberOfNames |
| `+0x1C` | AddressOfFunctions |
| `+0x20` | AddressOfNames |
| `+0x24` | AddressOfNameOrdinals |

IMPORTANT:

These are RVAs.

NOT VAs.

---

# Export Tables

Three arrays work together:

```text
AddressOfNames[]
AddressOfNameOrdinals[]
AddressOfFunctions[]
```

---

# Export Resolution Algorithm

```text
for each export name:
    get name RVA
    convert RVA → VA
    read export string

    if name matches:
        get ordinal
        get function RVA
        convert RVA → VA
        return function address
```

---

# Actual Algorithm

```python
for i in range(NumberOfNames):

    name_rva = AddressOfNames[i]
    name_va  = dll_base + name_rva
    name     = read_cstring(name_va)

    if name == target:

        ordinal = AddressOfNameOrdinals[i]

        func_rva = AddressOfFunctions[ordinal]

        func_va = dll_base + func_rva

        return func_va
```

---

# Important Subtlety

This is CRITICAL:

```text
name index != function index
```

You MUST use:

```text
AddressOfNameOrdinals
```

to map names to functions.

This breaks a massive amount of beginner shellcode.

---

# Forwarded Exports

Some exports point to:

```text
DLLNAME.Function
```

instead of executable code.

Example:

```text
KERNELBASE.CreateFileW
```

These are:

```text
forwarded exports
```

You must recursively resolve them.

---

# Hash-Based API Resolution

Shellcode often avoids embedding strings:

```text
WinExec
LoadLibraryA
GetProcAddress
```

because of:

- bad chars
- AV signatures
- string detection

Instead shellcode hashes export names.

---

# Hash Algorithm Pattern

```text
hash = ROR(hash, bits)
hash += current_byte
```

performed one byte at a time.

---

# Why Byte-By-Byte?

Because shellcode processes memory sequentially.

Equivalent assembly:

```nasm
lodsb
ror eax, 13
add eax, ebx
```

This is stream processing.

NOT bulk hashing.

---

# WinDbg Workflow

---

# Verify DOS Header

```windbg
db kernel32_base L40
```

Expected:

```text
4D 5A
```

---

# Read e_lfanew

```windbg
dd kernel32_base+3c L1
```

---

# Verify PE Header

```windbg
db nt_headers L8
```

Expected:

```text
50 45 00 00
```

---

# Dump Export Directory

```windbg
dt ntdll!_IMAGE_EXPORT_DIRECTORY export_dir_va
```

or:

```windbg
dd export_dir_va L10
```

---

# Dump Names Table

```windbg
dd names_table_va
```

Each DWORD is:

```text
name RVA
```

---

# Read Export String

```windbg
da name_va
```

---

# Common Shellcode Failures

| Issue | Cause |
|---|---|
| Wrong structure subtraction | Walking wrong list |
| RVA treated as VA | Forgot to add image base |
| Unicode length confusion | Length is bytes |
| Ordinal bias confusion | Name ordinals are already zero-based |
| Forwarded export crash | Treated string as code |
| Case-sensitive mismatch | `WinExec != winexec` |
| Hardcoded module order | Modern Windows changed loader behavior |

---

# Final Mental Model

Everything reduces to:

```text
pointer
→ offset
→ dereference
→ interpret memory
→ repeat
```

That is Windows shellcode development.