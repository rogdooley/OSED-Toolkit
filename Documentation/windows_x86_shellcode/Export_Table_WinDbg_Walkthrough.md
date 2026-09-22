# Export Table Resolution -- WinDbg Walkthrough

Hands-on WinDbg sessions walking the PE export table the same way shellcode does.
Companion to [Export_Table_Parsing.md](../Windows/Shellcode/Export_Table_Parsing.md)
and [PEB-and-PE-Export-Resolution.md](PEB-and-PE-Export-Resolution.md).

---

## Walk Export Table (Step by Step)

1. Find kernel32 base
2. Find PE header
3. Find Export Directory
4. Find AddressOfNames
5. Convert RVA to VA
6. Read exported names
7. Find a target function
8. Resolve its actual address

---

### Step 1: Get kernel32 Base

Suppose you've already found:
```
ebx = 766f0000
```
Kernel32 base:
```
KERNEL32 = 0x766f0000
```

### Step 2: Find PE Header

At module base:
```
0:003> dd ebx L1
766f0000  00905a4d
```
That's `MZ`.

Read e_lfanew:
```
0:003> dd ebx+3c L1
766f003c  000000f8
```
PE Header RVA = 0xF8

Convert:
```
PE Header VA = 0x766f0000 + 0xF8 = 0x766f00f8
```

Verify:
```
0:003> dd 766f00f8 L1
766f00f8  00004550
PE\0\0
```

### Step 3: Locate Export Directory RVA

For PE32, Optional Header + 0x78 contains IMAGE_DIRECTORY_ENTRY_EXPORT.

Your shellcode usually does:
```asm
mov eax,[ebx+3c]
add eax,ebx
mov eax,[eax+78]
```

Inspect:
```
0:003> dd 766f00f8+78 L1
766f0170  00076d90
```

Export Directory RVA = 0x76d90 (not an address yet).

Convert:
```
Export Directory VA = 766f0000 + 76d90 = 76766d90
```

### Step 4: Read IMAGE_EXPORT_DIRECTORY

Structure offsets:
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;          // +0x00
    DWORD TimeDateStamp;            // +0x04
    WORD  MajorVersion;             // +0x08
    WORD  MinorVersion;             // +0x0A
    DWORD Name;                     // +0x0C
    DWORD Base;                     // +0x10
    DWORD NumberOfFunctions;        // +0x14
    DWORD NumberOfNames;            // +0x18
    DWORD AddressOfFunctions;       // +0x1C
    DWORD AddressOfNames;           // +0x20
    DWORD AddressOfNameOrdinals;    // +0x24
}
```

Read them:
```
0:003> dd 76766d90+18 L5
76766da8  0000063a
76766dac  0000063a
76766db0  00079348
76766db4  00076c30
76766db8  0007ba38
```

```
NumberOfFunctions      = 0x63a
NumberOfNames          = 0x63a
AddressOfFunctions     = RVA 0x79348
AddressOfNames         = RVA 0x76c30
AddressOfOrdinals      = RVA 0x7ba38
```

### Step 5: Convert AddressOfNames RVA

```
766f0000 + 0076c30 = 76766c30
```

### Step 6: Examine Name Array

The name table is an array of RVAs. Dump first few:
```
0:003> dd 76766c30 L4
76766c30  00079348
76766c34  00079381
76766c38  000793b4
76766c3c  000793c3
```

### Step 7: Convert First Name RVA

First entry: 0x79348
```
766f0000 + 0079348 = 76769348
```

```
0:003> da 76769348
76769348 "AcquireSRWLockExclusive"
```

The chain:
```
AddressOfNames -> array of RVAs -> convert RVA to VA -> ASCII export name
```

### Step 8: What Shellcode Is Doing

Equivalent assembly:
```asm
mov eax,[edi+24h]    ; AddressOfNames RVA
add eax,ebx          ; eax = names table VA
mov esi,[eax+ecx*4]  ; name RVA at index ecx
add esi,ebx          ; name VA
```

### Step 9: Resolve Ordinal

AddressOfNameOrdinals = RVA 0x7ba38
```
766f0000 + 7ba38 = 7676ba38
```

Get ordinal:
```
ordinal = WORD [7676ba38 + ecx*2]
```

### Step 10: Resolve Function RVA

AddressOfFunctions = RVA 0x79348
```
766f0000 + 79348 = 76769348
```

Function RVA:
```
DWORD [76769348 + ordinal*4]
```

### Step 11: Convert Function RVA to VA

```
766f0000 + 000571f0 = 767471f0
```

Verify:
```
0:003> u 767471f0
KERNEL32!WinExec:
```

### What the Export Resolver Does (Pseudocode)

```c
for (i=0; i<NumberOfNames; i++)
{
    name_rva = AddressOfNames[i];
    name_va = kernel32_base + name_rva;
    if (hash(name_va) == target_hash)
    {
        ordinal = Ordinals[i];
        function_rva = AddressOfFunctions[ordinal];
        return kernel32_base + function_rva;
    }
}
```

---

## Concrete Session: shellcode-03.py

From WinDbg after saving exports:

```
(2974.32c): Break instruction exception - code 80000003 (first chance)
eax=76ddb9f0 ebx=76d60000 ecx=00000649 edx=76ddec60 esi=76ddba18 edi=76ddd33c
eip=02d4005c esp=0166f955 ebp=0166ff60 iopl=0         nv up ei pl nz na pe nc
```

At this point, ebx holds kernel32.dll base address.
`ebx+0x3c` to find `e_lfanew`, `ebx+e8` is PE header `PE\0\0` (0x00004550).

### Find Export Directory RVA

```
0:001> dd ebx+e8+78 L1
76d60160  0007b9f0
```

```
0:001> ? ebx+0007b9f0
Evaluate expression: 1994242544 = 76ddb9f0
```

Note: `eax = 76ddb9f0` from the assembly.

### Read Export Directory Fields

```
0:001> dd eax+14 L6
76ddba04  00000649 00000649 0007ba18 0007d33c
76ddba14  0007ec60 0001d810
```

Maps to:
```
+0x14  NumberOfFunctions     = 0x649
+0x18  NumberOfNames         = 0x649
+0x1C  AddressOfFunctions    = RVA 0x7ba18
+0x20  AddressOfNames        = RVA 0x7d33c
+0x24  AddressOfNameOrdinals = RVA 0x7ec60
```

### Retrieve AddressOfNames

```
0:001> dd eax+0x20 L1
76ddba10  0007d33c
0:001> ? ebx+0007d33c
Evaluate expression: 1994249020 = 76ddd33c
```

### Register Summary at This Point

```
eax = 76ddb9f0    ; Export Directory VA
ebx = 76d60000    ; kernel32 base
ecx = 00000649    ; NumberOfNames
edx = 76ddec60    ; AddressOfNameOrdinals VA
esi = 76ddba18    ; AddressOfFunctions VA
edi = 76ddd33c    ; AddressOfNames VA
```
