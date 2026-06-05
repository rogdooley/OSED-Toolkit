# Walk Export Table

Let’s manually walk a real export table the same way your shellcode does:

1. Find kernel32 base
2. Find PE header
3. Find Export Directory
4. Find AddressOfNames
5. Convert RVA → VA
6. Read exported names
7. Find a target function
8. Resolve its actual address


⸻

Step 1: Get kernel32 Base

Suppose you’ve already found:
```
ebx = 766f0000
```
Kernel32 base:
```
KERNEL32 = 0x766f0000
```
⸻

Step 2: Find PE Header

At module base:
```
0:003> dd ebx L1
766f0000  00905a4d
```
That’s:
```
MZ
```
Read e_lfanew:
```
0:003> dd ebx+3c L1
766f003c  000000f8
```
Meaning:
```
PE Header RVA = 0xF8
```
Convert:
```
PE Header VA
=
0x766f0000 + 0xF8
=
0x766f00f8
```
Verify:
```
0:003> dd 766f00f8 L1
766f00f8  00004550
PE\0\0
```


⸻

Step 3: Locate Export Directory RVA

For PE32:
```
Optional Header
+
0x78
```
contains:
```
IMAGE_DIRECTORY_ENTRY_EXPORT
```
Your shellcode usually does:
```
mov eax,[ebx+3c]
add eax,ebx
mov eax,[eax+78]
```
Let’s inspect:
```
0:003> dd 766f00f8+78 L1
766f0170  00076d90
```
Export Directory RVA:
```
0x76d90
```
Not an address yet.

Convert:
```
Export Directory VA
=
766f0000 + 76d90
=
76766d90
```
Verify:
```
0:003> dd 76766d90
```
⸻

Step 4: Read IMAGE_EXPORT_DIRECTORY

Structure:
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
}
```
Offsets:
```
+0x18 NumberOfFunctions
+0x1C NumberOfNames
+0x20 AddressOfFunctions
+0x24 AddressOfNames
+0x28 AddressOfNameOrdinals
```
Read them:
```
0:003> dd 76766d90 L12
```
or individually:
```
0:003> dd 76766d90+18 L5
```
You might see:
```
76766da8  0000063a
76766dac  0000063a
76766db0  00079348
76766db4  00076c30
76766db8  0007ba38
```
Meaning:
```
NumberOfFunctions      = 0x63a
NumberOfNames          = 0x63a
AddressOfFunctions     = RVA 0x79348
AddressOfNames         = RVA 0x76c30
AddressOfOrdinals      = RVA 0x7ba38
```
⸻

Step 5: Convert AddressOfNames RVA

You recently hit exactly this in WinDbg.

RVA:
```
0x76c30
```
Convert:
```
766f0000
+0076c30
---------
76766c30
```
VA:
```
76766c30
```
⸻

Step 6: Examine Name Array

The name table is an array of RVAs.

Dump first few:
```
0:003> dd 76766c30 L4
```
Example:
```
76766c30  00079348
76766c34  00079381
76766c38  000793b4
76766c3c  000793c3
```
Each entry is another RVA.

⸻

Step 7: Convert First Name RVA

First entry:
```
0x79348
```
Convert:
```
766f0000
+0079348
---------
76769348
```
Now examine:
```
0:003> da 76769348
```
You previously got:
```
76769348 "AcquireSRWLockExclusive"
```
Perfect.

That proves:
```
AddressOfNames
    ↓
array of RVAs
    ↓
convert RVA→VA
    ↓
ASCII export name
```
⸻

What Shellcode Is Doing

Equivalent assembly:
```
mov eax,[edi+24h]
add eax,ebx
```
Now:
```
eax = names table VA
```
Then:
```
mov esi,[eax+ecx*4]
```
Gets:
```
name RVA
```
Then:
```
add esi,ebx
```
Converts:
```
name VA
```
Now:
```
esi -> "AcquireSRWLockExclusive"
```
⸻

Step 8: Find Matching Function

Suppose your hash matches:
```
WinExec
```
Current index:
```
ecx = 0x257
```
(Not the real index, just an example.)

Use the same index in the ordinal table.

⸻

Step 9: Resolve Ordinal

Read:
```
AddressOfNameOrdinals
=
RVA 0x7ba38
```
Convert:
```
766f0000 + 7ba38
=
7676ba38
```
Get ordinal:
```
ordinal =
WORD [7676ba38 + ecx*2]
```
Example:
``
ordinal = 0x1e5
``
⸻

Step 10: Resolve Function RVA

AddressOfFunctions:
```
RVA 0x79348
```
Convert:
```
766f0000 + 79348
=
76769348
```
Function RVA:
```
DWORD [76769348 + ordinal*4]
```
Example:
```
0x571f0
```
⸻

Step 11: Convert Function RVA → VA
```
766f0000
+00571f0
---------
767471f0
```
Final result:
```
767471f0
```
Check:
```
0:003> u 767471f0
```
You should see:
```
KERNEL32!WinExec:
```
or whatever function matched.

⸻

What Your Export Resolver Actually Does

Conceptually:
```c
for (i=0; i<NumberOfNames; i++)
{
    name_rva = AddressOfNames[i];
    name_va = kernel32_base + name_rva;
    if (hash(name_va) == target_hash)
    {
        ordinal = Ordinals[i];
        function_rva =
            AddressOfFunctions[ordinal];
        return kernel32_base +
               function_rva;
    }
}
```

