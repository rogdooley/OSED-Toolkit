## Step through with shellcode-03.py

From Windbg after saving exports



```txt
(2974.32c): Break instruction exception - code 80000003 (first chance)
eax=76ddb9f0 ebx=76d60000 ecx=00000649 edx=76ddec60 esi=76ddba18 edi=76ddd33c
eip=02d4005c esp=0166f955 ebp=0166ff60 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
02d4005c cc              int     3
0:001> dd ebx L1
76d60000  00905a4d
0:001> dd ebx+3c L1
76d6003c  000000e8
0:001> dd ebx+e8 L1
76d600e8  00004550
```

At this point, ebx is holding kernel32.dll base address.
`ebx+0x3c` to find `e_lfanew`
`ebx+e8` is PE header 'PE\0\0' eg 00004550

### Find Export Directory RVA

```
0:001> dd ebx+e8+78 L1
76d60160  0007b9f0
```

```
0:001> ? ebx+0007b9f0
Evaluate expression: 1994242544 = 76ddb9f0
```

Note: `eax = 76ddb9f0` from the assembly

```
0:001> dd eax+14 L6
76ddba04  00000649 00000649 0007ba18 0007d33c
76ddba14  0007ec60 0001d810
```

Translates to:
```C
DWORD Base;                   // +0x10
DWORD NumberOfFunctions;      // +0x14
DWORD NumberOfNames;          // +0x18
DWORD AddressOfFunctions;     // +0x1C
DWORD AddressOfNames;         // +0x20
DWORD AddressOfNameOrdinals;  // +0x24
```

To retrieve the AddressOfNames
```
dd eax+20 L1
```

```
0:001> dd eax+0x20 L1
76ddba10  0007d33c
0:001> ? ebx+0007d33c
Evaluate expression: 1994249020 = 76ddd33c
```

```
edi = 76ddd33c
```

```
eax = 76ddb9f0    ; Export Directory VA
ebx = 76d60000    ; kernel32 base
ecx = 00000649    ; NumberOfNames
edx = 76ddec60    ; AddressOfNameOrdinals VA
esi = 76ddba18    ; AddressOfFunctions VA
edi = 76ddd33c    ; AddressOfNames VA
```