## 1. Reconnaissance: what are we attacking?

Before a single packet, characterise the target statically and at runtime. You
are answering four questions: *What speaks? What mitigations are in force? What
modules share the address space? What do they import?*

### 1.1 The process and its modules

Start the service, attach WinDbg, and list modules:

```
0:000> lm
start    end        module name
00400000 0042e000   service    (deferred)       <- the vulnerable EXE, base 0x00400000      
00e20000 00e3c000   compression   (deferred)    <- no ASLR (we'll confirm) 
00e40000 00e56000   network    (deferred)       <- no ASLR (we'll confirm)     
01070000 01085000   crypto     (deferred)             
73340000 733e4000   apphelp    (deferred)             
75660000 75897000   KERNELBASE   (deferred)             
76b10000 76bad000   KERNEL32   (deferred)             
76bb0000 76c70000   RPCRT4     (deferred)             
76fd0000 77033000   WS2_32     (deferred)             
77770000 7790f000   ntdll      (pdb symbols)          C:\ProgramData\Dbg\sym\ntdll.pdb\EBAE1381C11394FF20DD5EFC34E32FD91\ntdll.pdb
78ae0000 78af5000   helper     (deferred)       <- no ASLR (we'll confirm) 
```

Five application modules in one process. That is your gadget/IAT universe;
system DLLs (ntdll, kernel32) are usually off-limits early because they are
ASLR'd and version-dependent.

### 1.2 Mitigations

```
dx @$osed().modules()

=== Modules ===
Module                                                                                       Base                Size        ASLR      DEP       SafeSEH   System  
-------------------------------------------------------------------------------------------  ------------------  ----------  --------  --------  --------  --------
<redacted>OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\service.exe                      0x00400000          0x2E000     disabled  enabled   disabled  no      
<redacted>OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\compression.dll                  0x00E20000          0x1C000     disabled  enabled   enabled   no      
<redacted>OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll                      0x00E40000          0x16000     disabled  enabled   enabled   no      
<redacted>OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\crypto.dll                       0x01070000          0x15000     disabled  enabled   enabled   no      
C:\Windows\SYSTEM32\apphelp.dll                                                              0x73340000          0xA4000     enabled   enabled   enabled   yes     
C:\Windows\System32\KERNELBASE.dll                                                           0x75660000          0x237000    enabled   enabled   enabled   yes     
C:\Windows\System32\KERNEL32.DLL                                                             0x76B10000          0x9D000     enabled   enabled   enabled   yes     
C:\Windows\System32\RPCRT4.dll                                                               0x76BB0000          0xC0000     enabled   enabled   enabled   yes     
C:\Windows\System32\WS2_32.dll                                                               0x76FD0000          0x63000     enabled   enabled   enabled   yes     
ntdll.dll                                                                                    0x77770000          0x19F000    enabled   enabled   enabled   no      
<redacted>OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\helper.dll                       0x78AE0000          0x15000     enabled   enabled   enabled   no  
```

Read this carefully. `helper` carries `*ASLR`; the others do not. Narly reads
the PE header, so DEP enforced via `/NXCOMPAT` may not show here — confirm DEP
empirically (Chapter 7). SafeSEH is off everywhere, which matters only if we go
the SEH route (we don't, in the main line).

> **Verify in WinDbg.** Cross-check statically too:
> `dumpbin /headers bin\helper.dll | findstr /i "dynamic"` should show
> *"Dynamic base"*; the same command on `compression.dll` should not.

### 1.3 Imports — the question nobody asks early enough

A gadget source is far more valuable if it also **imports the API you intend to
call**, because then it hands you a fixed IAT slot to resolve that API at
runtime. Check:

```
0:000> dx @$osed().sc.iat_ptr("compression.dll", "VirtualAlloc")
@$osed().sc.iat_ptr("compression.dll", "VirtualAlloc")                 : [slot: 0x00E32010 | target: 0x76B35680 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualAlloc | status: ok]
    length           : 0x1
    [0x0]            : slot: 0x00E32010 | target: 0x76B35680 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualAlloc | status: ok
0:000> dx @$osed().sc.iat_ptr("compression.dll", "VirtualProtect")
@$osed().sc.iat_ptr("compression.dll", "VirtualProtect")                 : [slot: 0x00E32014 | target: 0x76B36570 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualProtect | status: ok]
    length           : 0x1
    [0x0]            : slot: 0x00E32014 | target: 0x76B36570 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualProtect | status: ok
0:000> dx @$osed().sc.iat_ptr("compression.dll", "HeapAlloc")
@$osed().sc.iat_ptr("compression.dll", "HeapAlloc")                 : [slot: 0x00E320A4 | target: 0x777AA380 | module: ntdll.dll | symbol: HeapAlloc | status: ok]
    length           : 0x1
    [0x0]            : slot: 0x00E320A4 | target: 0x777AA380 | module: ntdll.dll | symbol: HeapAlloc | status: ok
0:000> dx @$osed().sc.iat_ptr("compression.dll", "VirtualFree")
@$osed().sc.iat_ptr("compression.dll", "VirtualFree")                 : [slot: 0x00E32018 | target: 0x76B35F80 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualFree | status: ok]
    length           : 0x1
    [0x0]            : slot: 0x00E32018 | target: 0x76B35F80 | module: C:\Windows\System32\KERNEL32.DLL | symbol: VirtualFree | status: ok
0:000> dx @$osed().sc.iat_ptr("network.dll", "VirtualAlloc")
@$osed().sc.iat_ptr("network.dll", "VirtualAlloc")                 : [Error: No IAT slot found for "VirtualAlloc" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.]
    length           : 0x1
    [0x0]            : Error: No IAT slot found for "VirtualAlloc" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.
```

`compression.dll` imports **both** `VirtualAlloc` and `VirtualProtect` — because
its worker legitimately allocates and reprotects a scratch arena. Note this;
it decides a lot in Chapter 3.

By contrast:

```
0:000> dx @$osed().sc.iat_ptr("network.dll", "VirtualAlloc")
@$osed().sc.iat_ptr("network.dll", "VirtualAlloc")                 : [Error: No IAT slot found for "VirtualAlloc" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.]
    length           : 0x1
    [0x0]            : Error: No IAT slot found for "VirtualAlloc" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.
0:000> dx @$osed().sc.iat_ptr("network.dll", "VirtualProtect")
@$osed().sc.iat_ptr("network.dll", "VirtualProtect")                 : [Error: No IAT slot found for "VirtualProtect" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.]
    length           : 0x1
    [0x0]            : Error: No IAT slot found for "VirtualProtect" in C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\network.dll.
```

Neither noise DLL imports a protection API.

---

---

[Index](00-index.md) · [Next →](02-find-the-bug.md)
