## Initial

Breack on ws2_32!rec and view the call stack.

```text
0:000> bp ws2_32!recv
0:000> g
ModLoad: 745e0000 74636000   C:\Windows\system32\mswsock.dll
ModLoad: 732b0000 732bf000   C:\Windows\SYSTEM32\kernel.appcore.dll
ModLoad: 76dc0000 76e7f000   C:\Windows\System32\msvcrt.dll
Breakpoint 1 hit
*** WARNING: Unable to verify checksum for C:\Users\dooley\Documents\OSED-Toolkit\Learning\Win32_X86\07_dep_bypass\bin\service.exe
eax=006fff14 ebx=00509258 ecx=000000b8 edx=0000000c esi=00401000 edi=00509258
eip=767823a0 esp=006ffed0 ebp=006ffef0 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
WS2_32!recv:
767823a0 8bff            mov     edi,edi
0:001> k
 # ChildEBP RetAddr      
00 006ffecc 00401335     WS2_32!recv
WARNING: Stack unwind information not available. Following frames may be wrong.
01 006ffef0 004013d4     service+0x1335
02 006fff04 0040187e     service+0x13d4
03 006fff28 00401032     service+0x187e
04 006fff38 00405343     service+0x1032
05 006fff70 7552d829     service+0x5343
06 006fff80 76ea254d     KERNEL32!BaseThreadInitThunk+0x19
07 006fffdc 76ea2521     ntdll!__RtlUserThreadStart+0x2b
08 006fffec 00000000     ntdll!_RtlUserThreadStart+0x1b
```


cmp
```text
0:004> u 004013d4
service+0x13d4:
004013d4 83c40c          add     esp,0Ch
004013d7 83f80c          cmp     eax,0Ch
004013da 7405            je      service+0x13e1 (004013e1)
004013dc 83c8ff          or      eax,0FFFFFFFFh
004013df eb76            jmp     service+0x1457 (00401457)
004013e1 8b450c          mov     eax,dword ptr [ebp+0Ch]
004013e4 8138564c5653    cmp     dword ptr [eax],53564C56h
004013ea 741d            je      service+0x1409 (00401409)
```

