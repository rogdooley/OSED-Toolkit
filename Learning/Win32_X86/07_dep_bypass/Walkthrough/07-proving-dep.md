## 7. Proving DEP, and why `jmp esp` is dead

Before building ROP, prove to yourself that the classic technique is actually
blocked here — understanding *why* motivates the whole chain.

Pre-DEP, you would drop shellcode on the stack and redirect EIP to a `jmp esp`
in some module. Try the essence of that and watch it fail:

```
0:000> !vprot esp
    BaseAddress:  0133e000
    Protect:      00000004  PAGE_READWRITE          ← writable, NOT executable
0:000> ed esp 90909090        ; write NOPs on the stack
0:000> r eip = esp            ; point EIP at them
0:000> p
(xxxx.xxxx): Access violation - code c0000005      ← DEP blocks execution
0133e320 90              nop
```

The page is `PAGE_READWRITE`. The CPU's NX bit refuses to execute it. Because we
compiled `service.exe` `/NXCOMPAT`, DEP is **on and permanent** for the process —
you cannot flip it off with `NtSetInformationProcess`. The only path is to make a
page executable through a legitimate API, using code that already exists. That is
ROP.

> **If DEP were *not* compiled in** (a `/NXCOMPAT`-less target), you would enable
> it externally to practise: Windows Security → App & browser control → Exploit
> protection → Program settings → add `service.exe` → override **DEP = On**, then
> restart. Narly still won't show it (it reads the header), so you would confirm
> with the NOP-on-stack test above. Here `/NXCOMPAT` already did it for you.

---

---

[← Previous](06-bad-characters.md) · [Index](00-index.md) · [Next →](08-strategy.md)
