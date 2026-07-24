# Chapter 15 — SEH + DEP Bypass

This chapter covers the second exploit path in VulnSvc: the `OP_CONFIG_IMPORT`
handler, which wraps its parse in `__try/__except`. Instead of overwriting a
saved return address, the overflow overwrites an SEH registration record. The
DEP bypass is still VirtualProtect via ROP, but the control-transfer path is
different and harder.

Read `Learning/DEP/006_seh_dep_bypass.md` for the conceptual foundation. This
chapter is the hands-on application.

## Prerequisites

- Completed the direct-EIP exploit (Chapters 1-11).
- Understand SEH registration, `pop;pop;ret`, and short jumps from lesson 006.

## 15.1 — The new attack surface

`OP_CONFIG_IMPORT` (opcode `0x0022`) calls `parse_config_import`, which:

1. Registers an SEH handler via `__try/__except`.
2. Copies `len` bytes of attacker body into a 256-byte stack buffer with
   `memcpy` — **no bounds check**.
3. Reads through a pointer derived from the buffer data (`*(int *)buf`).
4. When the buffer is overflowed, step 3 reads corrupted data and triggers an
   access violation.
5. The exception dispatcher walks the SEH chain and finds the overwritten
   handler.

## 15.2 — Trigger and confirm

```bash
python solutions/exploit_seh_dep.py <ip> trigger
```

In WinDbg after the crash:

```
!exchain
```

If the SEH record is overwritten, you will see `41414141` in the handler
field. If the crash looks different (EIP = 41414141 directly), the overflow
may be smashing the saved return address before reaching the SEH record —
adjust the overflow length.

## 15.3 — Find the SEH offset

```bash
python solutions/exploit_seh_dep.py <ip> pattern
```

After the crash:

```
!exchain
```

Note the handler value (e.g., `39694238`). Then:

```
msf-pattern_offset -q 39694238
```

That gives you `OFFSET_TO_SEH`. Set `OFFSET_TO_NSEH = OFFSET_TO_SEH - 4` in
the script.

## 15.4 — Prove SEH control

Update `OFFSET_TO_NSEH` in the script and run:

```bash
python solutions/exploit_seh_dep.py <ip> seh
```

After the crash:

```
!exchain
```

Expect: handler = `43434343`, nSEH = `42424242`. If not, recheck the offset.

## 15.5 — Find the PPR gadget

The PPR gadget must come from a module with:

- SafeSEH **disabled** (or not opted in)
- ASLR **disabled**
- No bad characters in the address

Use the toolkit:

```
dx @$osed().seh_ppr("compression", "00 09 0A 0B 0C 0D 20")
```

Or use `rp++`:

```
rp-win-x86.exe -f compression.dll -r 3 | findstr "pop .* pop .* ret"
```

Select a `pop reg; pop reg; ret` sequence. The specific registers do not
matter — both pops discard dispatcher arguments.

## 15.6 — Determine the ESP correction

Set `G_PPR` in the script, update nSEH to `EB 06 90 90`, and set the SEH
handler to the PPR address. Send a recognizable pattern (e.g., `"DDDD"` repeated)
in the ROP area. Break on the PPR gadget:

```
bp <PPR address>
g
```

After the PPR executes (`pop;pop;ret`), EIP lands on nSEH. The short jump
(`EB 06`) skips forward 6 bytes into the ROP area. Step through:

```
p
p   ; now at the ROP landing zone
r esp
```

Compare ESP to where your controlled ROP data starts in memory. The difference
is the value for `G_ADD_ESP_OFFSET` — the `add esp, N` gadget's correction.

Find the gadget:

```
dx @$osed().add_esp("compression")
```

## 15.7 — Build and verify the chain

The ROP chain is structurally identical to the direct-EIP chain with one
prepended phase:

```text
Phase 0:  add esp, N ; ret     (recover ESP into controlled area)
Phase 1:  push esp ; ...       (capture ESP)
Phase 2:  resolve VirtualProtect from IAT
Phase 3:  store API address into frame[0]
Phase 4-8: populate remaining frame fields
Phase 9:  pivot and fire
```

Verify at each transition:

```
bp <add_esp gadget>           ; Phase 0
bp <stackptr gadget>          ; Phase 1
bp <deref gadget>             ; Phase 2: EAX should become VirtualProtect
bp <VirtualProtect>           ; final: dd esp L6 to check the call frame
```

## 15.8 — Differences from the direct-EIP path

| Aspect | Direct EIP | SEH + DEP |
|---|---|---|
| Control transfer | `ret` pops controlled EIP | Exception dispatcher calls overwritten handler |
| First controlled instruction | First ROP gadget | Short jump at nSEH |
| ESP at chain start | Predictable (into controlled buffer) | Relocated by exception dispatcher |
| Extra overhead | None | PPR + short jump + ESP recovery |
| PPR constraint | N/A | Must be in SafeSEH-disabled module |
| Stack space | Everything after saved EIP | Everything after SEH record |
| Trigger | Function return | Access violation |

## 15.9 — Common mistakes

1. **Forgetting that the exception dispatcher relocates ESP.** The first ROP
   gadget must be ESP recovery, not the VirtualProtect frame setup.

2. **Using a PPR from a SafeSEH-enabled module.** The dispatcher silently
   blocks it. Nothing happens.

3. **Wrong short-jump offset.** `EB 06` assumes nSEH and SEH are contiguous
   and the ROP data immediately follows. Verify in the debugger.

4. **Not enough space.** The ROP chain, fake frame, and shellcode must all
   fit after the SEH record. Budget carefully.

5. **Confusing the two exploit paths.** `OP_CONFIG_SET` overwrites saved EIP.
   `OP_CONFIG_IMPORT` overwrites the SEH record. They use the same gadget
   table and VirtualProtect frame construction, but different control-transfer
   mechanics.

## Exercises

### Exercise A — offset verification

Run the `pattern` mode and recover `OFFSET_TO_NSEH`. Then manually calculate:
buffer size (256) + saved registers + other locals + SEH record position.
Does the calculated offset match the pattern result? If not, why?

### Exercise B — PPR selection

List all PPR gadgets in `compression.dll`. For each one, check:
- Does the address contain bad characters?
- Is the module SafeSEH-disabled?
- Does it matter which registers the pops target?

### Exercise C — ESP recovery alternatives

The walkthrough uses `add esp, N; ret`. List two alternative ESP recovery
strategies (from lesson 006) and explain when each would be preferred.

### Exercise D — space budget

The overflow buffer is 256 bytes. The SEH record is at offset N. Calculate
how many bytes remain for the ROP chain, fake frame, NOP sled, and shellcode.
Compare this to the direct-EIP exploit's available space and explain the
tradeoff.
