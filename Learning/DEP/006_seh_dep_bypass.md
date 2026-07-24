# Lesson Capture 006 — SEH Overflow with DEP Bypass

## Objective

Combine SEH handler overwrite with a ROP chain that disables DEP. This is the harder variant of lessons 003-005: instead of controlling a saved return address directly, the exploit controls the exception handler, and the ROP chain must account for the exception dispatcher's effect on the stack.

## Prerequisites from earlier lessons

- Registers versus memory (001)
- Machine state thinking (002)
- Fake function calls via ROP (003)
- VirtualProtect/VirtualAlloc frame construction (004)
- Runtime pointer arithmetic and badchar corrections (005)

## Two control scenarios

### Direct EIP overflow (lessons 003-005)

```text
[padding] [saved EIP] [ROP chain] [frame] [shellcode]
```

After the function returns, `ESP` points into the ROP chain. The chain runs immediately.

### SEH overflow (this lesson)

```text
[padding] [nSEH] [SEH handler] [ROP chain] [frame] [shellcode]
```

After the access violation, the OS exception dispatcher calls the SEH handler. `ESP` does not point where you left it. The exploit must go through an extra control transfer before the ROP chain begins.

## The SEH overwrite mechanism

An SEH record is two adjacent DWORDs on the stack:

```text
nSEH:     pointer to the next EXCEPTION_REGISTRATION
handler:  pointer to the exception handler function
```

When an exception fires:

1. The dispatcher walks the SEH chain.
2. It calls the handler function stored in the SEH record.
3. If the handler returns `ExceptionContinueExecution`, the dispatcher uses the nSEH pointer to find and potentially call the next handler.

If you overwrite the handler with a PPR gadget address, the dispatcher calls that gadget. The `pop;pop;ret` adjusts ESP so that `ret` loads `EIP` from the nSEH field — which you also control.

## Why `pop;pop;ret` lands on nSEH

When the exception dispatcher calls the handler, it pushes arguments onto the stack. At the handler entry point:

```text
ESP+00  return address (into dispatcher)
ESP+04  EXCEPTION_RECORD*
ESP+08  EstablisherFrame (pointer to the SEH record: nSEH)
ESP+0C  ContextRecord*
ESP+10  DispatcherContext*
```

`EstablisherFrame` at `ESP+08` points back to the nSEH field on the original stack.

After `pop;pop;ret`:

```text
pop reg   ; consumes ESP+00 (return address)
pop reg   ; consumes ESP+04 (EXCEPTION_RECORD*)
ret       ; EIP = [ESP+08] = EstablisherFrame = &nSEH
```

Execution now continues at the address stored in nSEH. But nSEH is on the stack — you control those bytes.

## nSEH: short jump, not a gadget address

In a direct EIP overflow, every controlled DWORD is either a gadget address, a constant for `POP`, or an API argument. In SEH exploitation, the nSEH field is different: it is executed as code.

The classic encoding:

```text
EB 06 90 90
```

- `EB 06` — short JMP forward 6 bytes (skips over the 4-byte SEH handler DWORD and lands on the first byte of the ROP chain area)
- `90 90` — NOP padding to fill the 4-byte nSEH field

After the short jump:

```text
[nSEH: EB 06 90 90] [SEH: PPR address] [landing zone → ROP chain starts here]
```

The 6-byte forward jump clears the 4 bytes of nSEH consumed by the jump instruction itself, plus the 4-byte SEH handler field, minus the 2 bytes of the JMP instruction. `6 = 4 (SEH field) + 2 (remaining nSEH bytes) - 0`. In practice, verify the exact landing offset in WinDbg.

## ESP after the exception dispatcher

This is the critical difference from a direct overflow. After the exception fires and the PPR gadget transfers control to nSEH, **ESP does not point into your controlled buffer at a predictable offset**. The exception dispatcher has built its own stack frames.

The first task of the ROP chain is to recover a known pointer into the controlled area. Common approaches:

### Approach A: stack pivot

If a gadget like `xchg eax,esp ; ret` or `mov esp,ebp ; ret` is available and a register happens to point near the controlled buffer, pivot directly.

### Approach B: ESP adjustment

If ESP is close to the controlled area but offset by a dispatcher-dependent delta, use `add esp,N ; ret` to slide ESP into the ROP chain proper.

### Approach C: push-ESP capture

Use a `push esp` sequence (as in lesson 004) to capture the current stack pointer into a register, then compute the offset to the controlled area.

In all cases, the first few gadgets after the short jump are about **establishing a known ESP**, not about building the VirtualProtect frame. This is overhead that direct EIP overflows do not have.

## Determining the ESP offset

At the breakpoint after the short jump lands:

```
0:000> r esp
0:000> dd esp L20
```

Find your controlled pattern bytes. The difference between ESP and the start of your ROP data is the correction value for the `add esp,N` gadget, or the base offset for the stack pivot.

The toolkit can help:

```
dx @$osed().triage(8000, "00 0A 0D", "target", 2048)
```

The STACK section shows the current ESP, and the shellcode candidate scan identifies controlled regions.

## SafeSEH filtering

Before calling the handler, the dispatcher checks if the handler address is in a SafeSEH-registered module. If the module has SafeSEH enabled and the handler address is not in the registered table, the call is blocked.

Consequences for gadget selection:

- The PPR gadget must come from a module with SafeSEH **disabled** (or not opted in).
- ASLR must also be disabled (or the module must not be rebased), because the handler address is embedded in the exploit buffer.
- After the PPR transfers control to nSEH and the ROP chain begins, subsequent gadgets face the same ASLR/badchar constraints as a direct overflow but do **not** need to be in a SafeSEH-disabled module — SafeSEH only filters the handler, not the rest of the chain.

```
dx @$osed().seh_ppr("target", "00 0A 0D")
```

The toolkit filters PPR results for SafeSEH status and badchars.

## Stack space constraints

In a direct EIP overflow, the ROP chain, API frame, and shellcode extend into the buffer after the saved return address. Space is usually generous.

In an SEH overflow, available space depends on:

1. The distance between the SEH record and the end of the overflowed buffer.
2. Whether the stack region past the buffer is still writable and accessible.

The PUSHAD technique (lesson 004) is especially valuable here because it constructs the VirtualProtect frame in 7 register-wide slots (28 bytes) plus the chain to populate those registers. A VirtualAlloc approach with explicit frame construction may consume more stack.

## The combined exploit structure

```text
Offset 0            Padding (A's or pattern)
Offset N            nSEH: EB 06 90 90 (short jump)
Offset N+4          SEH handler: PPR gadget address
Offset N+8          ROP chain begins
                      - establish known ESP (add esp,N or pivot)
                      - populate registers for VirtualProtect frame
                      - PUSHAD to build the call frame
                      - ret into VirtualProtect
Offset N+8+chain    NOP sled (optional)
Offset N+8+chain+N  Encoded shellcode
```

## Phase-by-phase state transitions

### Phase 0 — trigger and control transfer

| Step | EIP | ESP | Notes |
|---|---|---|---|
| Access violation | trap | dispatcher frame | OS takes over |
| Dispatcher calls handler | PPR address | dispatcher args | SafeSEH check passed |
| POP; POP; RET | nSEH address | dispatcher+0x0C | short jump about to execute |
| JMP +6 | ROP chain start | unchanged | first controlled instruction |

### Phase 1 — recover ESP

| Step | Goal |
|---|---|
| `add esp, <offset>` or pivot | ESP points into controlled ROP data |

### Phase 2 — VirtualProtect frame (same as lessons 004-005)

| Step | Goal |
|---|---|
| Resolve API from IAT | EAX = VirtualProtect |
| Compute lpAddress | stack region to mark executable |
| Load constants | dwSize, flNewProtect, lpflOldProtect |
| PUSHAD or explicit frame | call frame on stack |
| RET | EIP = VirtualProtect |

### Phase 3 — API return to shellcode

VirtualProtect marks the stack region executable. Its return address points to the shellcode. After the API returns, the shellcode runs.

## Verification with the toolkit

```text
; 1. After the crash, triage everything at once
dx @$osed().triage(8000, "00 0A 0D", "target", 2048)

; 2. Walk the SEH chain to confirm the overwrite
dx @$osed().seh()

; 3. Find PPR gadgets in SafeSEH-disabled, ASLR-off modules
dx @$osed().seh_ppr("target", "00 0A 0D")

; 4. Find the ESP adjustment gadget
dx @$osed().add_esp("target")

; 5. Scan for ROP gadgets to build the VirtualProtect frame
dx @$osed().rop_suggest("target", 50)
dx @$osed().rop_template("VirtualProtect", "target")

; 6. Encode the shellcode
dx @$osed().encode("fc e8 82 00 00 00...", "00 0A 0D")

; 7. After sending the exploit, verify the frame at API entry
dx @$osed().triage()
```

## Common mistakes

1. **Forgetting that ESP moved.** After the exception dispatcher, ESP is not where your overflow left it. The ROP chain must begin with ESP recovery.

2. **Using a PPR from a SafeSEH-enabled module.** The dispatcher blocks it silently. The exploit appears to do nothing.

3. **Short jump lands in the wrong place.** The `EB 06` constant assumes the SEH handler field is immediately after nSEH and the ROP chain follows immediately after that. If there is alignment padding or the layout differs, adjust the jump offset and verify in WinDbg.

4. **Not enough space after the SEH record.** If the vulnerable buffer is small, the ROP chain, frame, and shellcode may not fit. Consider a two-stage approach: a short first-stage chain that pivots to a larger controlled region elsewhere in memory.

5. **Badchars in the PPR address.** The PPR address is transmitted as raw bytes in the overflow. If any byte is filtered by the protocol, you need a different PPR from a different module.

## Exercises

### Exercise A — stack layout

Draw the stack from the buffer start through the shellcode. Label the nSEH, SEH, ESP correction, each ROP gadget's consumed DWORDs, the VirtualProtect frame, and the shellcode offset.

### Exercise B — ESP recovery

Given ESP = 0x0012FB34 after the short jump and ROP data starting at 0x0012FBAC, calculate the `add esp, N` value. Express it in hex and verify that no byte is a badchar.

### Exercise C — SafeSEH audit

Run `dx @$osed().modules()` and identify which modules have SafeSEH disabled and ASLR disabled. Explain why both conditions matter for the SEH handler but only ASLR matters for the rest of the ROP chain.

### Exercise D — space budget

If the controlled buffer is 512 bytes, the EIP/SEH offset is at byte 260, and the SEH record is 8 bytes: how many bytes remain for the ROP chain, frame, and shellcode? What is the minimum chain you can construct using the PUSHAD technique?

## Durable conclusions

- SEH exploitation adds one control-transfer layer (PPR → nSEH → short jump) before the ROP chain begins.
- The exception dispatcher relocates ESP. Recovering a known stack pointer is the first chain objective.
- SafeSEH is a constraint on the handler gadget, not on the ROP chain.
- The PUSHAD frame technique is compact enough for the tighter space budget.
- The verification method is the same: break at each transition, confirm registers and memory, verify the API call frame before checking whether the payload runs.
