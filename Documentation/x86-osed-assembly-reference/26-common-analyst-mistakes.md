# 26. Common Analyst Mistakes

1. **Confusing an address with the data at that address.**
   `EAX = 0x0012FF80` means EAX holds the number 0x0012FF80. `[EAX]` is the
   data stored at that address. These are not the same thing.

2. **Forgetting little-endian storage.**
   The address `0x625011AF` is stored as bytes `AF 11 50 62`. Forgetting this
   when reading `db` output or constructing payloads produces wrong addresses.

3. **Assuming EBP is always a frame pointer.**
   Optimized code uses EBP as a general register (FPO). Treating EBP-relative
   offsets as frame references in FPO code produces nonsense.

4. **Reading pseudocode without checking assembly.**
   IDA's decompiler is a useful approximation. It can misrepresent casts, loop
   boundaries, and calling conventions. Verify against the actual instructions.

5. **Forgetting that CALL pushes a return address.**
   `call target` decrements ESP by 4 and writes the return address before
   transferring control. The callee's ESP is 4 less than the caller's ESP
   at the call site.

6. **Forgetting that RET consumes 4 bytes.**
   `ret` pops EIP from [ESP] and increments ESP by 4. This stack movement must
   be accounted for in ROP chain layout.

7. **Misunderstanding RET N.**
   `ret 0x10` does NOT pop 0x10 bytes before reading EIP. It pops EIP first
   (ESP += 4), then adds 0x10 to ESP (ESP += 0x10). Total: ESP += 0x14. The
   0x10 cleans the arguments, not the return address.

8. **Treating LEA as a dereference.**
   `lea eax, [ebx+4]` computes EBX+4 and stores it in EAX. It does NOT read
   memory. `mov eax, [ebx+4]` reads memory.

9. **Confusing signed and unsigned branches.**
   `ja` is unsigned above; `jg` is signed greater. After `cmp eax, 0x80`, they
   behave differently if EAX contains a value with the high bit set.

10. **Ignoring gadget side effects.**
    A gadget like `pop eax; pop ecx; ret` consumes 12 bytes of stack (two
    values + return address), not 8. The extra pop clobbers a register and
    consumes a stack slot.

11. **Forgetting stack movement caused by POP.**
    Each `pop` advances ESP by 4. A gadget with three pops before `ret`
    consumes 16 bytes of stack total (12 for pops + 4 for ret).

12. **Assuming PUSHAD pushes in memory order.**
    PUSHAD pushes EAX first (deepest) and EDI last (on top). The CPU push
    order and the resulting memory layout are inverted because the stack grows
    downward.

13. **Forgetting writable storage for VirtualProtect.**
    The `lpflOldProtect` parameter must point to writable memory. If it points
    to non-writable memory, VirtualProtect fails silently. A writable .data
    section address or stack address works.

14. **Using an RVA as a VA.**
    An RVA is an offset from the module base. Using it as an absolute address
    accesses the wrong memory. Always compute `VA = base + RVA`.

15. **Assuming a module is non-ASLR without checking.**
    Verify with `!nmod` or by checking the PE header's DllCharacteristics for
    the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag (0x0040).

16. **Assuming all stack memory is currently committed.**
    The full stack reservation (typically 1 MB) is virtual address space. Only
    a portion is committed. Guard pages extend the commit on demand. Writing
    far below ESP without probing can cause a stack overflow exception.

17. **Confusing stack reservation with active stack frames.**
    A thread's stack size is not determined by the number of functions in the
    executable. It is a fixed reservation. Active frames are created
    dynamically as functions are called and destroyed as they return.

18. **Assuming a function knows how its arguments reached the stack.**
    A stdcall function executes `ret N` regardless of whether it was reached
    by `call`, a ROP gadget, or an overwritten return address. The CPU follows
    the ABI mechanically.
