## Appendix C: Challenges

Work these before reading Appendix B's corresponding lines.

1. **Build `0x1000` with no null bytes.** You need `MEM_COMMIT = 0x1000` for the
   VirtualAlloc chapter. There are at least three ways: (a) split-add two
   null-free operands; (b) `neg` its two's complement — but check whether
   `0xFFFFF000` is null-free first; (c) shift a small value left. Pick one,
   justify it, then compare with Chapter 12.

2. **Find an alternative stack-copy for P0.** `push esp ; ... ; pop esi ; ret`
   is one way to get ESP into ESI. Search your `rop.txt` for a *different*
   sequence achieving the same. Reject any that end in `call`/`jmp`. Verify your
   pick in WinDbg.

3. **Retarget to VirtualAlloc.** Convert Appendix B to a VirtualAlloc frame
   (drop P7, add `flAllocationType`). Reuse every gadget you can. Confirm
   `!vprot` shows RWX after.

4. **WriteProcessMemory cave hunt.** Find a ≥ 200-byte run of executable padding
   in `compression.dll` (look for `int3`/`nop` fill between functions, or a
   `.text` gap). Prove it is executable (`!vprot`) and stable across restarts.

5. **Turn ASLR on.** Rebuild `compression.dll` `/DYNAMICBASE`, watch the exploit
   break, and write one paragraph on exactly which dword failed first and why.

---

---

[← Previous](B-annotated-chain.md) · [Index](00-index.md) · [Next →](D-tooling-osed-windbg.md)
