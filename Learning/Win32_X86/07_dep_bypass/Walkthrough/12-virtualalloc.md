## 12. Chapter 2 API: VirtualAlloc

Everything above is API-shaped, not API-specific. To retarget `VirtualAlloc`,
change three things:

- **IAT slot** — resolve `compression!_imp__VirtualAlloc` instead of VP (it is
  imported too).
- **Frame** — `VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)`:
  four args, and crucially **no `_Out_` pointer**, so P7 disappears.
  - `lpAddress` = your shellcode page (calling `MEM_COMMIT` on an
    already-committed page just changes its protection — same effect as VP).
  - `dwSize` = `0x201`.
  - `flAllocationType` = `MEM_COMMIT` = `0x1000` → build with split-add
    `0x80808080 + 0x7F7F8F80`.
  - `flProtect` = `0x40` → split-add as in P6.
- **Return semantics** — VirtualAlloc is also stdcall/4 args (`ret 0x10`), so the
  pivot and fake-frame logic are identical.

> **The abstraction to internalise.** DEP does not care *how* a page became
> executable. The OS only observes: `RW → (some API) → RWX → ret → execute`.
> Whether that API is VirtualProtect, VirtualAlloc, or `NtProtectVirtualMemory`
> is almost incidental. The workflow — resolve import, patch placeholders, pivot,
> return — is the reusable skill; the API is a detail. This is why a
> VirtualAlloc chain and our VirtualProtect chain are ~90% the same code.

Build it as a second exercise; you will reuse most gadgets from Chapter 9.

---

---

[← Previous](11-landing-shellcode.md) · [Index](00-index.md) · [Next →](13-writeprocessmemory.md)
