## 14. What ASLR would have broken

Every hardcoded address in this exploit — gadgets and the IAT slot — assumed
`compression.dll` loads at `0x61500000` every time. That held only because we
built it `/DYNAMICBASE:NO`.

Rebuild `compression.dll` with `/DYNAMICBASE` (ASLR on) and the exploit dies: the
first gadget address points at nothing. This is exactly why `helper.dll` was a
trap in Chapter 3 — great gadgets, useless because randomized.

Against a fully-ASLR'd target you would need one of:

- **A non-ASLR module** anywhere in the process (check `!nmod` first — often one
  poorly-linked DLL exists). Pin all gadgets + IAT to it and the problem reduces
  to what you just did.
- **An information leak** — a memory-disclosure primitive that reveals one
  pointer into a known module; subtract its static offset to recover the base,
  then compute every gadget/IAT address as `base + offset` at runtime. This is
  where format-string and OOB-read bugs become the linchpin.
- **Low-entropy corners** — partial EIP overwrite (low 12 bits are page-fixed),
  or 32-bit brute force against an auto-restarting service. Situational; not a
  plan on modern 64-bit.

The ROP machinery is unchanged once you can compute `base + offset`; ASLR adds a
*base-discovery* stage in front of the chain you already know how to build.
That's the next lab.

---

---

[← Previous](13-writeprocessmemory.md) · [Index](00-index.md) · [Next →](A-gadget-table.md)
