# VulnSvc: A Complete DEP-Bypass Walkthrough

**From source, to crash, to a working ROP exploit — earning every decision.**

This is a full-length exploit-development walkthrough against `service.exe`, the
deliberately vulnerable 32-bit Windows service you built in `BUILD.md`. It is
written to teach *judgement*, not to hand you a finished script. Every gadget is
earned through an explicit sequence: **problem → reasoning → search → candidate
gadgets → rejected alternatives → chosen gadget → verify → observe stack state →
repeat.** By the time you reach the appendix, the complete chain should feel
inevitable rather than magical.

### How to read this

- **Design decision** boxes mark forks in the road and explain the choice.
- **Verify in WinDbg** boxes give the exact commands to confirm each step on
  *your* build.
- Addresses shown in narrative (e.g. `compression+0x1234`) are from **one
  reference build**. Yours will differ — the whole point of building it yourself
  is that you rederive them with the exact `findstr` searches shown. A fill-in
  **Gadget Table** (Appendix A) and `exploit/exploit.py` are structured so your
  addresses drop straight in.

### Toolchain assumed

WinDbg Preview with the [`osed-windbg`](https://github.com/rogdooley/osed-windbg)
JavaScript extension (`.scriptload dist\osed.js`) — it covers module/mitigation
triage, pattern & offset, bad-char comparison, gadget scanning, IAT resolution,
and shellcode encoding from the `dx` evaluator (full command map in Appendix D).
Python 3 to drive the exploit, and a throwaway Windows VM you can crash and
restart. `rp++` is optional — only if you want to feed raw gadgets into
`@$osed().rop.scan` for semantic queries.
---

## Table of contents

1. [Reconnaissance: what are we attacking?](01-recon.md)
2. [Finding the bug: follow bytes, not function names](02-find-the-bug.md)
3. [Choosing a gadget source: which module?](03-choosing-a-gadget-source.md)
4. [Triggering the crash](04-triggering-the-crash.md)
5. [Controlling EIP: offset and register survey](05-controlling-eip.md)
6. [Bad characters](06-bad-characters.md)
7. [Proving DEP, and why `jmp esp` is dead](07-proving-dep.md)
8. [Strategy: the fake frame and the plan](08-strategy.md)
9. [Building the VirtualProtect chain, primitive by primitive](09-building-the-chain.md)
10. [Firing the call and the "don't debug two problems" discipline](10-firing-and-discipline.md)
11. [Landing real shellcode](11-landing-shellcode.md)
12. [Chapter 2 API: VirtualAlloc](12-virtualalloc.md)
13. [Chapter 3 API: WriteProcessMemory](13-writeprocessmemory.md)
14. [What ASLR would have broken](14-aslr-outlook.md)
15. [Appendix A: gadget table (fill-in)](A-gadget-table.md)
16. [Appendix B: the complete annotated chain](B-annotated-chain.md)
17. [Appendix C: challenges](C-challenges.md)
18. [Appendix D: tooling — the osed-windbg command map](D-tooling-osed-windbg.md)

---

