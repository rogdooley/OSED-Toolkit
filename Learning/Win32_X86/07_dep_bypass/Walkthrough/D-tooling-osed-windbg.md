## Appendix D: Tooling — the `osed-windbg` command map

This lab uses the [`osed-windbg`](https://github.com/rogdooley/osed-windbg)
WinDbg-Preview JavaScript extension for every mechanical step, so you stay in the
`dx` evaluator instead of juggling Narly, rp++, and Metasploit. Load it once per
session:

```
.scriptload C:\path\to\osed-windbg\dist\osed.js
dx @$osed().help()                 ; list commands
dx @$osed().help("rop_suggest")    ; schema for one
```

Every phase of this walkthrough maps to one command. Substitute your module name
(`compression`) and bad-char set (`00 09 0a 0b 0c 0d 20`).

| Walkthrough step | Old tool | `osed-windbg` command |
| --- | --- | --- |
| Ch.1 module + mitigation survey | Narly `!nmod` | `dx @$osed().modules()` — ASLR/SafeSEH/DEP/CFG per module |
| Ch.1 filter to one module | `lm m compression` | `dx @$osed().modules("compression")` |
| Ch.1 PE / imports inspection | `dumpbin /imports` | `dx @$osed().sc.modules()` · `dx @$osed().sc.exports("compression","Virtual")` |
| Ch.4/5 first-look crash triage | manual `r` + `dds` | `dx @$osed().triage(8000, "00 09 0a 0b 0c 0d 20", "compression", 2048)` |
| Ch.5 build the pattern | `msf-pattern_create -l 2000` | `dx @$osed().pattern_create(2000)` |
| Ch.5 resolve the offset | `msf-pattern_offset -q <eip>` | `dx @$osed().pattern_offset(0x6a413969)` |
| Ch.6 bad-char comparison | manual byte array + `db` | `dx @$osed().badchars(esp, "00 09 0a 0b 0c 0d 20")` |
| Ch.3/9 general gadget hunt | `rp-win-x86.exe -f … -r 5` | `dx @$osed().rop_suggest("compression", 50)` |
| Ch.3/9 raw opcode search | `findstr` in rop.txt | `dx @$osed().find_bytes("compression","FF E4")` |
| Ch.9 semantic gadget query | manual grep | `dx @$osed().rop.scan("<rp++ line>")` then `dx @$osed().rop.query({ writes:["eax"], capability:"LOAD_REGISTER" })` |
| Ch.9 P1 resolve IAT slot | `dps compression!_imp__VirtualProtect` | `dx @$osed().sc.iat_ptr("compression.dll","VirtualProtect")` (slot + target) · `dx @$osed().sc.iat_find("VirtualProtect")` |
| Ch.10 P8 find a stack pivot | `findstr "mov esp"` | `dx @$osed().pivots("compression")` · `dx @$osed().add_esp("compression")` · `dx @$osed().retn("compression")` |
| Ch.11 build a NOP runway | `b"\x90"*N` | `dx @$osed().nop(16)` |
| Ch.11 encode shellcode past bad chars | `msfvenom -e shikata -b …` | `dx @$osed().encode("<hex>", "00 09 0a 0b 0c 0d 20")` |
| SEH extra-mile PPR search | Narly/`!py find-ppr` | `dx @$osed().seh_ppr("compression","00 09 0a 0b 0c 0d 20")` · `dx @$osed().seh()` |
| Any step — recover structured output | — | `dx @$osed().last_result()` · `dx @$osed().last_summary()` |

Two notes on using it well here:

- **`triage` is your Chapter 4–5 fast path.** One call reports whether you
  control EIP, the SEH chain, stack context, and a gadget summary — folding the
  crash survey, offset hint, and initial gadget census into a single command.
  Use it first, then drill in with `pattern_offset` and `badchars`.
- **`rop_template("VirtualProtect","compression")` can emit a PUSHAD skeleton**
  for you. We deliberately *don't* use it in Chapters 8–10 — the whole point is
  to build the frame by hand so you understand each primitive. Reach for the
  template only after you can construct the chain manually; then it's a
  time-saver, not a crutch. The semantic `rop.scan` / `rop.query` pair is the
  honest middle ground: it finds *candidates* by effect (`LOAD_REGISTER`,
  `WRITE_MEM`, …) but you still choose and verify each one.

> **Verify-in-WinDbg boxes still apply.** The extension resolves and suggests;
> it does not exempt you from confirming. After `sc.iat_ptr` gives a slot,
> `u poi(<slot>) L1` should still disassemble as `KERNEL32!VirtualProtectStub`.
> After `pivots` proposes a gadget, single-step it and watch ESP land on your
> frame. The tool removes typing, not understanding.

---

*Scope: defensive exploit-development practice against a lab target you built
and control. The methodology transfers; the specific addresses do not.*

---

[← Previous](C-challenges.md) · [Index](00-index.md)
