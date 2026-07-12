## 3. Choosing a gadget source: which module?

This is the highest-leverage decision in the whole exploit, and the one most
tutorials skip by simply announcing a module. Do not accept a module; *derive*
it. You have five candidates. Score each against three requirements:

1. **Predictable base** — no ASLR, or you cannot hardcode gadget addresses.
2. **Bad-char-free addresses** — every gadget address you use travels through
   the vulnerable `%s`, so it must avoid the bad-char set (Chapter 6: notably
   `0x00`).
3. **Imports the API you'll call** — so you get a fixed IAT slot to resolve it.

### 3.1 The elimination

**`service.exe` — REJECTED (bad-char addresses).** No ASLR, tempting. But its
image base is `0x00400000` and it spans `0x00400000–0x0045ffff`. *Every* address
in it has a `0x00` high byte:

```
0x0041F210  →  bytes 10 F2 41 00   (little-endian on the wire: 10 F2 41 00)
0x0045A012  →  bytes 12 A0 45 00
```

`0x00` is a bad character (it terminates the `%s`). Try three gadget addresses
and you will notice the pattern: they all start with `00`. You cannot source a
single gadget from the main executable. *(This is the classic
default-image-base problem: a vulnerable EXE at `0x00400000` is unusable as a
gadget source, forcing you to a companion DLL.)*

**`helper.dll` — REJECTED (ASLR).** You will find it first and love it: clean
`pop eax ; ret`, `mov [esi], eax ; ret`, `xchg eax, ebp ; ret`. Then you restart
the service and every address moved:

```
run 1:  helper base 0x62000000   gadget 0x6200A1B0
run 2:  helper base 0x008E0000   gadget 0x008EA1B0   ← moved
```

Gadget quality is irrelevant if you cannot predict the base. Reject on ASLR
alone. **Lesson: quality never overrides predictability.**

**`crypto.dll` — REJECTED (thin, no useful imports).** No ASLR, fixed base — so
far so good. But it is a small `/Od` build: poor gadget density, and it imports
no `VirtualAlloc`/`VirtualProtect`, so it gives you no IAT slot to resolve your
API. Necessary properties present, sufficient ones absent.

**`network.dll` — VIABLE BUT INFERIOR.** No ASLR, `/O2`, genuinely decent
gadgets and a predictable base. The catch is imports: it pulls in `ws2_32`
(recv/send/htons) but **not** a protection API. You *could* use it purely for
gadgets and borrow the IAT slot from another module — but now you are juggling
two modules for gadgets vs. IAT resolution. More moving parts, no benefit.

**`compression.dll` — CHOSEN.**

```
✓ No ASLR (base fixed at 0x61500000)
✓ Addresses start 0x61.. / 0x615x.. → no 0x00, no 0x0a/0x0d/0x20 in the high byte
✓ Imports BOTH VirtualAlloc and VirtualProtect → fixed IAT slots for either API
✓ /O2 build with checksum/compression byte-loops → excellent gadget density
```

### 3.2 The decision, as a table

| Module | No ASLR | Bad-char-free addrs | Imports VA/VP | Gadget density | Verdict |
|---|---|---|---|---|---|
| service.exe | ✓ | ✗ (`0x00` high byte) | — | ok | **reject** |
| helper.dll | ✗ (ASLR) | ✓ | ✓ | excellent | **reject** |
| crypto.dll | ✓ | ✓ | ✗ | poor | **reject** |
| network.dll | ✓ | ✓ | ✗ | good | viable, inferior |
| **compression.dll** | ✓ | ✓ | ✓ | excellent | **CHOSEN** |

> **Design decision.** You did not learn *which* module to use — you learned
> *how to choose one*. On the next Windows target the modules change; the
> scoring does not. Module selection is a decision you make on nearly every
> Windows exploit, whereas the exact gadgets change every binary. This is the
> more valuable skill.

Generate gadgets from the winner:

```
copy bin\compression.dll .
rp-win-x86.exe -f compression.dll -r 5 > rop.txt
```

`-r 5` caps gadgets at five instructions; longer ones almost always drag in a
`call`/`jmp` that breaks the chain.

---

---

[← Previous](02-find-the-bug.md) · [Index](00-index.md) · [Next →](04-triggering-the-crash.md)
