# Roadmap — Modules 02 through 05

Module 01 is the only module currently built out. The rest is sketched here
so you can see where the curriculum is going. Each entry lists the *driving
questions* the module's exercises will be built around, not just topics.

When a module gets fleshed out, the questions become exercises with
verification steps, the same shape as Module 01.

## Module 02 — Exploit Mechanics

Premise: you have EIP control. Now what?

### Driving questions

- **Where in memory will your shellcode live, and how does EIP get there?**
  Direct jump, jmp esp, egghunter, SEH overwrite — each is an answer to a
  specific constraint. Which constraint forces which answer?
- **What makes a return address survive a reboot?** Module base + RVA vs
  absolute address. ASLR-on modules vs ASLR-off modules. Which DLLs to
  trust.
- **What goes wrong when bad characters mangle your return address?**
  Walk through a real failure: pick an address with `0x0a` in it, watch the
  exploit fail, derive why.
- **What is the minimum reliable payload size, and how do you stay under
  it?** Receive-buffer size limits, allocation patterns, what gets
  truncated and where.
- **SEH overwrite vs straight stack overflow — when and why?** Find a
  target with a stack canary that breaks the straight overflow but not the
  SEH path. Exploit it both ways.
- **What if the saved return address is corrupted before strcpy even
  finishes?** Targets that read the stack mid-copy. Detection and
  workarounds.

### Targets used

- Vulnserver TRUN (continued from Module 01)
- Easy File Sharing Server (SEH overwrite practice)
- A target with DEP enabled (forces ROP introduction at the end of this
  module)

### Done when

You can take a fresh stack overflow, identify which technique is
appropriate, and write a working exploit in under 90 minutes.

---

## Module 03 — Shellcoding

Premise: you can place arbitrary bytes at EIP. Those bytes have to *be*
something useful.

### Driving questions

- **Why does `mov eax, 0` produce 5 bytes including 4 nulls, but
  `xor eax, eax` produces 2 bytes and no nulls?** Look at the encoded
  bytes. Derive the rule.
- **How does a Windows API function get called from raw assembly when you
  don't know its address?** PEB walking from first principles. Don't copy
  a published walker — write one.
- **How do you build a string on the stack when you can't include null
  bytes in your instructions?** Stack strings, push order, alignment
  tricks.
- **What is an egghunter actually doing, and why does it work?** Step
  through skape's egghunter under the debugger. Watch every memory access.
  Understand why each instruction is what it is.
- **Why does a custom XOR encoder need a "do not produce these bytes"
  constraint at encoding time?** Write one. Break it. Fix it.
- **How small can a working MessageBox shellcode be?** Optimize one of
  your own writes. Compare to published minimums.

### Targets used

- A controlled environment: a wrapper binary you write that calls into
  your shellcode with no protections. Then increasing constraints.

### Done when

You can write a working Windows shellcode under arbitrary byte
constraints (no nulls, no spaces, no CRLF, ASCII-only, etc.) without
consulting published examples. Encode it by hand if necessary.

This is the hardest module. Plan on 80+ hours.

---

## Module 04 — Reverse Engineering Speed

Premise: OSED's RE machine eats time. You need to read binaries faster
than you currently do.

### Driving questions

- **In a 500-line decompiled function, which 10 lines actually matter?**
  Triage practice. What to skim, what to read carefully.
- **Given a stripped function, how do you identify what API it's calling
  from the disassembly alone?** Common call patterns. Distinguishing
  `strcpy` from `strncpy` from a custom copy loop just by the pattern.
- **How do you know which calling convention a function uses?** Read the
  prologue, epilogue, and call site. Three pieces of evidence, all must
  agree.
- **What does optimized code look like vs unoptimized?** Side-by-side
  comparison of the same C function compiled with `/O0` and `/O2`. Learn
  to read both.
- **How fast can you identify a known function (memcpy, strlen, malloc)
  in an unfamiliar binary?** Pattern-match practice. Speed drill *only*
  after the recognition is reliable.
- **Where in a closed-source service is the authentication check, and how
  do you find it without grepping for strings?** Real-world: lots of
  binaries strip strings. Find the check by control flow.

### Targets used

- crackmes.one Windows challenges (filter: medium difficulty)
- The Flare-On early rounds
- A retired HackTheBox Windows machine's main service binary

### Done when

You can read a 50KB Windows service binary cold and have a working
mental map of its protocol-handling code within 90 minutes.

---

## Module 05 — Integration Under Pressure

Premise: doing one step well doesn't mean you can do all the steps in
sequence under time pressure. This module simulates exam conditions.

### Driving questions

- **In a fixed 8-hour window, on an unfamiliar Windows target, can you
  reproduce a known-vulnerable exploit without referring to your own
  notes from when you did it before?** This is the actual exam skill.
- **What happens to your performance when you've been debugging for 6
  hours straight?** Track this. Identify your fatigue patterns. Adapt.
- **What does your workflow look like when a step doesn't work the way
  it did last time?** Adaptability under pressure. Knowing when to back
  off and try a different approach.
- **Are your writeups good enough?** The OSED report is graded. Practice
  it now. Every practice exploit gets a 1-page writeup, formatted like
  the exam report.

### Format

One full simulated exam per week for four weeks. 8 hours each, no
internet, no AI assistance, only documentation you've personally written
or printed in advance. Score yourself honestly.

### Done when

You can complete a fresh stack-overflow exploit on an unfamiliar target
in under 5 hours including writeup, with no aid except your own notes.

---

## A note on time

The total hours implied by this curriculum, done well:

- Module 01: 10–15 hours
- Module 02: 30–40 hours
- Module 03: 80+ hours
- Module 04: 40–60 hours
- Module 05: 32 hours (four 8-hour sessions)

Total: 192–227 hours of focused work. That's 12–16 weeks at 15 hours/week.

This is the realistic OSED prep curve. Anyone telling you it's faster is
selling something. Anyone telling you it's slower hasn't accounted for the
PEN-300 lab time that's separate from this.

The good news: this curriculum, done honestly, gets you past OSED. The bad
news: there are no shortcuts inside it. Every hour you skip is an hour
you'll wish you had at hour 40 of the exam.
