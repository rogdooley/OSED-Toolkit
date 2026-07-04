# How to Think While Reverse Engineering

> A companion to the [reversing study guide](README.md). The guide teaches *what*
> x86 constructs mean. This document teaches the *questions to keep asking* while
> you read unfamiliar assembly. It is methodology, not reference — a playbook you
> reread, not a manual you consult once.

---

## Preface — read this like a mentor talking, not a spec

I want to give you the thing that took me years to build: the running interrogation
that happens in an experienced reverser's head. When I open an unknown function I
am not "reading" it the way you read prose, top to bottom. I am asking a small set
of questions over and over, and each answer narrows what the code *can* be until
only one interpretation survives. The instructions are evidence. My job is to
cross-examine them.

The single most important habit — the one everything else hangs from — is this:
**separate facts from hypotheses, out loud, always.** A fact is something the
instructions force to be true ("ECX is decremented every iteration"). A hypothesis
is a story I'm entertaining ("this is probably a length"). Beginners fuse the two
and then defend the fused blob. Experts keep a ledger: this column is what the
machine does; that column is what I think it means; and I only promote a hypothesis
to a fact when the evidence closes the gap. If you take nothing else from this
document, take the ledger.

The second habit: **translate every instruction into English before you translate
it into C.** "Load the byte at ESI into AL, then advance ESI" is English. `*p++` is
C. If you skip the English step you are pattern-matching shapes, and shapes lie. The
English step is where you actually understand; the C step is just notation.

The rest of this document is the set of questions, organized by what you're looking
at. For each, I'll tell you the question, why it's worth asking, how to answer it
from the assembly in front of you, where beginners go wrong, and — most
importantly — **what evidence is enough** before you're allowed to write the
conclusion down as a fact.

---

## Function boundaries

**The question: "Where does this unit of behavior begin and end, and is this
really one function?"**

*Why it's useful.* You cannot reason about arguments, locals, or return values
until you know the frame they belong to. A misplaced boundary makes you read the
tail of one function as the head of another, and every offset after that is wrong.

*How to answer it from assembly.* Look for the entry fingerprint — the standard
prologue `push ebp / mov ebp, esp / sub esp, N` — and the exit fingerprint —
`leave`/`mov esp,ebp; pop ebp` followed by `ret`/`ret N`. Cross-check with who
*calls* the address: a `call` target is a function entry by definition. IDA's
boundaries are usually right, but verify them where it matters, especially around
`ret N` (which also tells you the calling convention) and tail calls (a `jmp` to
another function that shares your frame).

*How much of the prologue should I care about?* Care about what it *establishes*,
not the ceremony. The `sub esp, N` gives you the frame size. A `push ebp / mov ebp,
esp` gives you the EBP coordinate system. `push esi/edi/ebx` tells you which
callee-saved registers this function will use for values that must survive calls.
A `mov eax, __security_cookie / xor eax, ebp` tells you `/GS` is present. Beyond
that, the prologue is scaffolding — note it and move on. Don't narrate every
instruction of boilerplate; recognize it as one unit.

*Beginner mistakes.* Treating IDA's `sub_XXXX` label as a fact about behavior (it's
just the address). Missing that a function has *multiple* returns. Reading a tail
call as an internal jump and merging two functions. Assuming no-prologue means
no-function — optimized code omits the frame pointer (Chapter 11) and still has
clean boundaries.

*Sufficient evidence.* You may call something a function when you have both an
entry reached by a `call` (or an exported/registered address) **and** a matching
epilogue+`ret`. One without the other is a hypothesis, not a boundary.

---

## Registers

**The question: "What role is *this* register playing *right now*, and how long
does that role last?"**

*Why it's useful.* x86 has few registers and the compiler recycles them ruthlessly.
A register has no type and no fixed meaning; the same EAX is a counter, then a
pointer, then a return value within ten instructions. If you assign a register one
identity for the whole function you will misread it.

*How to answer it from assembly.* Track each value from **birth** (the instruction
that first writes it) to **death** (the instruction that overwrites it). In that
live range it holds one logical thing — classify it by what the code *does* to it:
dereferenced (`[reg]`) → it's a pointer; decremented and used by `rep`/`loop` → a
counter; moved into EAX right before `ret` → the return value.

*Which registers matter / which are temporary?* By ABI convention on 32-bit
Windows: **EAX** carries return values and is the default arithmetic scratch;
**ECX/EDX** are scratch (and ECX is the counter for `rep`/`loop`, or `this` under
`__thiscall`); **EBX/ESI/EDI/EBP** are callee-saved, so the compiler parks
long-lived values (base pointers, loop pointers) there precisely because they
survive calls. **ESP** is never a temp — it's the stack pointer. So when you see a
value living in ESI across several calls, that's a signal it's *important* to the
function's logic, not a throwaway.

*Which likely hold arguments?* At a call site, arguments are the `push`es
immediately before the `call`, plus ECX/EDX if it's fastcall/thiscall. Inside the
callee, arguments are the positive EBP offsets (`[ebp+8]`, `[ebp+0xC]`, ...) in a
framed function, or ESP-relative slots above the return address in FPO code. Don't
confuse callee-saved `push esi/edi` at the top of a body (register preservation)
with argument pushes at a call site.

*Beginner mistakes.* Believing EAX after every `call` is meaningful even when the
callee is `void`. Ignoring partial-register writes (`mov al, ..` does not clear the
top 24 bits of EAX). Reading `xor eax, eax` as an XOR operation instead of "set to
zero." Guessing signedness from the bytes instead of from the jump that consumes
them (`ja/jb` unsigned, `jg/jl` signed).

*Sufficient evidence.* Before you claim "ESI is the source pointer," you need to
see it *dereferenced* and *advanced*. Before you claim a `call` returns a value,
you need to see EAX *consumed* afterward. A register's role is proven by use, never
by its name.

---

## Stack

**The question: "What is the shape of this frame, and why is ESP where it is right
now?"**

*Why it's useful.* Arguments, locals, saved registers, the saved return address —
all of it lives on the stack at known offsets. The frame is the map. For
vulnerability work it's *the* map: the distance from a buffer to the saved return
address is the exploit.

*What does the stack look like?* After a standard prologue: arguments at `[ebp+8]`
and up, the return address at `[ebp+4]`, the saved caller EBP at `[ebp+0]`, and
locals below at `[ebp-4]`, `[ebp-8]`, downward. The stack grows toward *lower*
addresses, so an overflow in a local writes *upward* toward the saved return
address. Draw it once with high addresses on top and keep that picture.

*What does EBP represent?* A stable anchor. It's set once in the prologue and does
not move for the rest of the function, which is exactly why the compiler addresses
args and locals as fixed `[ebp±N]`. EBP is the frame's origin coordinate.

*Why is ESP moving?* Because ESP is the *volatile top-of-stack cursor*. Every
`push`, every `call`, every argument setup shifts it. That's its job — it tracks
where the next push will go. The whole reason a separate frame pointer exists is so
that args/locals stay addressable at fixed offsets *while* ESP wanders. In
optimized (FPO) code there's no EBP anchor and everything is ESP-relative, so you
must track ESP's delta from entry yourself (or trust IDA's stack-variable naming,
which does it for you).

*Beginner mistakes.* Drawing the stack growing up (then every sign is backwards).
Forgetting the two dwords — saved EBP and return address — between the first local
and the first argument, so they call `[ebp+4]` "arg1" (it's the return address).
Reading `[esp+N]` as a fixed slot in FPO code without accounting for pushes that
moved ESP.

*Sufficient evidence.* Before you commit to "the buffer is at ebp-0x40 and the
return address is 0x44 bytes past its start," you should read the buffer's offset
off the actual `lea reg,[ebp-40h]` that feeds it — not infer it from the frame
size — and then confirm it against live memory in WinDbg. Frame geometry is a
hypothesis until the debugger shows you the bytes.

---

## Memory

**The question: "Is this instruction touching memory or just moving an address, and
if it touches memory, whose memory is it?"**

*Why it's useful.* The difference between a pointer and the thing it points to is
the single most consequential distinction in reversing. Conflate `eax` with `[eax]`
and your entire reading silently corrupts.

*Is this reading memory or copying a pointer?* Brackets mean dereference:
`mov eax, [ebx]` reads memory at EBX; `mov eax, ebx` copies the pointer value.
`lea eax, [ebx+8]` is the trap — despite the brackets, `lea` *computes the address*
`ebx+8` and stores the number; it touches no memory. So `lea` is how you recognize
"take the address of" (`&local`, `&field`) and also how the compiler does cheap
arithmetic (`lea eax,[eax+eax*4]` is `eax*5`). Ask of every bracketed operand: is
this an actual load/store, or is it inside a `lea`?

*Is this heap or stack?* Follow the base pointer to its birth. `lea reg, [ebp-N]`
or `[esp+N]` → stack (dies at return). A base returned by `malloc`/`HeapAlloc`/`new`
→ heap (dies at free). An absolute address (`dword_40A000`, `offset g_thing`) →
global (lives forever). Storage class is *where the pointer came from*, never a
property you can read off the access itself.

*How do I recognize pointers?* A value is a pointer when it gets dereferenced
(`[reg]`), when it's advanced by an element size in a loop (`add reg, 4`), when it's
produced by `lea`/an allocator/an address-of, or when it's passed where a callee
then dereferences it. A value that only ever participates in arithmetic and
comparisons and is never dereferenced is a scalar, not a pointer — even if it
happens to look like an address.

*Beginner mistakes.* Reading `lea` as a memory access (inventing phantom
dereferences). Assuming the scale in `[base+idx*4]` doesn't matter — it's the
element size, and thus a type hint. Deciding heap-vs-stack from the type of the
object instead of from where its base was born. Treating a fixed displacement
(`[eax+8]`, a struct field) the same as a variable scaled index (`[eax+ecx*4]`, an
array element) — they mean different source constructs.

*Sufficient evidence.* Before calling a register a pointer, you should have seen it
dereferenced or unambiguously produced as an address. Before labeling memory "heap,"
you should have traced its base to an allocator call. A plausible-looking address
value is a hypothesis; a dereference or an allocator is the evidence.

---

## Loops

**The question: "What advances, what stays fixed, what stops it, and what is true
when it's done?"**

*Why it's useful.* Loops are where the real work happens — copies, scans, parsing,
transformation. Misreading a loop's bound or its induction variable is how you get
buffer sizes and offsets wrong.

*How to answer it from assembly.* First find the **back-edge** — a jump whose target
is an *earlier* address. That cycle is the loop. Then answer four things in order:

- **Identify the induction variable.** It's the value modified every iteration
  (`inc`, `add reg,4`, `p++`) *and* named in the termination test. Note: it may be a
  *pointer* that walks, not an integer counter — the compiler often strength-reduces
  `arr[i]` into a moving pointer and the integer `i` disappears.
- **What changes each iteration?** The induction variable, plus whatever the body
  mutates — an accumulator, a destination pointer, a running hash. List them.
- **What remains constant?** The loop invariants — the base address, the bound, a
  key. Knowing what *doesn't* change is as important as knowing what does; it tells
  you the loop's fixed context.
- **What terminates it?** Read the back-edge's `cmp`/`test` + conditional jump. Is
  it a counter against a bound (counted loop), or a pointer against a sentinel like
  a NUL byte (walk loop)? Note signed vs unsigned — that's the counter's type.
- **What state exists after the loop exits?** This is the question beginners skip
  and it's often the point of the whole loop. After a strlen-style walk, a pointer
  sits one past the NUL and a length is computed from the delta. After a copy, the
  destination holds N bytes and the pointers are at their ends. The *post-condition*
  is frequently the function's actual output.

*Simulate it.* For anything non-trivial, mentally (or in WinDbg) run two or three
iterations with concrete values. Watch the induction variable and the accumulator
change. Simulation catches off-by-ones — especially update-before-test vs
test-before-update — that static staring misses.

*Beginner mistakes.* Reading a loop as straight-line code because they didn't
resolve the back-edge. Picking the accumulator as the induction variable (the
induction variable is the one in the *termination test*). Reading a count-down loop
as if the source counted down (the compiler reverses loops for free zero-compares;
the trip count is the invariant, not the direction). Ignoring the loop's
post-condition.

*Sufficient evidence.* You understand a loop when you can state its induction
variable, its invariants, its exact termination condition, and its post-condition —
and a two-iteration simulation matches your story. Anything less is a guess dressed
as an analysis.

---

## Branches

**The question: "What question is this branch answering, and where does each answer
lead?"**

*Why it's useful.* Control flow is a graph, not a script. If you try to read it
linearly you'll follow paths the CPU never takes and miss paths it does.

*Think in control-flow graphs and decision trees.* Every conditional jump is a
node with two edges. Your mental model should be the *graph* of those nodes, not a
reconstruction of `if`/`else` keywords. Ask of each branch: what condition does it
test (the preceding `cmp`/`test`), and what code does each outcome reach? Build the
tree of decisions. Same-value sequential tests are a chain (`if/else if`);
different-value branching arms are nesting; a bounds check plus an indirect jump
through a table is a `switch`.

*Avoid trying to reconstruct the original C syntax.* This is a discipline, not a
limitation. The compiler had many ways to emit your `if`, and the reverse mapping is
many-to-one — chasing "was this a `while` or a `for`?" wastes effort on a question
with no unique answer. What matters is the *behavior*: which conditions gate which
code. Capture the decision structure faithfully and let the exact C syntax stay
ambiguous.

*How to answer it from assembly.* Read the `cmp`/`test` for *what* is compared and
the jump mnemonic for *how* (signed/unsigned, equal/greater/zero). Follow both
edges. In IDA, use graph view — the arrows *are* the decision tree. For `switch`,
find the unsigned bounds check (`cmp x, MAX / ja default`) and read the jump table
from `.rdata` to enumerate the cases.

*Beginner mistakes.* Reading `ja` as signed (it's deliberately unsigned so negatives
fold into "too large"). Following only the fallthrough edge and forgetting the taken
edge exists. Trying to name a construct (`for` vs `while`) instead of capturing the
condition. Disassembling a jump table's data as code.

*Sufficient evidence.* Before you write down "if X then A else B," you must have
identified the exact condition (operands and signed/unsigned sense) and confirmed
where *both* edges go. A branch with one unexplored edge is an unfinished analysis.

---

## Data flow

**The question: "Where did this value come from, where is it going, and who is
allowed to touch it?"**

*Why it's useful.* Follow data before control. The values are the substance; the
branches are just the plumbing that routes them. For vulnerability work, data flow
*is* the analysis — you're tracing attacker bytes from entry to a dangerous use.

*Where did this pointer originate?* Walk backward from where it's used to where it
was born — an argument (`[ebp+8]`, then go up to the caller), an allocator return,
an address-of a local, a field loaded from another object. Don't stop at the first
`mov`; a value can hop through several registers and slots. Renaming as you go (in
IDA) keeps the origin visible.

*Who owns this memory?* Ownership means "whose lifetime governs it and who is
responsible for it." A stack local is owned by its function and dies at return —
passing its address to something that stores it for later is a bug. Heap memory is
owned by whoever frees it. Knowing the owner tells you what's legal and where
use-after-free or dangling-pointer conditions can arise.

*Where is attacker-controlled input?* Start at the sources: `recv`, `ReadFile`,
`fread`, `GetEnvironmentVariable`, registry reads, command-line, parsed protocol
fields. Mark those buffers/returns as tainted and propagate: taint flows through
`mov` and arithmetic, is *narrowed* by masks (`and eax,0xFF` → you control one
byte), and is *constrained* (not cleaned) by validation checks. State precisely how
many bytes you control and with what limits — "tainted" is not enough; "0x200 bytes,
fully controlled, no filter" is an analysis.

*How does data move through the program?* In hops: source buffer → copied to a local
→ a field extracted → used as a length → drives a copy. Trace the chain hop by hop.
The interesting events are where tainted data meets a sink (a copy into a fixed
buffer, an index, an indirect call).

*Beginner mistakes.* Following control flow first and losing the data in the noise.
Stopping the trace at one copy. Treating "derived from input" as "fully controlled"
when a mask left you only 3 bits. Forgetting that return values (like `recv`'s byte
count) are tainted too.

*Sufficient evidence.* Before claiming "the attacker controls this operand," you
need an unbroken chain from a source to that operand, with every transform along the
way accounted for, and the constraints stated. A gap in the chain is a hypothesis,
not a data-flow fact.

---

## Function identification

**The question: "What are this function's inputs, outputs, side effects, and
invariants — and *only then*, does it match something I know?"**

*Why it's useful.* This is where "derive, never assume" pays off hardest. Naming a
function by its shape ("looks like strcpy") is the most seductive and most dangerous
shortcut in reversing, because the properties that matter for security — the bound,
the stop condition — are exactly what the name hides.

*How to answer it from assembly, in order.*

1. **Inputs.** What does it read? Arguments (how many, which are pointers), globals,
   memory it dereferences.
2. **Outputs.** What does it return in EAX? What does it write through its pointer
   arguments?
3. **Side effects.** What does it change in the world beyond its return —
   memory it writes, globals it sets, APIs it calls, handles it touches?
4. **Invariants.** What is always true across it — a bound it respects, a
   terminator it honors, a relationship it maintains between arguments?
5. **Only then compare to known library functions.** If it takes (dst, src), copies
   byte-by-byte forward, stops when it copies the source's NUL, and has no count
   cap, then it *behaves as* `strcpy` — and you say exactly that, with the four
   derived facts attached. You are not recognizing a shape; you have reconstructed a
   contract and matched the contract.

*Beginner mistakes.* Reading `rep movsd`'s ECX as a byte count (it's dwords — ×4).
Calling a bounded `strncpy` a `strcpy` because the loop looks the same (one counter
instruction is the whole difference). Naming by the presence of a NUL check without
confirming there's no bound. Skipping side effects and missing that the function
also, say, lowercases or filters.

*Sufficient evidence.* You may attach a library name only after you've derived
element size, direction, stop condition, and bound, and they match that function's
contract. The derivation is the evidence; the resemblance is not.

---

## Vulnerability analysis

**The question: "Where is trust established, where is it violated, and what
assumption sits in the gap?"**

*Why it's useful.* Bugs live at the boundary between "the program believes X" and
"X isn't guaranteed." Finding that boundary is more productive than scanning for
dangerous function names.

*How to answer it from assembly.*

- **Where is trust established?** Where the program *validates* something — a length
  check (`cmp len, MAX / ja reject`), a NUL-termination assumption, a type/tag
  check, a bounds check on an index. Note what each check actually guarantees on the
  accepted path.
- **Where is trust violated?** Where tainted data is used *as if* validated when it
  wasn't — a copy with no length check, an index with no bounds check, a length
  field taken straight from input and fed to a copy.
- **What assumptions exist?** Make them explicit: "this code assumes src is
  NUL-terminated within 64 bytes," "this assumes the length field is ≤ buffer size,"
  "this assumes the count is non-negative." Then ask whether the attacker can break
  each one.
- **Is there a bounds check?** And if so — is it *correct*? Check its sign (`jg`
  signed vs `ja` unsigned — a negative length can pass a signed check then become a
  huge `size_t`), its width (`cmp cx` vs `cmp ecx`), and whether it actually guards
  the path that reaches the sink. Most real bugs are *broken* checks, not missing
  ones.
- **Is attacker-controlled data copied, and is destination capacity verified?**
  Match the source size against the destination size at every copy. The bug is the
  mismatch: `0x200` tainted bytes into a `0x40` buffer with no cap.

*Beginner mistakes.* Assuming a bounds check is sound because it exists. Treating a
bounded `recv` as making everything downstream safe (safety is per-operation — the
*next* copy may be unbounded). Confusing "reads attacker data" with "attacker
controls the operand." Chasing function names instead of trust boundaries.

*Sufficient evidence.* Before you call something a vulnerability, you need: an
unbroken taint chain from a source to the sink (data flow), proof the sink is
unbounded or the check is broken (function identification), and a concrete story of
what an attacker sends to trigger it. Ideally you then reproduce it in WinDbg. A
"dangerous-looking" call without those is a lead, not a finding.

---

## Compiler behavior

**The question: "Is this instruction the programmer's intent, or the compiler's
bookkeeping?"**

*Why it's useful.* Half of what you read at `-O2` is scaffolding — register spills,
alignment, cookies, strength-reduced arithmetic. If you treat scaffolding as logic
you'll invent meaning that isn't there; if you can't recognize it you'll drown in
noise.

*Separate scaffolding from intent.* Scaffolding: the prologue/epilogue ceremony,
`push esi/edi/ebx` register preservation, `and esp, 0xFFFFFFF0` alignment, `__chkstk`
stack probes, `/GS` cookie setup and check, register spills to `[esp+N]` and
reloads, block reordering that shoves error paths to the end. Intent: the
arithmetic, the calls with meaningful arguments, the branches that gate real
behavior, the memory the function actually produces. Learn to skim the former and
focus on the latter.

*Recognize compiler idioms without relying on them.* Know that `lea [r+r*4]` is `×5`,
that a magic-number `imul` + `shr` is division by a constant, that `xor reg,reg` is
zero, that `test reg,reg / jz` is a NULL check, that `cmov`/`setcc` is a branchless
select, that `rep movs`/`stos` is a copy/fill. But — and this is the discipline —
recognizing an idiom is a *hypothesis you then verify from the operands*, not a
license to stop reading. The moment an idiom appears where it doesn't fit (a
"prologue" that's really a jump target, a "strcpy" that's really a delimiter parser)
is the moment pattern-matching betrays you. Recognize fast; verify anyway.

*Beginner mistakes.* Reading strength-reduced `lea`/shift math as memory access or
as cryptography. Hunting for a missing branch when they see a `cmov`. Treating a
spilled temporary in `[esp+N]` as a source-level variable. Trusting the decompiler
blindly *or* refusing to use it — both are errors; use it to accelerate, then verify
the hot path against the disassembly.

*Sufficient evidence.* Before you dismiss instructions as scaffolding, you should be
able to name *which* idiom they are and what they accomplish. "Boilerplate I don't
understand" is not the same as "scaffolding I've identified." Certainty about what
you're ignoring is part of the analysis.

---

## General principles — the heuristics, and why each is true

Keep these where you can see them. Each compresses a hard-won lesson; the one-line
reason matters as much as the slogan.

- **Follow data before control.** Values are the substance; branches just route
  them. Trace the data and the control flow explains itself.
- **Translate every instruction into English before C.** English is understanding; C
  is notation. Skipping to C means pattern-matching shapes, and shapes lie.
- **Simulate loops.** Two concrete iterations catch the off-by-one that infinite
  staring won't.
- **Never identify a function solely by its shape.** The bound and the stop
  condition — the things that matter — are exactly what the shape hides. Derive the
  contract.
- **Every branch answers a question.** If you can't state the question a branch
  asks, you haven't read it yet.
- **Every loop has an induction variable.** Find the thing that advances and appears
  in the termination test; if you can't, you've misread the loop.
- **Every memory access has an owner.** Stack frame, heap allocation, or global —
  name the owner, or you don't understand the access.
- **Every pointer came from somewhere.** Trace it to its birth: an argument, an
  allocator, an address-of. An untraced pointer is an unfinished thought.
- **Separate facts from hypotheses.** Keep the ledger. Promote a hypothesis to a
  fact only when the evidence closes the gap — never by repetition or by wanting it
  to be true.
- **A name is a hypothesis; an instruction is evidence.** IDA's `sub_401000` and
  your own guess "this is the parser" are both stories until the instructions
  confirm them.
- **The debugger settles arguments.** When static reasoning gives two readings,
  don't argue with yourself — break, dump, and look. One observation ends the debate.
- **Certainty about what you ignore is part of the analysis.** You may skip
  scaffolding only once you can name it. "I don't understand this so I'll ignore it"
  is how bugs hide.

---

## How to use this playbook over time

Reread it at the start of a hard target, not just once. Early on you'll consult the
topic sections consciously — literally asking "where did this pointer originate?" as
you go. After a few months the questions run in the background and you only slow down
when an answer surprises you. That's the goal: the interrogation becomes reflexive,
and the surprises become where you find the interesting bugs.

The deepest skill here isn't knowing x86 — the [study guide](README.md) covers the
facts. It's the *temperament*: patient, skeptical, willing to hold two hypotheses
until the evidence picks one, and unwilling to write "obviously" in front of any
conclusion. Build that temperament and you can read any x86 Windows binary, whether
or not you've seen its tricks before.
