Lesson: Understanding CALL/POP PIC Shellcode

Goal

By the end of this lesson, you should be able to explain:

1. What CALL actually does internally
2. Why CALL/POP reveals the current runtime address
3. Why shellcode needs PIC
4. How backward calls avoid NULL bytes
5. How to mentally trace these instructions in memory

We are going to stay very small and mechanical first.

No API resolution yet.
No PEB walking yet.
No hashing yet.

Just:

* control flow
* stack behavior
* runtime addresses

⸻

Part 1 — The Smallest Useful PIC Example

Here is the smallest useful example:

start:
    jmp short callsite
resolver:
    pop esi
    int3
callsite:
    call resolver

⸻

First Question

Before execution:

What do you think CALL pushes onto the stack?

Not philosophically.

Literally:

* which address?
* what exact instruction?

Think carefully before continuing.

⸻

Memory Layout

Assume this lands at:

0x00401000

Now let’s map it.

⸻

Actual Layout

00401000  eb02              jmp short callsite
00401002  5e                pop esi
00401003  cc                int3
00401004  e8f9ffffff        call resolver

Notice:

call resolver

is 5 bytes.

Always remember this for x86 near calls.

⸻

Step 1 — Execution Begins

EIP:

00401000

Instruction:

jmp short callsite

What happens?

The CPU jumps to:

00401004

⸻

Step 2 — CALL Executes

Now:

00401004  e8f9ffffff  call resolver

This is the critical moment.

⸻

What CALL REALLY Does

Internally:

push next_instruction
jmp target

So the CPU pushes:

00401009

onto the stack.

Why?

Because:

* CALL is 5 bytes
* next instruction would be after the CALL

⸻

Stack State

Before CALL:

ESP -> previous stack data

After CALL:

ESP -> 00401009

⸻

Then CALL Transfers Control

EIP becomes:

00401002

which is:

pop esi

⸻

Step 3 — POP Executes

pop esi

retrieves:

00401009

from the stack.

Now:

ESI = 00401009

⸻

Important Realization

ESI now contains:

an address inside the shellcode itself

This is the entire PIC primitive.

The shellcode has learned:

* where it lives
* at runtime
* dynamically

without hardcoded addresses.

⸻

Why This Matters

Suppose the exploit injects the shellcode here today:

0x00401000

Tomorrow:

* ASLR changes
* heap changes
* stack changes
* exploit conditions differ

Now shellcode lands at:

0x01740000

Hardcoded addresses fail.

But CALL/POP still works.

⸻

Part 2 — Why The JMP Exists

Question:

Why not simply do:

call resolver
resolver:
    pop esi

?

Answer:
because then execution falls incorrectly into the middle of code.

The JMP:

* skips over the resolver stub
* reaches the CALL
* lets CALL return into the resolver

This creates controlled execution flow.

⸻

The Visual Model

Think of it like this:

jmp over helper
↓
call helper
↓
CALL pushes return address
↓
helper POPs it
↓
helper now knows shellcode location

⸻

Part 3 — Why Backward CALLs Matter

Notice this encoding:

e8 f9 ff ff ff

The relative offset is:

-7

because the target is behind the CALL.

Negative numbers in signed 32-bit become:

ff ff ff xx

which often avoids:

* 00
* badchars

⸻

Compare Forward CALL

Suppose instead:

call future_function

with offset:

+7

Encoding:

07 00 00 00

Now you have NULL bytes.

That is why shellcode authors love backward CALLs.

⸻

Part 4 — Why PIC Is Essential

Normal PE executables get:

* relocations
* import fixing
* loader support

Shellcode gets none of this.

So shellcode must:

* discover itself
* locate DLLs
* resolve APIs
* compute addresses dynamically

PIC is mandatory.

⸻

Part 5 — Extending The Primitive

Now let’s slightly improve the example.

⸻

Version 2

start:
    jmp short setup
resolver:
    pop esi
    lea edi, [esi+8]
    int3
setup:
    call resolver
data:
    db "ABCD"

⸻

Question

When POP ESI executes:

What address is inside ESI?

Answer carefully.

⸻

Walk It Mentally

CALL pushes:

the next instruction after CALL

which is:

data:

So:

ESI = address of embedded data

Now:

lea edi,[esi+8]

can compute addresses relative to that.

⸻

This Is How Embedded Strings Work

Classic shellcode:

jmp short strings
resolver:
    pop esi
strings:
    call resolver
    db "kernel32.dll",0

The shellcode:

* discovers string locations dynamically
* without hardcoded pointers

This is extremely common.

⸻

Exercise 1 — Mental Tracing

Without running anything:

Trace this:

jmp short x
y:
    pop eax
    int3
x:
    call y

Questions:

1. What exact address gets pushed?
2. What does EAX contain?
3. Why is the CALL negative?

Do this mechanically.

No guessing.

⸻

Exercise 2 — NULL Byte Analysis

Would this likely contain NULL bytes?

call future
nop
nop
future:

Why or why not?

⸻

Exercise 3 — Why LEA?

Why might shellcode authors prefer:

lea eax,[eax-5]

instead of:

sub eax,5

Think about:

* flags
* opcode bytes
* shellcode constraints

