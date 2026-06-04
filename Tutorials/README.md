# WinDbg Fluency for Exploit Development

A goal-driven curriculum for building real debugger and exploit-dev intuition.

## What this is

A series of exercises that ask you to answer specific, verifiable questions about
real programs running under WinDbg. The questions are chosen so that answering
them forces you to use specific debugging skills *in context*, and the answers
themselves build the mental model you need for OSED-level exploit development.

## What this is NOT

- Command drills. "Get fast at typing `dd esp L40`" is not a learning goal.
- A WinDbg reference. The Microsoft docs are excellent — keep them open.
- A guide that hands you the answer before you find it.

If you finish a session looking up what a command does, that is expected and
fine. If you finish a session typing commands quickly without understanding
what each output means, you are doing it wrong.

## The core philosophy

WinDbg fluency is not knowing commands. It is having a mental model of program
execution so internalized that you reach for the right tool without thinking.
Commands serve the model.

Each exercise in this curriculum has four parts:

1. **A question** — concrete, verifiable
2. **A reason** — what skill answering this question forces you to use
3. **A model update** — what you should know that you didn't before
4. **A writeup prompt** — explain it as if teaching someone else

Skip the writeup and you skip the consolidation. The writeup is the learning.

## How to use this

1. Pick the next exercise in order. Order matters; each builds on the last.
2. Open a fresh notes file using [notes-template.md](notes-template.md).
3. Work the exercise without looking ahead.
4. Write the writeup at the end before moving on.
5. Only then go to the next exercise.

Most exercises are sized at 45–90 minutes. If you finish much faster, you
guessed rather than verified — go back.

## Prerequisites

- A Windows 7 or Windows 10 x86 VM (the 32-bit version matters)
- WinDbg installed (the classic version, not just WinDbg Preview)
- `cdb.exe` accessible from a terminal
- Vulnserver compiled and runnable
- Python 3 for sending payloads
- A blank notebook (paper or markdown) for the writeups

You do **not** need symbols, Mona, Immunity, or IDA for Module 01. You will
need all of those later.

## Modules

| Module | Status | Focus |
|---|---|---|
| [01 — Foundations](module-01-foundations/) | Built | Reading programs under the debugger. Building the mental model. |
| 02 — Exploit Mechanics | Roadmap | From "I can read this" to "I control EIP." |
| 03 — Shellcoding | Roadmap | Writing payload code under real constraints. |
| 04 — Reverse Engineering Speed | Roadmap | Reading unfamiliar binaries fast. |
| 05 — Integration Under Pressure | Roadmap | Full exploits, timed, no internet. |

The roadmap for unfinished modules lives in [roadmap.md](roadmap.md). Each
roadmap entry lists the questions that will drive those exercises so you can
preview what's coming.

## One ground rule

When an exercise asks you to figure something out, do not look it up first.
Looking up the answer before working the problem will give you the *answer*
without giving you the *path*, and the path is the entire point. If you cannot
make progress after 30 minutes of honest effort, then look up *the specific
thing that's blocking you* — not the answer to the exercise. Then continue.
