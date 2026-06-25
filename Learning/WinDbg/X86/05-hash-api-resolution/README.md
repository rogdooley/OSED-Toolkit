# Module 05 — Hash-Based API Resolution

## What this module teaches

Why shellcode uses function name hashes instead of strings, how to compute ROR13
and other common algorithms by hand, how to reverse a hash to a function name,
and how to verify all of this with osed-windbg.

By the end you will be able to look at an unknown hash value in a shellcode
sample and identify which function it resolves to.

## Why this module exists

A linear name search (what Exercise 03 did) requires the target string to live
in the shellcode. Strings like `WinExec\0` and `LoadLibraryA\0` add bytes to
the payload, create null bytes (a bad character in many overflows), and make
the shellcode trivially identifiable. Hash comparison solves all three problems:
the hash is a single DWORD (4 bytes), can be made null-free, and is not
directly readable as a string.

Understanding hashes also helps you identify what a shellcode does during
reverse engineering: if you see `cmp eax, 0x7c0dfcaa` in a shellcode, you
should be able to say "that's checking for `WinExec` using ROR13."

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [Why hashes](01-why-hashes.md) | Articulate the three reasons shellcode uses hashes instead of strings |
| 02 | [ROR13 by hand](02-ror13-by-hand.md) | Compute a ROR13 hash manually and verify it |
| 03 | [Verify and reverse with osed-windbg](03-verify-with-osed.md) | Use `sc.hashes`, `sc.hash`, and `sc.hashresolve` |

Total time: 2–3 hours.

## What you need

- osed-windbg toolkit loaded (the hash implementations live in the toolkit)
- Module 04 completed
- A calculator that handles hex and bit rotation (or WinDbg's `?` command)

## Background reading

`Documentation/Windows/Shellcode/Hash_Algorithms.md` — complete coverage of
common hash families used in real-world shellcode. Read after this module.
