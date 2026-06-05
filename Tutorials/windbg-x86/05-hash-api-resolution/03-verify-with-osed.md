# Exercise 03 — Verify and Reverse with osed-windbg

## The question

Given an unknown hash value found in shellcode, identify which function it
resolves to. And given a list of functions you need to call, compute all their
hashes and check for bad characters and collisions.

---

## Setup

Any x86 process with kernel32 loaded. osed-windbg loaded.

---

## Part A — Hash a full module

The `sc.hashes` command computes the hash of every named export in a module:

```
0:000> dx @$osed().sc.hashes("kernel32")
```

This produces a table of (Algorithm, Hash, Name, Address) for all named
exports. Scroll through it. Recognize the pattern: the ROR13 hash of a
function is a consistent 8-hex-digit number, varying widely even for similar
names.

**Question:** Find two exports whose ROR13 hashes share the same first byte.
Does that concern you? (Hint: hash collisions are checked against the entire
32-bit value, not just a prefix.)

---

## Part B — Check for bad characters in your hashes

You are writing a shellcode for a vulnerability that disallows `\x00`, `\x0a`,
and `\x0d`. You need to resolve `WinExec` and `CreateProcessA`.

**Step 1:** Compute both hashes:

```
0:000> dx @$osed().sc.hash("WinExec", "ROR13")
0:000> dx @$osed().sc.hash("CreateProcessA", "ROR13")
```

**Step 2:** Check each byte of each hash for bad characters:

For `WinExec = 0x7c0dfcaa`:
- Byte 0 (MSB): `0x7c` — OK
- Byte 1: `0x0d` — **BAD CHAR** (`\x0d` = carriage return)
- Byte 2: `0xfc` — OK
- Byte 3 (LSB): `0xaa` — OK

`0x7c0dfcaa` contains `\x0d`. For a vulnerability that strips carriage
returns, this hash is unusable as-is.

**Step 3:** Try CRC32:

```
0:000> dx @$osed().sc.hash("WinExec", "crc32")
```

Check the result for `\x00`, `\x0a`, `\x0d`. If it's clean, use CRC32.

**Step 4:** Try ROL7:

```
0:000> dx @$osed().sc.hash("WinExec", "rol7")
```

Check again.

**Key lesson:** The choice of hash algorithm is driven by the bad-char
constraints of the specific vulnerability. There is no universally "best"
algorithm. You select the algorithm (and verify with `sc.hash`) for each
function you need to resolve.

---

## Part C — Reverse a hash (identify an unknown function)

You are reverse-engineering a shellcode and find the instruction:

```asm
cmp eax, 0x0726774c
jne .next
```

This is a hash comparison. The algorithm is ROR13 (standard Metasploit
shellcode). What function is it resolving?

```
0:000> dx @$osed().sc.hashresolve("kernel32", 0x0726774c, "ROR13")
```

The toolkit walks all exports of kernel32, computes the ROR13 hash of each,
and returns the one that matches. This is your identification tool for
unknown shellcode analysis.

Try it for a few other well-known hashes from Metasploit shellcode:

| Hash | What it resolves to |
|---|---|
| `0x0726774c` | ? |
| `0xe8afe98` | ? |
| `0x6b8029` | ? |
| `0x7c0dfcaa` | WinExec (confirmed earlier) |

Fill in the `?` values using `sc.hashresolve("kernel32", <hash>, "ROR13")`.

---

## Part D — Collision check

Hash collisions would be catastrophic: your shellcode would call the wrong
function. Verify that your chosen hashes are collision-free within the target
module:

```
0:000> dx @$osed().sc.hashes("kernel32", "ROR13")
```

Scan the output for duplicate Hash values. In a well-designed kernel32 export
table, collisions should be extremely rare for ROR13. If you find one, note
the pair — that is a function you cannot resolve by this hash in this module.

---

## Part E — End-to-end: shellcode API resolution in the debugger

Imagine you have shellcode that does:

1. PEB walk → kernel32 base (Module 03)
2. PE header walk → export directory (Module 04)
3. Hash comparison loop → WinExec (this module)
4. Call WinExec

Step through the entire chain using the manual techniques and then verify each
step with the osed-windbg toolkit commands in sequence:

```
0:000> dx @$osed().sc.peb()          ; Step 1: confirm PEB
0:000> dx @$osed().sc.base("kernel32")  ; Step 1: confirm module base
0:000> dx @$osed().sc.pe("kernel32")    ; Step 2: confirm PE, export dir
0:000> dx @$osed().sc.exportwalk("kernel32", "WinExec")  ; Step 3+4: confirm walk
0:000> dx @$osed().sc.hash("WinExec", "ROR13")          ; Step 3: confirm hash value
```

When you can run this sequence on a fresh process in under two minutes without
looking up any command syntax, this module is complete.

---

## Checkpoint

1. What osed-windbg command identifies which function a hash belongs to?
2. `0x7c0dfcaa` contains `\x0d`. Why is this a problem for many exploits?
3. You have three algorithm choices (ROR13, CRC32, ROL7). Your bad chars are
   `\x00 \x0a \x0d \x20 \x2f`. How do you decide which algorithm to use for
   a specific function name?
4. What happens if two functions in a module have the same ROR13 hash and
   your shellcode uses that hash?
5. A shellcode you're analyzing uses CRC32 hashes. How do you change the
   `sc.hashresolve` call to account for this?

---

## Summary: the full chain

```
fs:[0x30]             ; TEB → PEB address
[PEB + 0x0c]          ; PEB → Ldr (PEB_LDR_DATA)
[Ldr + 0x0c]          ; Ldr → InLoadOrderModuleList.Flink
walk list, compare BaseDllName → DllBase of kernel32

[K32_BASE + 0x3c]     ; e_lfanew
[K32_BASE + e_lfanew + 0x78]  ; Export Directory RVA

AddressOfNames[i]     ; name string RVA
ROR13(name) == hash?  ; hash comparison
AddressOfNameOrdinals[i]  ; ordinal index
AddressOfFunctions[idx]   ; function RVA
function_va = K32_BASE + function_rva
```

Every step above corresponds to one manual WinDbg exercise and one
osed-windbg command. If any step is unclear, go back to the relevant module.
