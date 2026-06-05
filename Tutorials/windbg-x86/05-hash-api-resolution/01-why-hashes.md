# Exercise 01 — Why Hashes

## The question

Before writing a single line of hash code, explain why hashes exist in
shellcode. There are three concrete, independent reasons. Write them down
before reading on.

---

## The three reasons

### Reason 1: Null bytes

The string `WinExec` in ASCII is `57 69 6e 45 78 65 63`. No null bytes in
the string itself — but it must be null-terminated to be a valid C string.
That null terminator is `00`.

Most stack overflow vulnerabilities involve a function like `strcpy` or
`gets` that treats `\x00` as the string's end. If your shellcode contains
`00 57 69 6e 45 78 65 63 00` (with the embedded null terminator), `strcpy`
will stop copying at the first `00`. The rest of your shellcode — including
the part that actually calls `WinExec` — never arrives.

A ROR13 hash of `WinExec` is `0x7c0dfcaa`. Four bytes, none of them `00`.

**Exercise:** Verify that `0x7c0dfcaa` contains no null bytes. What other
common bad characters might a hash inadvertently contain? (Hint: `\x0a`,
`\x0d`, `\x20`, `\x2f`.) This is why some shellcode uses alternative hash
algorithms — to avoid specific bad characters.

### Reason 2: Size

A string comparison function embedded in shellcode takes bytes:

- The strings themselves: `WinExec\0` = 8 bytes, `LoadLibraryA\0` = 13 bytes
- A loop, counter, and comparison logic: 20–30 bytes minimum

A hash comparison replaces all of that with:

```asm
call compute_hash   ; compute hash of current export name
cmp eax, 0x7c0dfcaa ; is this WinExec?
jne .next
```

That is 2–4 bytes for the `cmp` (using immediate) versus 20+ bytes for a
string comparison loop. Over six or eight functions to resolve, the savings
add up to 100+ bytes. OSED scenarios sometimes have very constrained payload
sizes.

### Reason 3: Obfuscation

`WinExec\0` in a shellcode is a gift to defenders: a yara rule that matches
`WinExec` in non-text sections will flag the payload. A hash constant
(`0x7c0dfcaa`) is four bytes that look like an arbitrary immediate value.
Without knowing which hash algorithm and which function, the four bytes are
not directly readable.

This is not strong obfuscation — defenders maintain hash lookup tables — but
it adds a layer that slows analysis.

---

## The tradeoffs

Hashes have downsides too:

**No collision guarantee.** If two different function names produce the same
hash, your shellcode could call the wrong function. This must be verified
before deployment. Use `sc.hashresolve` (Module 03 of this series) to
confirm uniqueness within the target module.

**Fixed algorithm dependency.** The shellcode and your debugging/verification
tools must agree on the algorithm. If you're analyzing a shellcode and assume
ROR13 but it uses CRC32, your reverse-lookups will all be wrong.

**Debugging difficulty.** The comparison `cmp eax, 0x7c0dfcaa` is harder to
read at a glance than `strcmp(name, "WinExec")`. When stepping through
shellcode, you need a lookup table to know which function each hash corresponds
to. The osed-windbg toolkit's `sc.hashresolve` provides this.

---

## Checkpoint (write answers, no reference)

1. Why can't a stack-overflow shellcode contain `\x00` bytes?
2. A hash of `WinExec` could still contain `\x0a`. How would you detect this
   before encoding?
3. Name one situation where hashes make debugging harder.
4. Why is `\x20` (space) a common bad character in network-based exploits?
5. A shellcode needs to resolve 8 functions. How many bytes does the hash
   approach save compared to 8 string comparisons (rough estimate)?
