# Exercise 02 — ROR13 By Hand

## The question

Given the name `WinExec`, compute its ROR13 hash manually and verify it equals
`0x7c0dfcaa`. If you cannot do this calculation by hand, you cannot debug
shellcode that uses it.

---

## The algorithm

**ROR13 (Metasploit variant):**

```python
def ror13(name):
    hash = 0
    for byte in name.encode('ascii'):
        hash = ror32(hash, 13)
        hash = (hash + byte) & 0xFFFFFFFF
    return hash

def ror32(value, bits):
    bits = bits & 31
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF
```

Each iteration:
1. Rotate the current 32-bit accumulator right by 13 bits
2. Add the current byte's ASCII value
3. Truncate to 32 bits

The hash processes the string byte by byte, building up a 32-bit value.

---

## Step 1 — Compute hash of `W` (first byte, ASCII 0x57)

Initial accumulator: `0x00000000`

After ROR13: `ror32(0, 13) = 0` (rotating zero is still zero)

After add: `0x00000000 + 0x57 = 0x00000057`

Accumulator: `0x00000057`

---

## Step 2 — Compute hash of `i` (ASCII 0x69)

Rotate `0x00000057` right by 13:

```
0x00000057 in binary (32 bits):
0000 0000 0000 0000 0000 0000 0101 0111

Rotate right 13: the bottom 13 bits wrap to the top.
Bottom 13 bits of 0x00000057: bits 12-0 = 000 0000 0101 0111 = 0x057
These 13 bits go to the top: 0x057 << (32-13) = 0x057 << 19

0x057 << 19 = 0x000 0057 << 19:
0x000 = 0, 0x05 = 0101, 0x7 = 0111
= 0b0000_0000_0000_0000_0000_0000_0101_0111
Shift left 19:
= 0b0000_0000_0000_1010_1110_0000_0000_0000
= 0x000A_E000

Top bits (original bits 31-13):
0x00000057 >> 13 = 0x00000057 / 8192 = 0x00000002 (with remainder)
Actually: 0x57 = 87 decimal; 87 >> 13 = 0 (87 < 8192)
So top part = 0x00000000

ROR13(0x00000057) = 0x000AE000
```

WinDbg can compute this for you:

```
0:000> ? (0x57 >> 13) | (0x57 << 0n19)
```

Wait — the WinDbg `?` evaluator uses C-style operators but truncates at 32
bits only in some contexts. Use Python or the osed-windbg toolkit for
verification instead. The manual calculation is the exercise; the toolkit is
the check.

Add `i` = 0x69:

`0x000AE000 + 0x69 = 0x000AE069`

---

## Step 3 — Continue for remaining bytes

The string `WinExec` = `57 69 6e 45 78 65 63` in ASCII.

Continue the iteration. For each byte:
1. ROR32 the accumulator right 13
2. Add the byte
3. Truncate to 32 bits (the `& 0xFFFFFFFF`)

**Do not shortcut to Python yet.** Work through at least three more bytes by
hand on paper. The act of tracing the bit rotation builds the intuition you
need to read shellcode that does this.

After working through `W`, `i`, `n`, `E` manually:

---

## Step 4 — Use WinDbg to verify your running total

WinDbg's `?` command does 32-bit arithmetic. You can verify each step:

```
; After processing 'W' (0x57):
0:000> ? ((0 >> 0n13) | (0 << 0n19)) + 0x57
; = 0x57

; After processing 'i' (0x69), starting with 0x57:
; ror32(0x57, 13) = ?
0:000> ? (0x57 >> 0n13) | ((0x57 & 0x1fff) << 0n19)
; Note: must mask the low 13 bits before shifting up, to avoid overflow
```

The `0n` prefix in WinDbg means decimal (so `0n13` = thirteen, `0n19` =
nineteen).

Alternatively, use the `j` command (JavaScript evaluator in WinDbg Preview):

```
0:000> .scriptrun
```

Or just use the osed-windbg hash command to verify each step isn't needed —
you just need the final value.

---

## Step 5 — Final answer verification

After processing all 7 bytes of `WinExec`, the accumulator should be
`0x7c0dfcaa`.

Verify with osed-windbg:

```
0:000> dx @$osed().sc.hash("WinExec", "ROR13")
```

Expected output:

```
Input     : WinExec
Algorithm : ROR13
Hash      : 0x7C0DFCAA
```

If your hand computation doesn't match, find the iteration where you diverged
and recompute from that step.

---

## Step 6 — Hash another function name

Without any reference, compute the ROR13 hash of `LoadLibraryA` by hand up
to the first 3 bytes (`L`, `o`, `a`). Verify with `dx @$osed().sc.hash`.

Then compute the full hash using the toolkit:

```
0:000> dx @$osed().sc.hash("LoadLibraryA", "ROR13")
```

Note the result. This is the hash value you would embed in shellcode to
resolve `LoadLibraryA`.

---

## Step 7 — Other algorithms

The osed-windbg toolkit supports three algorithms:

```
0:000> dx @$osed().sc.algorithms()
```

Expected:

```
Algorithm : crc32
Algorithm : metasploit_ror13    (default, alias: "ror13")
Algorithm : rol7_add
```

Compute the CRC32 hash of `WinExec`:

```
0:000> dx @$osed().sc.hash("WinExec", "crc32")
```

When would you choose CRC32 over ROR13? If the ROR13 result contains a bad
character, you try CRC32. If that also has a bad char, you try another
algorithm, or accept encoding complexity.

---

## Checkpoint (no reference)

1. In ROR13, what are the two operations applied to the accumulator for each
   input byte?
2. `ror32(0x80000000, 1)` = what?
3. Why is the result truncated to 32 bits after each addition?
4. `WinExec` ROR13 = `0x7c0dfcaa`. Does this contain any of `\x00`, `\x0a`,
   `\x0d`? Check each byte.
5. If `0x7c0dfcaa` contained `\x0a`, what would be your options?
