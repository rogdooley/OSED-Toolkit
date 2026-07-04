# Chapter 6 — Decision Logic and switch Recovery

## 1. Objective

After this chapter you can read a web of conditional jumps and recover the original
control structure: distinguish a chain of `if/else if` from a nested decision tree,
recognize the four ways MSVC compiles a `switch` (if-chain, jump table, binary
search tree, and hybrid), and rebuild the source-level logic faithfully — including
which cases fall through.

## 2. Background

Everything above the level of a single comparison is built from `cmp`/`test`
setting flags and a conditional jump acting on them (Chapter 1). Source-level
constructs — `if`, `else`, `&&`, `||`, `switch` — are just *patterns* of those
jumps. The compiler has freedom in how it lays them out, and it uses that freedom
to minimize comparisons and mispredicted branches. So the same `switch` can look
completely different depending on how many cases there are and how dense their
values are. Rather than memorize each shape, learn the *decision the compiler is
making* and the shapes follow.

The key insight for `switch`: the compiler chooses its strategy based on the
**number and density of case labels**. Few cases → compare them one by one (an
if-chain). Many *dense* cases (like `0..20`) → compute an index and jump through a
**table** in O(1). Many *sparse* cases (like `1, 100, 5000`) → a **binary search**
tree of comparisons, O(log n). Recognizing which one you're in tells you
immediately how to read it.

## 3. Mental model

### if / else if / else — a linear chain

```
   cmp  eax, A
   jz   case_A
   cmp  eax, B
   jz   case_B
   jmp  default
```

Sequential `cmp`/`jz` against the *same* value, each failure falling to the next
test. This is an `if (x==A) ... else if (x==B) ... else ...`.

### Nested if / decision tree — comparisons on *different* values, branching both ways

```
   cmp  eax, ebx        ; test 1
   jle  L1
   cmp  ecx, edx        ; test 2 only reached if test 1 was false
   ...
 L1:
   cmp  esi, edi        ; a DIFFERENT test on the true side
```

The distinguishing feature: after a branch, the two sides test *different*
conditions. That's nesting (`if (a>b) { if (c>d) ... } else { if (e>f) ... }`),
not a flat chain.

### Short-circuit && and ||

```
   ; if (a && b)          |     ; if (a || b)
   cmp  a, 0              |     cmp  a, 0
   je   skip              |     jne  do_it       ; a true -> skip second test
   cmp  b, 0              |     cmp  b, 0
   je   skip              |     je   skip
 do_it: ...               |   do_it: ...
 skip:                    |   skip:
```

`&&` falls through only if *both* tests pass; the first failure jumps to skip.
`||` jumps *into* the body on the first success. The pattern of "jump out on
false" (for `&&`) vs "jump in on true" (for `||`) is how you tell them apart —
and it's derivable from the truth table, not memorized.

### switch — the four shapes

```
   (1) if-chain     : few cases, sequential cmp/je            (like if/else if)
   (2) jump table   : dense cases -> index the case value,
                      bounds-check, jmp [table + idx*4]        O(1)
   (3) binary tree  : sparse cases -> divide-and-conquer cmp   O(log n)
   (4) hybrid       : dense clusters via tables, outliers via cmp
```

## 4. Assembly examples

```asm
; Example A: jump-table switch (dense cases 0..3)
    mov     eax, [ebp+cmd]      ; the switch value
    cmp     eax, 3              ; bounds check against MAX case
    ja      loc_default         ; UNSIGNED 'ja' => also catches negative (wraps huge)
    jmp     ds:off_401100[eax*4]; jump through table indexed by the value

; the table (in .rdata): 4 dword targets
off_401100  dd offset loc_case0
            dd offset loc_case1
            dd offset loc_case2
            dd offset loc_case3
```

Derivation: the `cmp eax, 3 / ja default` is a *single unsigned bounds check* that
rejects everything outside `0..3` at once (unsigned catches negatives because they
wrap to large values — this is why the compiler uses `ja`, not `jg`). Then
`jmp ds:off_401100[eax*4]` reads the target address out of a 4-entry table indexed
by the value and jumps to it. Four dense cases → the compiler built an O(1) table.
IDA usually recognizes this and shows `jumptable ... case 0..3`.

When case values don't start at 0 or have gaps, expect a **subtract to
normalize** and possibly an **indirection table** (a byte array mapping value →
table slot):

```asm
    mov     eax, [ebp+cmd]
    sub     eax, 5              ; normalize: cases were 5..12, shift to 0..7
    cmp     eax, 7
    ja      loc_default
    movzx   ecx, byte ptr [eax + off_indexmap]  ; value -> compact slot
    jmp     ds:off_jumptab[ecx*4]
```

The `sub eax, 5` tells you the *lowest case label was 5*. The byte index map
appears when cases are dense-ish but not contiguous — it compresses the table.

```asm
; Example B: binary-search switch (sparse cases: 1, 50, 1000, 9999)
    mov     eax, [ebp+cmd]
    cmp     eax, 1000
    jg      loc_high            ; split the range
    jz      case_1000
    cmp     eax, 50
    jz      case_50
    cmp     eax, 1
    jz      case_1
    jmp     default
loc_high:
    cmp     eax, 9999
    jz      case_9999
    jmp     default
```

Divide and conquer: the first `cmp eax, 1000 / jg` halves the search space before
testing individual values. Sparse cases → the compiler avoids a giant mostly-empty
table and does O(log n) comparisons instead. Reading it: reconstruct the *set of
constants tested* — those are your case labels — ignoring the tree shape, which is
just an efficiency detail.

```asm
; Example C: fallthrough (cases share code)
case_A:
case_B:                         ; no jump between them -> A falls through to B
    ; shared body for A and B
    jmp     switch_end
case_C:
    ...
switch_end:
```

Two case labels with *no jump between them* means the source had `case A:` with no
`break`, falling into `case B:`. The absence of a terminating `jmp`/`break` is the
evidence.

## 5. Equivalent C

```c
// A
switch (cmd) {              // dense 0..3 -> jump table
    case 0: ...; break;
    case 1: ...; break;
    case 2: ...; break;
    case 3: ...; break;
    default: ...;
}

// B
switch (cmd) {              // sparse 1,50,1000,9999 -> binary search
    case 1: ...; break;
    case 50: ...; break;
    case 1000: ...; break;
    case 9999: ...; break;
    default: ...;
}

// C
switch (x) {
    case 'A':
    case 'B': shared(); break;   // fallthrough: A has no break
    case 'C': other(); break;
}
```

## 6. Reverse engineering methodology

1. **Map the branches first.** In IDA graph view, sketch each `cmp`/`test` + jump
   and where both edges go. The *shape* of the graph reveals the structure.
2. **Chain or tree?** Are successive tests on the *same* value (chain) or do the
   two sides of a branch test *different* things (tree/nesting)?
3. **Spot the switch signature:** a single **bounds check** (`cmp; ja default`)
   followed by an **indirect `jmp` through a table** = jump-table switch. Read the
   table from `.rdata` to list the cases and targets.
4. **Normalize.** A `sub eax, K` before the bounds check means the lowest case
   label is `K`. A byte index-map means sparse-but-clustered cases.
5. **Binary-search switch:** a tree of `cmp value, C / jz case_C / jg|jl` splits.
   Collect every constant compared for equality — that's the full case-label set.
6. **Fallthrough:** adjacent case labels with no intervening jump = missing
   `break`.
7. **Reconstruct and verify.** Rebuild the `switch`/`if` and confirm in WinDbg by
   forcing the switch value (`r eax = ...` at the check) and watching which target
   the indirect `jmp` takes.

## 7. Common compiler idioms

- **`cmp x, MAX / ja default`** — the unsigned bounds check guarding a jump table;
  `ja` (not `jg`) so negatives are rejected as huge unsigned values in one test.
- **`jmp ds:table[reg*4]`** — the indirect jump-table dispatch.
- **`sub x, LOW`** before the bounds check — rebasing non-zero case labels; `LOW`
  = smallest label.
- **Two-level table** (byte index map + dword jump table) — sparse/clustered cases
  compressed.
- **`test`/`and` for flag checks** — `test al, 4 / jnz` is `if (flags & 4)`, a
  bitmask test, not an equality switch.
- **Chains of `cmp/je` on a `char`** — small `switch` on characters compiled as an
  if-chain because there are too few cases to justify a table.

## 8. Common mistakes

- **Reading a jump table's data as code.** The dwords after the indirect jump are
  *addresses*, not instructions. IDA usually marks them; if it doesn't, don't
  disassemble them.
- **Missing the `sub`/normalization** and mislabeling the cases (calling case 5
  "case 0").
- **Confusing a decision tree with an if-chain.** If the two branch arms test
  different variables, it's nested `if`s, not a flat `switch`/chain.
- **Overlooking fallthrough** and inserting a phantom `break`, changing the logic.
- **Reading `ja` as signed.** The bounds check is deliberately unsigned to fold the
  "negative" case into "too large." Treating it as `jg` misses that negatives hit
  default.
- **Trusting IDA's "jumptable for switch" comment as the case *values*.** It gives
  targets and indices; confirm the value→case mapping through any `sub`/index-map.

## 9. Exercises

1. Given `cmp eax, 6 / ja default / jmp ds:tbl[eax*4]` with a 7-entry table, what
   are the case labels and how many are there? What if a `sub eax, 2` preceded the
   `cmp`?
2. Distinguish, from assembly alone, `if (a && b)` from `if (a || b)`. Write both
   jump patterns and explain the difference by the truth tables.
3. You find `cmp eax, 100 / jg hi / jz c100 / cmp eax, 10 / jz c10 ...`. Is this a
   jump table or a binary search? Why did the compiler choose it? List the case
   labels.
4. Two case labels sit back-to-back with no jump between them. What does that mean
   in the source, and what's the risk if you miss it?

## 10. Summary

- All higher-level control flow is patterns of `cmp`/`test` + conditional jumps;
  recover structure from the *pattern*, not from keywords that no longer exist.
- Same-value sequential tests = if-chain; different-value branching arms = nested
  decision tree.
- MSVC compiles `switch` four ways chosen by case count/density: if-chain (few),
  jump table (dense, O(1)), binary search (sparse, O(log n)), hybrid.
- The jump-table signature is an unsigned bounds check (`cmp; ja`) + indirect
  `jmp` through a `.rdata` table; a preceding `sub` reveals the lowest label.
- Adjacent case labels with no jump between them are C fallthrough (missing
  `break`). Verify the value→target mapping in WinDbg.
