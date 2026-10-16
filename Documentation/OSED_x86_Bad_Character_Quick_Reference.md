# OSED x86 Bad-Character Quick Reference

**Print this page.  One side.  Exam desk reference.**

---

## WinDbg Symptom Table

| Symptom in WinDbg | Most likely mechanism | What to check next |
|---|---|---|
| Everything after a byte is missing | Termination or truncation | `test al,al`/`jz`; `cmp al,imm8`/`jz` to loop exit; length cap |
| One byte missing, following bytes shift left | Deletion | `cmp al,imm8`/`jz` skipping the store; src/dst pointer delta |
| Byte present but value changed | Substitution or transformation | `xor`/`add`/`sub`/`and`/`or`/`rol`/`not` before store |
| Extra bytes appear | Expansion or escape decoding | Destination advances faster than source in the copy loop |
| Only certain positions change | Position-dependent transformation | Index-based branch or lookup table in the processing loop |
| Same byte differs depending on preceding bytes | Stateful parser | State variable (`[ebp+var]`) tested before the comparison |
| First N bytes correct, then stack corruption | Destination overflow from test sequence | Destination capacity < test length; reduce test range |

---

## Assembly-Pattern Recognition

| Pattern | Suspected behavior | Confidence |
|---|---|---|
| `test al,al` + `jz` (loop exit) | NUL termination | Medium |
| `cmp al, imm8` + `jz` (skip store) | Byte deletion | Medium |
| `cmp al, imm8` + `jz` (exit loop) | Delimiter / termination | Medium |
| `xor al, imm8` before store | Reversible transform | High |
| `and al, imm8` before store | Irreversible masking | High |
| `add al, 20h` with 41h-5Ah range check | Case fold (upper->lower) | High |
| Separate src/dst index increments | Filtering or expansion | Medium |
| `[ebp+var]` test before byte comparison | Context-dependent | Low |
| `movsx` on length field | Signed truncation risk | High |
| `rep movsb` with clamped ECX | Length truncation | High |

---

## Investigation Sequence

```text
1. Locate input     bp <recv/ReadFile>;  g;  db <buffer> L<count>
2. After decode     bp <decode_exit>;    g;  db <dest> L<decoded_len>
3. After copy       bp <copy_exit>;      g;  db <final_dest> L<copy_len>
4. Compare          side-by-side db dumps at each stage
5. First mismatch   = the stage that introduces the restriction
```

---

## Key WinDbg Commands

```text
bp <addr>                 breakpoint
bp <addr> ".if (cond) {} .else {gc}"   conditional break
db <addr> L100            byte dump
dd <addr> L20             dword dump
r eax                     register value
? @ebp+4 - @ebp-12c      offset arithmetic
db poi(@ebp-1c) L100      dereference pointer, dump
!address <addr>           region info and protection
```

---

## Critical Reminders

- A `cmp` proves inspection, not restriction.  **Follow the branch target.**
- Deletion shifts offsets.  Transformation preserves them.
- Signed (`jl/jg`) vs unsigned (`jb/ja`) changes which bytes pass.
- Test the actual exploit path, not a different command or handler.
- Size the test sequence to fit the destination buffer.
- `memcpy`/`rep movs` with an explicit count do NOT stop at NUL.
- Bad-char constraints are per-path, not per-binary.
- A transformation may be reversible through pre-encoding.
