# OSED x86 Bad-Character Quick Reference

**Symptom in WinDbg** | **Mechanism** | **Assembly to find**
---|---|---
Everything after a byte is missing | Termination / truncation | `test al,al`+`jz`; `cmp al,imm8`+`jz` exit; length cap
One byte missing, rest shifts left | Deletion | `cmp al,imm8`+`jz` skipping store; src/dst delta
Byte present but value changed | Transformation | `xor`/`add`/`sub`/`and`/`or`/`not` before store
Extra bytes appear | Expansion / escape decode | Destination advances faster than source
Only certain positions change | Position-dependent | Index-based branch or lookup table
Same byte differs by context | Stateful parser | `[ebp+var]` tested before comparison
First N bytes ok, then corruption | Dest overflow | Destination capacity < test length

**Pattern** | **Behavior** | **Confidence**
---|---|---
`test al,al` + `jz` (loop exit) | NUL termination | Med
`cmp al,imm8` + `jz` (skip store) | Byte deletion | Med
`cmp al,imm8` + `jz` (exit loop) | Delimiter / termination | Med
`xor al,imm8` before store | Reversible transform | High
`and al,imm8` before store | Irreversible masking | High
`add al,20h` with 41h-5Ah check | Case fold | High
Separate src/dst increments | Filtering / expansion | Med
`movsx` on length field | Signed truncation risk | High
`rep movsb` with clamped ECX | Length truncation | High

**Investigation sequence:**
`1` bp recv/ReadFile; g; db buffer -- `2` bp decode exit; db dest -- `3` bp copy exit; db final dest -- `4` compare dumps -- `5` first mismatch = restricting stage

**WinDbg commands:**
`bp <addr>` break | `db <addr> L100` bytes | `dd <addr> L20` dwords | `r eax` reg | `? @ebp+4-@ebp-12c` offset math | `db poi(@ebp-1c) L100` deref+dump | `!address <addr>` protection | `bp <a> ".if (cond) {} .else {gc}"` conditional

**Rules:**
A `cmp` proves inspection, not restriction -- follow the branch.
Deletion shifts offsets; transformation preserves them.
Signed (`jl/jg`) vs unsigned (`jb/ja`) changes which bytes pass.
Test the actual exploit path, not a different handler.
Size test sequence to destination capacity.
`memcpy`/`rep movs` do NOT stop at NUL.
Constraints are per-path, not per-binary.
Transformations may be reversible through pre-encoding.
