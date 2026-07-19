# x86 Assembly Reference for OSED

> EXP-301 Operational Reference -- Windows x86 User-Mode

A technically precise reference for studying OSED and developing 32-bit Windows
exploits. Covers IDA Pro static analysis, WinDbg debugging, stack overflows,
DEP bypass, ROP development, ASLR bypass, format-string exploitation,
position-independent shellcode, and Windows API resolution through the PEB.

## Building the PDF

```bash
bash scripts/build-assembly-reference.sh
```

Requires `pandoc` and a TeX distribution (`pdflatex`, `xelatex`, or
`lualatex`). The script auto-detects the available engine.

Output: `Documentation/x86-osed-assembly-reference.pdf`

## Sections

| # | File | Topic |
|---|------|-------|
| 1 | [CPU execution model](01-cpu-execution-model.md) | Registers, memory, EIP, little-endian, value vs address |
| 2 | [Register reference](02-register-reference.md) | GPRs, segments (FS), sub-register aliasing, implicit usage |
| 3 | [Memory operands and pointers](03-memory-operands-and-pointers.md) | MOV vs LEA, effective addresses, size qualifiers, pointer chains |
| 4 | [Endianness](04-endianness.md) | Byte order, Python packing, debugger display |
| 5 | [EFLAGS and conditional execution](05-eflags-and-conditional-execution.md) | CMP, TEST, signed vs unsigned jumps, SETcc, CMOVcc |
| 6 | [Core instruction reference](06-core-instruction-reference.md) | Data movement, arithmetic, logic, control flow, string ops |
| 7 | [Stack fundamentals](07-stack-fundamentals.md) | Growth direction, reserve vs commit, state transitions, guard pages |
| 8 | [Function stack frames](08-function-stack-frames.md) | Prologue/epilogue, frame layout, FPO, tail calls |
| 9 | [Calling conventions](09-calling-conventions.md) | cdecl, stdcall, fastcall, thiscall |
| 10 | [Normal CALL vs RET-based invocation](10-normal-call-vs-ret-based-invocation.md) | How ROP fakes a stdcall frame |
| 11 | [Buffers and stack overflows](11-buffers-and-stack-overflows.md) | Offset calculation, cyclic patterns, bad chars, SEH, stack pivots |
| 12 | [Arithmetic in exploit development](12-arithmetic-used-in-exploit-development.md) | Two's complement, null avoidance, alignment |
| 13 | [ROP gadget semantics](13-rop-gadget-semantics.md) | Register load, exchange, deref, write, pivot, PUSHAD |
| 14 | [PUSHAD-based API calls](14-pushad-based-api-calls.md) | Push order, memory layout, building call frames |
| 15 | [DEP and page protections](15-dep-and-page-protections.md) | VirtualProtect, VirtualAlloc, protection constants |
| 16 | [ASLR and module addressing](16-aslr-and-module-addressing.md) | VA vs RVA, fixed modules, info leaks, partial overwrites |
| 17 | [PEB walking](17-windows-process-structures-and-peb-walking.md) | TEB, PEB, loader data, linked-list traversal, module discovery |
| 18 | [PE export resolution](18-pe-structures-and-export-resolution.md) | DOS/NT headers, export directory, name/ordinal/function tables |
| 19 | [Position-independent shellcode](19-position-independent-shellcode.md) | JMP-CALL-POP, stack strings, null avoidance, direction flag |
| 20 | [API hashing](20-api-hashing.md) | ROR-13-ADD, collision handling, module+function hashing |
| 21 | [String construction in shellcode](21-string-construction-in-shellcode.md) | Pushing DWORDs backward, Unicode, bad-char avoidance |
| 22 | [Format-string concepts](22-format-string-assembly-concepts.md) | %n/%hn/%hhn, parameter indexing, write-what-where |
| 23 | [IDA Pro reading guide](23-ida-pro-reading-guide.md) | Views, xrefs, stack variables, switch tables, type propagation |
| 24 | [WinDbg reading guide](24-windbg-reading-guide.md) | Commands, memory display, exceptions, breakpoints |
| 25 | [Python exploit equivalents](25-python-exploit-development-equivalents.md) | Packing, ROP construction, bad-char checking, sockets |
| 26 | [Common analyst mistakes](26-common-analyst-mistakes.md) | 18 pitfalls with explanations |
| 27 | [Fast-reference tables](27-fast-reference-tables.md) | Registers, flags, jumps, calling conventions, PE offsets, WinDbg |
| 28 | [Worked exercises](28-worked-state-transition-exercises.md) | 11 state-transition problems with full solutions |

## Editing

Edit individual section files. The PDF is rebuilt from all `*.md` files in
sort order (the numeric prefix controls sequencing). The `metadata.yaml` file
contains the title page fields.

To add a new section: create `NN-topic-slug.md` with the appropriate number
prefix. Update this README. Rebuild.
