# Chapter 12 — The IDA and WinDbg Working Loop

## 1. Objective

After this chapter you can drive a full analysis end to end: use IDA Pro to build a
static model of an unknown binary, form hypotheses, and use WinDbg to confirm them
against live execution — closing the static/dynamic loop introduced in Chapter 0.
This chapter is the *procedure* that ties the previous eleven together, plus the
specific IDA and WinDbg commands you'll use most.

## 2. Background

Every earlier chapter ended with "confirm in WinDbg," because static reasoning
alone produces *hypotheses*, not facts. IDA shows you all the branches but none of
the values; WinDbg shows you the values along one real path. Expert analysis is a
disciplined oscillation between them: read statically until you have a specific,
falsifiable claim ("the buffer is at ebp-0x40, the copy is unbounded, EIP offset is
0x44"), then break and check it. The debugger either confirms the claim or reveals
what your static model missed — and either way you learn something concrete.

This chapter assumes you're analyzing a typical OSED target: a small Win32 x86
service or utility that reads input and mishandles it.

## 3. Mental model

The loop, concretely:

```
   +-------------------- IDA (static) --------------------+
   | 1. locate input (imports/strings)                    |
   | 2. read the handler: frame, args, locals, calls      |
   | 3. trace taint to a sink (Ch.7)                       |
   | 4. characterize the sink (Ch.9): bounded? stop cond?  |
   | 5. form a specific claim (offset, controlled bytes)   |
   +----------------------------+-------------------------+
                                | hypothesis
                                v
   +------------------- WinDbg (dynamic) -----------------+
   | 6. break at the function / sink                       |
   | 7. dump args, buffer, esp/ebp, the copy count         |
   | 8. send a marker/cyclic input; observe the crash      |
   | 9. read faulting EIP, compute offset, confirm control |
   +----------------------------+-------------------------+
                                | correction
                                v
                     back to IDA to refine
```

The rule: **never let a static claim go unverified when it matters** (an offset, a
controlled register, which branch runs). Conversely, never stare at WinDbg numbers
without a static model to interpret them — the two are useless apart.

## 4. Assembly examples

This chapter's "examples" are the tool commands themselves, applied to the earlier
`vuln` function (Chapter 10).

### IDA — building the static model

```
   Shift+F12         open the Strings window (find prompts, format strings, paths)
   Imports tab       find recv/ReadFile/strcpy/etc. -> double-click -> Xrefs (X)
   X (on a name)     list cross-references: who calls this? who uses this global?
   Spacebar          toggle graph / linear view
   N                 rename a variable/function (record your derivations!)
   Y                 set a variable's or function's type/prototype (Ch.4, Ch.8)
   Alt+Q / Structs   define a recovered struct (Ch.8), then apply with Y
   ;  (semicolon)    add a repeatable comment (e.g., "unbounded copy -> overflow")
   Ctrl+K            edit the stack frame view of the current function
   G                 jump to an address
   Tab               toggle disassembly / Hex-Rays decompiler (Ch.11)
```

Workflow on `vuln`: Imports → find `recv` → `X` to its caller → land in the handler
→ read the prologue (`sub esp, 44h`), find `lea eax,[ebp-40h]` feeding the copy →
`N` rename it `dst`, `;` comment "0x40 buffer" → analyze the copy callee (Chapter 9)
→ conclude unbounded → static claim: **EIP offset ≈ 0x44**.

### WinDbg — confirming it

```
   0:000> lm                      ; list modules; find the target's base
   0:000> x target!*              ; list symbols if available
   0:000> bp target+0x1234        ; break at the vuln function (IDA addr - imagebase + real base)
   0:000> g                       ; run until the breakpoint
   0:000> r                       ; dump registers (eip, esp, ebp, ...)
   0:000> dd @ebp-0x40 L20        ; view the destination buffer
   0:000> dd @ebp L4              ; saved EBP [ebp+0] and return address [ebp+4]
   0:000> dds @esp L8             ; stack with symbol resolution (see return addresses)
   0:000> p / t                   ; step over / trace into
   0:000> dc @esi L40             ; dump source bytes as hex+ASCII (is it my input?)
```

To measure the offset with a cyclic pattern (mona/metasploit):

```
   # generate a unique pattern of the right length and send it as input
   0:000> .load pykd ; !py mona pattern_create 200
   ... send the pattern, let it crash ...
   0:000> r eip                   ; e.g. eip = 6a413969  (a slice of the pattern)
   0:000> !py mona pattern_offset 6a413969
   [+] Pattern ... found at offset 68        ; 68 = 0x44  -> matches the static claim!
```

The dynamic offset (68 = 0x44) confirming the static geometry is the loop closing.
If it had said 76, you'd return to IDA and find the 8 bytes of saved registers or
cookie you missed (Chapter 10).

### WinDbg — confirming control

```
   # send: [ 0x44 bytes of 'A' ][ "BBBB" ][ ... ]
   0:000> g
   ... access violation ...
   0:000> r eip
   eip=42424242                   ; we control EIP. Claim proven.
   0:000> dd @esp L4              ; what's at esp now? (where a ret/jmp esp would land)
```

## 5. Equivalent C

Not applicable — this chapter is procedure and tooling. The "source" being
reconstructed is the analyst's own workflow: *hypothesize statically, prove
dynamically, refine.*

## 6. Reverse engineering methodology

A complete pass on an unknown target:

1. **Triage in IDA.** Let auto-analysis finish. Skim Strings and Imports to
   understand what the program is and where input enters.
2. **Find the input handler.** Xref from `recv`/`ReadFile`/`fread`/argv to the
   function that processes input.
3. **Reconstruct that function** (Chapters 3–4): prologue, frame size, args, locals,
   calls, return. Rename and comment as you go — your annotations *are* the analysis.
4. **Trace taint to a sink** (Chapter 7). Rename tainted buffers so the flow is
   visible.
5. **Characterize the sink** (Chapters 9–10): element size, stop condition, bound;
   compute the static offset and note protections (`/GS`, SEH).
6. **State a falsifiable hypothesis.** Write it down: "offset 0x44 to EIP, ~0x200
   controllable bytes, no cookie."
7. **Attach WinDbg** and break at the handler. Dump args, the buffer, esp/ebp.
   Confirm the frame matches your static model.
8. **Drive the sink** with a marker/cyclic input; capture the crash; compute the
   offset; reconcile any difference with the static model.
9. **Prove control** (EIP = your bytes), then move to whatever comes next
   (bad-char analysis, space, module/gadget selection) — beyond this guide's scope
   but built on exactly this loop.
10. **Record everything** in IDA (names, comments, struct types) so a second pass —
    or the exam clock — starts from your reconstructed model, not raw disassembly.

## 7. Common compiler idioms

Tooling conventions rather than compiler ones, but worth internalizing:

- **IDA rebases** to a preferred image base (often `0x400000` for x86 exes). WinDbg
  shows the *actual* loaded base (ASLR may relocate). Convert addresses:
  `real_addr = IDA_addr - IDA_base + WinDbg_base`. Getting this mapping wrong is the
  most common "my breakpoint never hits" cause.
- **`sub_`, `loc_`, `dword_`, `off_`, `unk_`** prefixes are IDA's "I guessed from the
  address" markers (Chapter 0). Replace them with real names as you learn them.
- **Hex-Rays (`F5`/`Tab`)** gives a fast C approximation; treat it as a strong
  hypothesis to verify against the disassembly, especially in FPO code (Chapter 11).
- **WinDbg `dds`/`dps`** resolve stack/pointer values to symbols — invaluable for
  reading return addresses and function pointers off the stack.
- **`!py mona`** (needs pykd) automates pattern creation/offset, bad-char comparison,
  and module property listing — the standard OSED companion.

## 8. Common mistakes

- **Breakpoint address math wrong.** Forgetting the IDA-base ↔ WinDbg-base
  conversion (especially under ASLR). Verify with `lm` and `bp <module>+<offset>`.
- **Confirming nothing.** Reading statically and declaring victory. The debugger is
  not optional for offsets and controlled-register claims.
- **Observing without a hypothesis.** Single-stepping aimlessly in WinDbg without a
  static claim to test wastes time; know what you're looking for.
- **Not recording derivations.** If your IDA database has no renames or comments
  after an hour, you'll re-derive the same things next session. Annotate relentlessly.
- **Trusting one dynamic run as the whole behavior.** The path you observed depends
  on your input; a different input exercises different branches (Chapter 0).
- **Ignoring ASLR/rebasing when reading absolute addresses** dumped from memory —
  translate them back to IDA space before cross-referencing.

## 9. Exercises

1. IDA shows the vulnerable function at `0x00401234` with image base `0x00400000`.
   WinDbg's `lm` shows the module loaded at `0x00E80000`. What `bp` command sets a
   breakpoint at that function?
2. Write the WinDbg commands to: break at a function, dump its two stack arguments,
   dump a 0x40-byte buffer at `ebp-0x40`, and show the saved return address.
3. Your static analysis says the copy moves 0x100 bytes (`rep movsd`, ecx=0x40).
   Describe the WinDbg steps to confirm exactly how many bytes moved and where they
   landed.
4. You set a breakpoint and it never triggers. List three likely causes and the
   command you'd run to diagnose each.

## 10. Summary

- Real analysis oscillates between IDA (all branches, no values) and WinDbg (all
  values, one path); a claim that matters is not finished until the debugger
  confirms it.
- In IDA: find input via Imports/Strings, follow xrefs to the handler, reconstruct
  the frame, trace taint, characterize the sink — and record every derivation with
  renames, comments, and types.
- In WinDbg: break at the handler/sink, dump args/buffer/esp/ebp, drive with a
  marker or cyclic pattern, read faulting EIP, compute and reconcile the offset,
  prove control.
- Mind the IDA-base ↔ WinDbg-base conversion; it's the top reason breakpoints
  "don't work."
- The loop is the method: hypothesize statically, prove dynamically, refine — for
  every load-bearing conclusion in this guide.
