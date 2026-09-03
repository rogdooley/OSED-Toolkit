# recon

Static analysis and triage aid for Windows x86 exploit development (OSED),
built as a single dependency-free Go executable so it runs on an air-gapped
Win10 x86 exam machine with no Python, no pip, and no Ghidra/IDA.

It answers the recon question those tools normally answer for you: given an
unknown binary, *where is the input-handling code, and where is the dangerous
copy?* It ranks functions by exploitability signal so you can open the top few
in WinDbg (`uf <addr>`) instead of reading the whole binary.

## Subcommands

| command | input | what it does |
| --- | --- | --- |
| `recon pe <file>` | PE on disk | Static PE report: mitigations (ASLR/DEP/SafeSEH/GS/CFG), sections, categorized imports, gadget pre-count, exploitability score. Stdlib only. Supersedes the Python `peinfo`. |
| `recon triage <file>` | PE on disk | Recursive-descent disassembly, call graph, IAT resolution, and per-function ranking by dangerous sinks, input sources, stack-frame size and inline copies. |
| `recon cdb <dump.txt>` | headless-cdb text | Same ranking, driven from a WinDbg/cdb `uf` dump. Use when the target is packed/stripped and the static sweep under-recovers, or when you want to rank on your Kali box from a dump made on the exam box. |

All three default to aligned text, take `--md` for Markdown (paste into notes
or an exam report) and `--json` for tooling. `triage`/`cdb` take `--top N`
(0 = all).

## Two runtimes, one score

`triage` and `cdb` are two frontends over the same ranking core
(`internal/analysis`), so they agree on how a function is scored:

- **unbounded copy/format** (`strcpy`, `strcat`, `sprintf`, `gets`, ...): +6
- bounded copy (`strncpy`, `memcpy`, `memmove`, ...): +2 (only if no unbounded)
- reads attacker input (`recv`, `WSARecv`, `ReadFile`, `fread`, ...): +3 -
  socket/bind/listen/accept are connection *setup*, not input, and score nothing
- **input reaches an unbounded copy** - directly, or through the call graph
  from an input-reading ancestor - the classic overflow shape: +5 bonus
- **format-family call with a non-constant format string** (the format is
  attacker-influenced - OSED modules 12-13): +4 bonus; a plain format sink: +1
- inline `rep movs`/`stos`: +2
- stack-frame size, scaled +1..+5 (0x80 -> +1 up to >=0x800 -> +5; under 0x80
  scores nothing). When the copy sink is invisible (statically-linked/inlined
  CRT, so `strcpy`/`sprintf` are not imports), buffer size is the main
  discriminator, so it does not saturate.
- calls a memory/exec primitive (`VirtualProtect`/`VirtualAlloc`/...): +1
- high fan-in helper (>=6 callers, no input read): -3 (down-weights runtime plumbing)

Bare `jmp [IAT]` thunks are dropped from the ranked view. The copy weights and
the interprocedural reachability are tuned against real targets (vulnserver):
the actual `strcpy` command handlers rank at the top, the `recv` dispatcher just
below, and boilerplate (`main`) and CRT/runtime helpers sink to the bottom.

`triage` also resolves and prints, per function: referenced string literals
(format strings, command strings, protocol tokens - the fastest way to tell
what a function does without symbols) and the caller count.

## Toolkit integration

`recon` is registered as a console script and has a Python bridge so its JSON
feeds the rest of the toolkit:

```bash
recon triage target.exe --top 20     # console script (from the venv)
```

```python
from Tools.recon_bridge import pe, triage
info = pe("target.exe")               # dict: mitigations, sections, ...
hot  = triage("target.exe", top=0)    # ranked functions as dicts
# e.g. pick fixed-base modules for ROP, or feed hot[0]["start"] into WinDbg
```

The bridge finds the binary via `RECON_BIN`, then `Tools/recon/dist/`, then
`PATH`.

## Build

Requires Go once, on a networked machine, to vendor deps (already committed
under `vendor/`). After that it builds fully offline:

```bash
./build.sh            # -> dist/recon (host), dist/recon.exe (win x86), dist/recon64.exe
```

Or by hand for the exam box:

```bash
GOPROXY=off GOFLAGS=-mod=vendor GOOS=windows GOARCH=386 go build -trimpath -ldflags "-s -w" -o recon.exe .
```

Copy `recon.exe` to the exam machine. Nothing else is needed.

## Exam workflow

1. `recon pe target.exe` - read the mitigations first. It tells you whether
   the module is a fixed-base ROP source, whether SafeSEH/GS are in the way,
   and pre-counts `jmp esp` / `pop pop ret` style gadgets.
2. `recon triage target.exe --top 20` - get the ranked function list. Start at
   the top; each entry prints a ready-to-paste `uf 0x...`.
3. Open those functions in WinDbg, confirm the sink and the buffer, and build
   the crash from there (feed offsets into the toolkit's `pattern` / `badchars`
   tools).
4. If the static sweep under-recovers (packed, obfuscated, heavy indirect
   calls), fall back to the `cdb` frontend below.

### Generating a cdb dump for the `cdb` frontend

On the exam box, load the target under cdb without running it and log a
disassembly of every symboled function:

```
cdb -z target.exe
0:000> .logopen C:\dump.txt
0:000> .foreach (f { x /1 target!* }) { uf f }
0:000> .logclose
0:000> q
```

Then rank it (on the box, or copy `dump.txt` - text only, not the binary - to
Kali):

```bash
recon cdb dump.txt --top 20
```

If the module is stripped, `x target!*` yields little; in that case prefer
`recon triage` on the file directly, or dump `uf` for the specific addresses
you reach at crash time.

## Scope and honesty

This is triage-grade, not a decompiler. The static sweep favors breadth and
never crashes on bad bytes: indirect `call`/`jmp` end a path, and data
mistaken for code is decoded until it fails and then abandoned. Treat the
ranking as "read these first," not as ground truth. The `pe` mitigation and
gadget data are exact; the function ranking is a heuristic.

**Coverage on stripped binaries.** With symbols (e.g. mingw's vulnserver) the
sweep recovers the whole binary. Stripped MSVC/MFC apps reach most code through
indirect calls and function-pointer tables, so recursive descent from the entry
point alone finds little; `triage` adds function-prologue scanning
(`push ebp; mov ebp, esp` and the MSVC hot-patch form) to recover far more, but
FPO/omit-frame-pointer functions in optimized release builds are still missed.
For GUI/file-parsing overflow targets, the reliable path is dynamic: crash it,
then `uf` the crashing function in WinDbg and rank that with the `cdb` frontend.
The `pe` report needs no recovery and is exact regardless.
