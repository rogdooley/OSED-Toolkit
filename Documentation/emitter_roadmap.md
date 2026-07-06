# Emitter Roadmap

What could be added to the shellcode emitter, why it matters, and how much work each item is.

Effort scale: **S** = hours, **M** = a day or two, **L** = several days.

---

## Already done (as of 2026-06)

| Item | Notes |
|---|---|
| `reverse_shell` template | WSAStartup → WSASocketA → connect → CreateProcessA |
| `copy_then_run` template | CopyFileA → WinExec |
| `tcp_download` template | TCP recv → VirtualAlloc → write to disk → WinExec |
| `tcp_stager` template | TCP recv → VirtualAlloc(RWX) → call stage 2 |
| `encode.py` badchar-safe immediates | encode_dword / encode_word / safe_push helpers |
| Manifest badchars wired to TemplateConfig | Was silently broken; now fixed |
| `push 0x80` sign-extension bug fixed | `push imm8` sign-extends; `FILE_ATTRIBUTE_NORMAL` was wrong |
| `tcp_stage_server.py` | Serves staged payloads (4-byte length + raw bytes) |

---

## API Database gaps

### `VirtualFree`
**Why:** Every `tcp_download` / `tcp_stager` build allocates via `VirtualAlloc` but never frees. Not a problem for shellcode that exits, but becomes one in long-running stage chains where multiple loads happen in the same process.  
**How:** One `APIRecord` entry in `api_database.py`. No new template needed — templates call it explicitly.  
**Effort:** S

### `WriteProcessMemory` + `CreateRemoteThread` + `OpenProcess`
**Why:** These three together enable classic process injection — write shellcode into a remote process and create a thread to run it. The next natural step after staged payloads.  
**How:** Three `APIRecord` entries. Then a `process_inject` template that: `OpenProcess` → `VirtualAllocEx` (also needs adding) → `WriteProcessMemory` → `CreateRemoteThread`.  
**Effort:** M (APIs are S, template is M — needs `VirtualAllocEx` too)

### `VirtualAllocEx`
**Why:** Required for remote process injection. `VirtualAlloc` only allocates in the current process.  
**How:** One `APIRecord` entry.  
**Effort:** S

### `SetFileAttributesA`
**Why:** Hide dropped files by setting the hidden/system attribute immediately after `CreateFileA` / `WriteFile`. Useful for `tcp_download` and `copy_then_run` payloads.  
**How:** One `APIRecord` entry. Add an optional call in `tcp_download` and `copy_then_run` templates.  
**Effort:** S

### `GetTempFileNameA`
**Why:** `GetTempPathA` is already in the DB but unused. Pairing it with `GetTempFileNameA` lets the shellcode write to a unique temp path without hardcoding one in the manifest string — reduces analyst fingerprinting.  
**How:** One `APIRecord` entry. Add a variable slot for the generated path; templates populate it before `CreateFileA`.  
**Effort:** S (API entry) + M (wiring into templates cleanly)

---

## Payload templates

### `process_inject`
**Why:** Inject stage 2 into a running process (e.g. explorer.exe, svchost.exe) rather than running it in the shellcode's own process. Harder to attribute, survives the original process dying.  
**How:** Template needs `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`. Also needs a variable slot for the target PID (caller populates it before the template runs, or it's hardcoded in the manifest).  
**Effort:** M

### `bind_shell` (complete)
**Why:** The current `bind_shell.py` is a scaffold — `bind` / `listen` / `accept` are TODO stubs. Completing it makes the toolkit symmetric (connect-back and bind).  
**How:** Fill in the three missing API calls. All three (`bind`, `listen`, `accept`) are already in `api_database.py`.  
**Effort:** S

### HTTP/1.0 download (`http_download`)
**Why:** Download stage 2 from a plain HTTP server (nginx, Python's `http.server`) without a custom TCP protocol. More operational flexibility than the raw TCP server.  
**How:** Same as `tcp_download` but: after `connect`, `send` a GET request string, then in the recv loop scan for `\r\n\r\n` and start writing only from the body offset. No new APIs needed — `send` and `recv` are already in the DB.  
**Effort:** M (the header-strip scan is ~20 extra instructions but must be correct)

### Stage-chaining helper (`tcp_stager` → `tcp_stager` → payload)
**Why:** A 3-stage chain currently requires manually coordinating two servers on two ports. A thin orchestration wrapper or manifest extension would let you define the chain declaratively.  
**How:** Options: (a) a `chain` field in the manifest YAML that lists stage URLs/ports in order, (b) a Python script that builds each stage and wires the server config automatically.  
**Effort:** M

---

## Infrastructure gaps

### Badchar validation on template immediates (partially done)
**What's done:** `encode.py` provides `encode_dword` / `encode_word` / safe push helpers. IP, port, `MAKEWORD(2,2)`, and `FILE_ATTRIBUTE_NORMAL` are now encoded correctly in all network templates.  
**What's still missing:** A static analysis pass that walks the composed assembly and flags any `push imm32` or `mov reg, imm32` whose bytes overlap with the manifest badchar set. This would catch issues in future templates automatically rather than requiring manual audits.  
**Effort:** M

### Encoder stage
**Why:** Currently the shellcode must survive transport raw. Many real targets mangle bytes beyond just null/LF/CR — alphanumeric-only, printable-only, Unicode-safe. An XOR encoder wraps the payload with a small decoder stub so the transmitted bytes are in the safe range.  
**How:** A separate `encoder.py` that takes raw shellcode bytes + badchars, selects an XOR key free of badchars, produces `encoded_payload = [b ^ key for b in payload]`, then prepends a decoder stub that XOR-decodes in place and jumps to the result. The stub itself must be written in badchar-safe assembly.  
**Effort:** L (the encoder logic is S; writing a correct, badchar-safe decoder stub that handles all edge cases is L)

### Shellcode size tracking
**Why:** There's no visibility into how large the assembled payload is until after the build. Exploit delivery buffers have fixed sizes; exceeding them silently produces a non-working payload.  
**How:** After assembly, add a size check against an optional `max_bytes` field in the manifest. Warn (or error) if exceeded.  
**Effort:** S

### `VirtualAlloc` size badchar check
**Why:** The 4-byte file size received from the staging server is used directly as the `VirtualAlloc` size argument. If the file's size in little-endian contains a badchar byte, `VirtualAlloc` gets a corrupted length. This is a server-side concern (pad the file to avoid the problematic size) but worth documenting.  
**How:** Add a check in `tcp_stage_server.py` that warns if `len(data)` encoded as a 4-byte LE value contains badchars.  
**Effort:** S

### Companion file server for `tcp_download`
**Why:** `tcp_stage_server.py` covers staged payloads but `tcp_download` needs a matching server. The protocol is identical (4-byte length + raw file bytes) so the same server works — it just needs documenting clearly.  
**How:** Add a note to `tcp_stage_server.py` and the `tcp_download` manifest that the same script serves both use cases.  
**Effort:** S (documentation only)

---

## Priority order (suggested)

| Priority | Item | Effort | Reason |
|---|---|---|---|
| 1 | Badchar static analysis pass | M | Catches future template bugs automatically |
| 2 | `bind_shell` completion | S | Trivial — APIs already exist |
| 3 | `process_inject` template | M | High-value for OSED exercises |
| 4 | XOR encoder | L | Enables use against non-trivial badchar sets |
| 5 | HTTP/1.0 download | M | Operational flexibility |
| 6 | `VirtualFree` + size tracking | S | Correctness / hygiene |
| 7 | `GetTempFileNameA` / `SetFileAttributesA` | S+M | Nice-to-have operational polish |
