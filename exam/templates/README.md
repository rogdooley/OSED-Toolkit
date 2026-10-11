# Exam Exploit Templates

Standalone Python scripts for OSED exam exploit development.
Each one is self-contained (no imports beyond stdlib + optional Keystone).
Copy the one that fits your target, fill in the constants, and run.

All scripts run on **Kali** (network exploits) or the **exam Windows box**
(file-based exploits). Python 3.7+. No pip dependencies except Keystone
for inline assembly (optional -- you can always use pre-built `.bin` files).


## Which Template Do I Use?

```
Is the target DEP-enabled?
  YES --> Is ASLR also enabled?
            YES --> aslr_leak.py (leak address first, then DEP bypass)
            NO  --> dep_bypass.py (ROP chain + shellcode from files)
  NO  --> Is it a stack overflow?
            YES --> Is the buffer big enough for shellcode?
                      YES --> stack_bof.py (JMP ESP + shellcode)
                      NO  --> egghunter.py (small stub finds shellcode elsewhere)
            NO  --> Is it an SEH overwrite?
                      YES --> seh_exploit.py (POP POP RET + short jmp)
                      NO  --> Is it a format string?
                                YES --> format_string.py
                                NO  --> Start with stack_bof.py and adapt
```


## Universal Workflow

Every template (except format_string and aslr_leak) follows the same
progression. Change `MODE` at the top of the script and re-run:

| Step | MODE        | What you do                                          |
|------|-------------|------------------------------------------------------|
| 1    | `crash`     | Confirm the target crashes at your buffer size       |
| 2    | `pattern`   | Send cyclic pattern, note EIP/nSEH in WinDbg        |
| 3    | `offset`    | Paste the value, get the byte offset                 |
| 4    | `eip`       | Overwrite with 0x42424242, confirm control in WinDbg |
| 5    | `badchars`  | Send 0x01-0xFF, compare in memory dump               |
| 6    | `exploit`   | Full payload with shellcode                          |

After each step, update the constants at the top of the script
(OFFSET, BADCHARS, JMP_ESP, etc.) before moving to the next mode.


## Shellcode: Three Ways to Provide It

Every template accepts shellcode in three ways (tried in this order):

### Option 1: Inline Assembly (Keystone)

Paste assembly directly into the script. Requires `keystone-engine`
(installed by the exam bundle's `install.bat`).

```python
SHELLCODE_ASM = r"""
    xor ecx, ecx
    push ecx
    push 0x6578652e
    push 0x636c6163
    mov eax, esp
    push ecx
    push eax
    call dword ptr [ebp-0x28]
"""
```

This is assembled at runtime. `jmp short` is automatically converted
to `jmp` for Keystone compatibility. Comments (`;` and `#`) work in
the assembly but are stripped before assembling.

### Option 2: Binary File

Point at a `.bin` file from the emitter or any other source:

```python
SHELLCODE_FILE = "shellcode.bin"
```

### Option 3: Inline Bytes

Paste raw Python bytes:

```python
SHELLCODE = (
    b"\x31\xc9\x51\x68\x2e\x65\x78\x65"
    b"\x68\x63\x61\x6c\x63\x89\xe0\x51"
    b"\x50\xff\x55\xd8"
)
```

If you set more than one, priority is: ASM > file > bytes.


## Template Reference

---

### stack_bof.py -- Stack Buffer Overflow (JMP ESP)

**When:** No DEP, no ASLR. Classic stack overflow with enough room
for shellcode after EIP.

**Key constants to fill in:**

| Constant       | What it is                          | How to find it               |
|----------------|-------------------------------------|------------------------------|
| `TARGET_HOST`  | IP of the vulnerable machine        | Given in the exam            |
| `TARGET_PORT`  | Port the service listens on         | Given / nmap                 |
| `PREFIX`       | Protocol framing before overflow    | e.g. `b"TRUN /.:/"`, `b"http://"` |
| `SUFFIX`       | Protocol framing after overflow     | e.g. `b"\r\n"`              |
| `OFFSET`       | Bytes to reach saved EIP            | pattern + offset mode        |
| `JMP_ESP`      | Address of a JMP ESP gadget         | `!mona jmp -r esp`          |
| `BADCHARS`     | List of forbidden byte values       | badchars mode                |

**Layout:**
```
[PREFIX][A * OFFSET][JMP ESP][NOP sled][shellcode][SUFFIX]
```

---

### dep_bypass.py -- DEP Bypass with ROP

**When:** DEP is enabled. You need a ROP chain to call VirtualAlloc
or VirtualProtect before your shellcode can execute.

**Key constants (in addition to the basics):**

| Constant       | What it is                              | How to find it              |
|----------------|-----------------------------------------|-----------------------------|
| `ROP_FILE`     | Path to raw ROP chain bytes             | Built manually or with mona |
| `ROP_CHAIN`    | List of gadget addresses (alternative)  | Manual gadget search        |
| `ALIGN_AFTER_ROP` | Padding between ROP end and shellcode | Usually `b""` or a few NOPs |

**ROP chain as a file:** Build the chain as raw packed bytes (each
address as 4 little-endian bytes) and save to a `.bin` file.

**ROP chain inline:** List addresses directly:
```python
ROP_CHAIN = [
    0x10015442,   # POP EAX; RET
    0x10104048,   # ptr to VirtualAlloc IAT
    0x1001eaf1,   # MOV EAX,[EAX]; RET
    0x10015442,   # POP EAX; RET  (placeholder for args)
    # ...
]
```

**Layout:**
```
[PREFIX][A * OFFSET][ROP chain][alignment][NOP sled][shellcode][SUFFIX]
```

The first DWORD of the ROP chain overwrites saved EIP (typically a
stack pivot or the first gadget).

---

### seh_exploit.py -- SEH Overwrite

**When:** The overflow triggers an exception and you control the SEH
chain. You see your pattern in `!exchain` output.

**Key constants:**

| Constant       | What it is                          | How to find it                |
|----------------|-------------------------------------|-------------------------------|
| `NSEH_OFFSET`  | Bytes to reach the nSEH pointer     | pattern + offset mode         |
| `POP_POP_RET`  | POP r32; POP r32; RET gadget        | `!mona seh`                   |
| `SHORT_JMP`    | Usually `b"\xeb\x06"` (jmp +6)     | Standard, adjust if needed    |

**Layout:**
```
[PREFIX][A * NSEH_OFFSET][nSEH: short jmp][SE handler: POP POP RET][NOP sled][shellcode][SUFFIX]
```

**How it works:** Exception fires -> OS walks SEH chain -> hits your
handler (POP POP RET) -> returns to nSEH -> short jmp over the handler
bytes -> lands in your NOP sled -> shellcode executes.

**Important:** The offset is to **nSEH**, not to EIP. nSEH is 4 bytes
before the SE handler in the chain.

---

### aslr_leak.py -- ASLR Bypass via Info Leak

**When:** ASLR is enabled and you can get the target to leak a pointer
(through a format string, an overread, or a print that includes a
stack/heap address).

**Modes:** `leak`, `exploit`, `both`

**Key constants:**

| Constant        | What it is                              | How to find it              |
|-----------------|-----------------------------------------|-----------------------------|
| `LEAK_PAYLOAD`  | Bytes that trigger the info leak        | Target-specific             |
| `LEAK_REGEX`    | Regex to extract the address from output| Examine the leak response   |
| `LEAK_INDEX`    | Which regex match is the address        | Count the matches           |
| `MODULE_OFFSET` | Offset of leaked addr from module base  | `leaked_addr - base` in WinDbg |
| `GADGET_OFFSETS`| Dict of gadget names to base offsets    | Static analysis of the DLL  |
| `ROP_TEMPLATE`  | Ordered list of gadget names + constants| Your ROP chain design       |

**Two-stage flow:**
1. `MODE = "leak"` -- sends LEAK_PAYLOAD, parses response, prints base address
2. `MODE = "exploit"` -- asks for the base address, rebases all gadgets, sends final payload
3. `MODE = "both"` -- does both in sequence (same connection or two connections)

**Defining the ROP chain with symbolic names:**
```python
GADGET_OFFSETS = {
    "pop_eax":      0x15442,
    "mov_eax_eax":  0x1eaf1,
    "virtualalloc": 0x04048,
}

ROP_TEMPLATE = [
    "pop_eax",          # resolved to base + 0x15442
    "virtualalloc",     # resolved to base + 0x04048
    "mov_eax_eax",      # resolved to base + 0x1eaf1
    0x00000201,         # constant (dwSize), used as-is
    0x00000040,         # constant (PAGE_EXECUTE_READWRITE)
]
```

---

### egghunter.py -- Egghunter (Small Buffer)

**When:** The buffer that overwrites EIP is too small for shellcode.
You can place shellcode somewhere else in memory (different input field,
earlier request, environment variable, etc.).

**Key constants:**

| Constant        | What it is                          | How to find it              |
|-----------------|-------------------------------------|-----------------------------|
| `EGG_TAG`       | 4-byte marker (default: `w00t`)     | Usually keep the default    |
| `JMP_ESP`       | Redirect gadget                     | `!mona jmp -r esp`         |
| `EGG_PREFIX`    | Framing for the egg delivery        | Target-specific             |

**Two payloads are sent:**
1. **Egg delivery:** `[EGG_PREFIX][w00tw00t][shellcode][EGG_SUFFIX]`
   sent to a different input/field that lands in memory
2. **Overflow:** `[A * OFFSET][JMP ESP][NOP sled][egghunter stub]`
   the 32-byte egghunter searches memory for `w00tw00t` and jumps there

**Customize `deliver_egg()`** for your target. The default sends it as
a separate TCP connection to the same port. You might need to:
- Send it in a different protocol command in the same connection
- Write it to a file the target reads
- Put it in an HTTP header or POST body

The built-in egghunter uses the NtAccessCheckAndAuditAlarm syscall
technique (32 bytes). Replace the `EGGHUNTER` variable if you need
a different variant.

---

### format_string.py -- Format String Attacks

**When:** The target passes user input directly to printf/sprintf
without a format specifier.

**Modes:** `probe`, `read`, `write`, `exploit`

**Workflow (different from the standard progression):**

| Step | MODE     | What you do                                         |
|------|----------|-----------------------------------------------------|
| 1    | `probe`  | Send `AAAA%08x.%08x...` and look for `41414141`    |
| 2    | `read`   | Read memory at an address using `%s` or `%x`        |
| 3    | `write`  | Write a value to an address using `%n` / `%hn`      |
| 4    | `exploit`| Combine write + shellcode                           |

**Key constants:**

| Constant       | What it is                              | How to find it              |
|----------------|-----------------------------------------|-----------------------------|
| `FMT_OFFSET`   | Stack position where input appears      | probe mode (look for 41414141) |
| `READ_ADDR`    | Address to read with `%s`               | Target-specific             |
| `WRITE_ADDR`   | Address to overwrite (e.g., GOT entry)  | `objdump -R` or IDA        |
| `WRITE_VALUE`  | Value to write there (e.g., stack addr) | WinDbg inspection           |

**How the write works:** The script uses two `%hn` writes (short writes)
to avoid printing millions of characters. It writes the low 2 bytes to
`WRITE_ADDR` and the high 2 bytes to `WRITE_ADDR + 2`.

---

### badchars_ref.py -- Bad Character Generator

**Not an exploit template.** Standalone utility to generate bad character
test arrays in any format. Copy the output into your exploit script.

```bash
# Python bytes (default), excluding null + CR + LF:
python3 badchars_ref.py 00 0a 0d

# C array:
python3 badchars_ref.py --format c 00

# Raw hex string:
python3 badchars_ref.py --format hex 00 0a 0d
```

Also contains a ready-to-copy `BADCHARS_ALL` constant (0x01-0xFF)
at the top of the file. Open the file and copy it directly.


## Protocol Framing Quick Reference

The `PREFIX` and `SUFFIX` constants handle protocol framing so the
overflow payload reaches the vulnerable buffer. Common examples:

| Target Type     | PREFIX                        | SUFFIX     |
|-----------------|-------------------------------|------------|
| HTTP GET path   | `b"http://"`                  | `b""`      |
| HTTP GET header | `b"GET / HTTP/1.1\r\nHost: "` | `b"\r\n\r\n"` |
| HTTP POST body  | `b"POST / HTTP/1.1\r\n..."`   | `b"\r\n"`  |
| POP3 USER       | `b"USER "`                    | `b"\r\n"`  |
| POP3 PASS       | `b"PASS "`                    | `b"\r\n"`  |
| Vulnserver TRUN | `b"TRUN /.:/"`                | `b""`      |
| FTP USER        | `b"USER "`                    | `b"\r\n"`  |
| Raw TCP         | `b""`                         | `b""`      |
| File-based      | `b""`                         | `b""`      |

For multi-line protocols (login before exploit), uncomment the
`banner = s.recv(1024)` line in the transport section and add
extra send/recv calls as needed.


## File-Based Exploits

Set `PROTOCOL = "file"` and `OUTPUT_FILE = "payload.m3u"` (or `.wax`,
`.pls`, etc.). The script writes the payload to disk instead of sending
it over the network. Transfer the file to the target machine and open
it with the vulnerable application.


## WinDbg Quick Reference

After sending a pattern, check EIP and SEH:

```
r eip                          # current EIP value
!exchain                       # SEH chain (for SEH exploits)
dd esp L8                      # first 8 DWORDs on the stack
dc esp L20                     # stack as ASCII
db <addr>                      # dump bytes at address
!mona jmp -r esp               # find JMP ESP gadgets
!mona seh                      # find POP POP RET gadgets
bp <addr>                      # set breakpoint
g                              # go (continue execution)
```

Compare badchars in memory:
```
db <addr>                      # dump the buffer
# Compare visually against the expected 01 02 03 04 05...
# Any byte that's missing, changed, or truncates the rest is bad.
```


## Typical Exam Checklist

1. [ ] Identify the vulnerability (crash the target)
2. [ ] Find the offset (cyclic pattern)
3. [ ] Confirm EIP control (0x42424242)
4. [ ] Test bad characters (full 01-FF test)
5. [ ] Find redirect gadget (JMP ESP / POP POP RET / ROP pivot)
6. [ ] Build shellcode (emitter on Kali, or Keystone on the exam box)
7. [ ] Choose delivery: reverse shell / copy+run / move+run
8. [ ] Build ROP chain if DEP is on
9. [ ] Test with a calc pop first, then switch to real payload
10. [ ] Verify with WinDbg breakpoints before blind execution
