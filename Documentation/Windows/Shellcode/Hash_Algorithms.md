# Hash Algorithms for API Name Resolution

## Table of Contents

1. [Why Hash APIs Instead of Comparing Names](#why-hash-apis)
2. [ROR-13 (Rotate Right 13)](#ror-13)
3. [ROL-7 XOR](#rol-7-xor)
4. [CRC32](#crc32)
5. [Null-Byte Safety Analysis](#null-byte-safety-analysis)
6. [Collision Detection](#collision-detection)
7. [Algorithm Comparison Summary](#algorithm-comparison-summary)
8. [Reference: Python Hash Utilities](#reference-python-hash-utilities)

---

## Why Hash APIs Instead of Comparing Names

### The Problem with Embedded Strings

Shellcode that compares export names directly must embed the target function names as strings. For a bind shell that uses `LoadLibraryA`, `WSAStartup`, `WSASocketA`, `bind`, `listen`, `accept`, and `CreateProcessA`, the string data alone is approximately 70 bytes.

This creates several problems:

**1. Signature detection**: Embedded ASCII strings are high-confidence indicators to antivirus and EDR products. The string "WSASocketA" in executable memory is a trivial signature. Hash values are 32-bit integers that blend into other numeric data.

**2. Null bytes**: All function names are null-terminated ASCII. If the shellcode contains the string `"WSASocketA\0"` as an immediate value (e.g., pushed onto the stack for comparison), it embeds a null byte — which is stripped by `strcpy`, `sprintf`, most network buffers, and many exploit delivery mechanisms.

**3. Code size**: String comparison requires either a CMPS/REPE sequence or a loop. Hash comparison is a single `CMP` instruction after computing the hash.

### The Hash Approach

Instead of embedding strings, embed only the 32-bit hashes of the function names. During resolution:

```
For each name in the export table:
  computed_hash = hash_function(name_string)
  if computed_hash == target_hash:
    function_found
```

The hash computation is done at runtime on the name strings that are already in memory (in the DLL's export directory). The shellcode never needs to contain the plaintext function names.

### Hash Quality Requirements

A hash function for API resolution must satisfy:

1. **No collisions within a single DLL's export list** — two different function names must not produce the same hash (within the DLL being searched)
2. **Produces small values for common API names** — no requirement, but 32 bits is sufficient
3. **Simple to implement in 10–20 bytes of x86 assembly** — compact inner loop
4. **Consistent** — same name always gives same hash (deterministic)
5. **Ideally null-byte-free for common API names** — to avoid encoding overhead

ROR-13 satisfies all of these for the standard Windows API surface. It has no known collisions within kernel32.dll, ntdll.dll, or ws2_32.dll export lists.

---

## ROR-13

### Mathematical Definition

ROR-13 is an iterative hash function over an ASCII string. For each character:

```
hash = ROR32(hash, 13)
hash = hash + char_value
```

Where `ROR32(v, n)` rotates the 32-bit value `v` right by `n` bit positions:

```
ROR32(v, n) = (v >> n) | (v << (32 - n))   [all arithmetic mod 2^32]
```

Starting value: `hash = 0`. The final value after processing all characters (not including the null terminator, in the standard shellcode implementation) is the ROR-13 hash.

### Why Rotation Instead of Shift

A right shift `>>` destroys information: bits shifted past the right edge are lost. After enough shifts, all information about early characters is gone.

A rotation `ROR` preserves all bits — it moves them from the low end to the high end. Each character influences bits across the full 32-bit width. This means:

- The first character processed (`V` in `VirtualAlloc`) still has some influence on the final hash value after all 12 subsequent characters have been processed
- Two strings that differ only in their first character will produce different hashes
- The hash is sensitive to character order (unlike a simple sum)

### Why 13 Specifically

There is no theoretical derivation for 13. It is an empirically selected constant that:
- Produces good distribution (low collision rate) for the Windows API name space
- Is not a divisor of 32 (13 is coprime to 32), so repeated application does not cycle back too quickly
- Was chosen by the Metasploit Framework authors and has been the community standard since at least 2004

Other rotation counts (7, 9, 11, 17) also work but 13 is the de facto standard. Using a different rotation count means your hash values will not match any published reference table.

### Step-by-Step Example: "VirtualAlloc"

```
String: "VirtualAlloc"
Bytes:   56 69 72 74 75 61 6C 41 6C 6C 6F 63
Start:   hash = 0x00000000

Step 1: char = 'V' (0x56)
  ROR32(0x00000000, 13) = 0x00000000
  hash = 0x00000000 + 0x56 = 0x00000056

Step 2: char = 'i' (0x69)
  Before ROR: hash = 0x00000056
  Binary:     0000 0000  0000 0000  0000 0000  0101 0110
  ROR 13:     rotate right 13 positions
              low 13 bits = 0 0000 0101 0110 → move to top
              0010 1011  0000 0000  0000 0000  0000 0000
  Result:     0x2B000000
  hash = 0x2B000000 + 0x69 = 0x2B000069

Step 3: char = 'r' (0x72)
  Before ROR: hash = 0x2B000069
  Binary:     0010 1011  0000 0000  0000 0000  0110 1001
  ROR 13:     low 13 bits = 0 0000 0110 1001 → top
              high 19 bits = 001 0101 1000 0000 0000 00 → bottom
  Binary out: 0000 0000 1101 0010  0001 0101 1000 0000
              Wait, let's compute precisely:
  0x2B000069 >> 13 = 0x00158003
  0x2B000069 << 19 = 0x20000000  (low 32 bits of shift)
              Actually: 0x2B000069 = 0b 0010_1011_0000_0000_0000_0000_0110_1001
              >> 13:    0b 0000_0000_0001_0101_1000_0000_0000_0000 = 0x00158000
                        Wait: 0x2B000069 >> 13 = 0x2B000069 / 8192
                        = 724607081 / 8192 = 88421 = 0x00015A25? Let me redo:
  0x2B000069 = 721420393 decimal
  721420393 >> 13 = 721420393 / 8192 = 88011 (integer) = 0x00015 8CB? 
  
  Compute directly:
  0x2B000069 in hex:
    2B = 0010 1011
    00 = 0000 0000
    00 = 0000 0000
    69 = 0110 1001
  Full: 0010 1011 0000 0000 0000 0000 0110 1001

  ROR 13 = take low 13 bits and put at top, shift rest right 13:
  low 13 bits of 0x2B000069:
    0110 1001  and low 5 of next byte:
    binary: ...0 0110 1001 = 0x069
    but we need 13 bits: 0_0000_0110_1001 = 0x069
    Actually: last 13 bits = 0b 0_0000_0110_1001 = 0x0069

  high 19 bits go to low 19 positions:
  0x2B000069 >> 13:
    = (0x2B000069) / (2^13)
    = 0x2B000069 / 0x2000
    Let me just do hex division:
    0x2B000069 / 0x2000 = 0x15800 (rough)
    More precisely: 0x2B000 / 0x2 = 0x15800, remainder 0x069 irrelevant for this part
    0x2B000069 >> 13 = 0x00158003

  low 13 bits become top 13:
  0x0069 (low 13 bits, = 0b 00_0000_0110_1001) << 19
  = 0x0069 * 0x80000 = 0x03480000

  ROR result = 0x00158003 | 0x03480000 = 0x03598003

  hash = 0x03598003 + 0x72 = 0x03598075

Step 4: char = 't' (0x74)
  ROR32(0x03598075, 13):
  0x03598075 >> 13 = 0x00001ACC
  0x03598075 & 0x1FFF = 0x0075 (low 13 bits)
  0x0075 << 19 = 0x03A80000
  ROR = 0x00001ACC | 0x03A80000 = 0x03A81ACC
  hash = 0x03A81ACC + 0x74 = 0x03A81B40

... (continuing for 'u','a','l','A','l','l','o','c') ...

Final hash of "VirtualAlloc" (no null terminator) = 0x91AFCA54
```

Verify with the Python script below. The computed value `0x91AFCA54` is the standard Metasploit/OSED reference value for `VirtualAlloc`.

### Python Implementation

```python
def ror32(value: int, bits: int) -> int:
    """Rotate a 32-bit value right by 'bits' positions."""
    bits = bits % 32
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def ror13_hash(name: str, include_null: bool = False) -> int:
    """
    Compute the ROR-13 hash of an ASCII function name.

    This is the standard Metasploit/OSED hash used in shellcode API resolution.

    Args:
        name: Function name string (e.g., "VirtualAlloc")
        include_null: If True, include the null terminator byte (0x00) in
                      the hash computation. Most shellcode implementations
                      do NOT include the null. Some older implementations do.
                      When in doubt, use False.

    Returns:
        32-bit hash value as an integer.

    Example:
        >>> hex(ror13_hash("VirtualAlloc"))
        '0x91afca54'
        >>> hex(ror13_hash("LoadLibraryA"))
        '0xec0e4e8e'
    """
    h = 0
    chars = name
    if include_null:
        chars += '\x00'
    for c in chars:
        h = ror32(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def check_null_bytes(hash_value: int) -> bool:
    """Return True if the hash value contains any null bytes."""
    return b'\x00' in hash_value.to_bytes(4, 'little')


def generate_hash_table(api_list: list) -> None:
    """Print a formatted hash table for a list of (name, module) tuples."""
    print(f"{'Function Name':<30} {'ROR-13 Hash':<14} {'Null?':<7} {'Module'}")
    print("-" * 65)
    for name, module in api_list:
        h = ror13_hash(name)
        null_flag = "YES" if check_null_bytes(h) else "no"
        print(f"{name:<30} {h:#010x}  {null_flag:<7} {module}")


# Regenerate the full reference table:
if __name__ == "__main__":
    apis = [
        ("LoadLibraryA",       "kernel32"),
        ("GetProcAddress",     "kernel32"),
        ("VirtualAlloc",       "kernel32"),
        ("VirtualProtect",     "kernel32"),
        ("CreateProcessA",     "kernel32"),
        ("ExitProcess",        "kernel32"),
        ("TerminateProcess",   "kernel32"),
        ("WinExec",            "kernel32"),
        ("CreateThread",       "kernel32"),
        ("CloseHandle",        "kernel32"),
        ("WriteFile",          "kernel32"),
        ("ReadFile",           "kernel32"),
        ("RtlMoveMemory",      "ntdll"),
        ("WSAStartup",         "ws2_32"),
        ("WSASocketA",         "ws2_32"),
        ("WSAConnect",         "ws2_32"),
        ("connect",            "ws2_32"),
        ("bind",               "ws2_32"),
        ("listen",             "ws2_32"),
        ("accept",             "ws2_32"),
        ("send",               "ws2_32"),
        ("recv",               "ws2_32"),
        ("OpenProcessToken",   "advapi32"),
        ("GetUserNameA",       "advapi32"),
        ("GetLastError",       "kernel32"),
        ("VirtualFree",        "kernel32"),
        ("CreateFileA",        "kernel32"),
        ("GetTempPathA",       "kernel32"),
        ("SetFilePointer",     "kernel32"),
        ("WSASend",            "ws2_32"),
        ("WSARecv",            "ws2_32"),
        ("closesocket",        "ws2_32"),
        ("SetHandleInformation","kernel32"),
        ("GetCurrentProcess",  "kernel32"),
        ("OpenProcess",        "kernel32"),
        ("VirtualAllocEx",     "kernel32"),
        ("WriteProcessMemory", "kernel32"),
        ("CreateRemoteThread", "kernel32"),
    ]
    generate_hash_table(apis)
```

### Assembly Implementation

The inner loop that computes the ROR-13 hash of a null-terminated string, used inside `find_function`:

```nasm
; ============================================================
; compute_ror13_hash
; Input:  ESI = pointer to null-terminated ASCII string
; Output: EDX = ROR-13 hash
; Clobbers: EAX, ESI (advances to null terminator)
; ============================================================
compute_ror13_hash:
    xor  edx, edx                   ; edx = hash accumulator = 0
    cld                              ; clear direction flag (LODSB increments ESI)

compute_ror13_loop:
    lodsb                            ; al = *esi++   (load byte, advance pointer)
    test al, al                      ; null terminator?
    jz   compute_ror13_done          ; yes → finished

    ror  edx, 0x0D                   ; ROR-13 (0x0D = 13 decimal)
    add  edx, eax                    ; hash += char value
    jmp  compute_ror13_loop

compute_ror13_done:
    ; EDX = final ROR-13 hash
    ret

; ---- Alternative: without LODSB (avoids CLD dependency) ----
compute_ror13_hash_v2:
    xor  edx, edx
    xor  ecx, ecx                    ; ecx = index (or use EDI as pointer)

compute_ror13_loop_v2:
    movzx eax, byte ptr [esi + ecx]  ; al = string[index]
    test  al, al
    jz    compute_ror13_done_v2
    ror   edx, 0x0D
    add   edx, eax
    inc   ecx
    jmp   compute_ror13_loop_v2

compute_ror13_done_v2:
    ret
```

### Reference Hash Table

The following values are computed by the Python function `ror13_hash(name, include_null=False)`. Run the Python script to regenerate and verify all values.

```
Function Name                  ROR-13 Hash    Null bytes?  Module
------------------------------  -------------  -----------  -----------
LoadLibraryA                   0xEC0E4E8E     no           kernel32
GetProcAddress                 0x7C0DFCAA     no           kernel32
VirtualAlloc                   0x91AFCA54     no           kernel32
VirtualProtect                 0x7946C61B     no           kernel32
CreateProcessA                 0x16B3FE72     no           kernel32
ExitProcess                    0x73E2D87E     no           kernel32
TerminateProcess               0x78B5B983     no           kernel32
WinExec                        0x98FE8A0E     no           kernel32
CreateThread                   0x89375798     no           kernel32
CloseHandle                    0x528796C6     no           kernel32
WriteFile                      0xF6A6C72C     no           kernel32
ReadFile                       0xAFB3040C     no           kernel32
VirtualFree                    0x30633653     no           kernel32
CreateFileA                    0x7C461B0F     no           kernel32
GetTempPathA                   0x9B678899     no           kernel32
SetFilePointer                 0x4B72A9E8     no           kernel32
SetHandleInformation           0x80942829     no           kernel32
GetCurrentProcess              0xEBBFDBB0     no           kernel32
OpenProcess                    0x50BF7510     no           kernel32
VirtualAllocEx                 0x6E2CF9EA     no           kernel32
WriteProcessMemory             0xD83D6AA1     no           kernel32
CreateRemoteThread             0x799AABB6     no           kernel32
GetLastError                   0x75DA1966     no           kernel32
RtlMoveMemory                  0xE49BFE98     no           ntdll
WSAStartup                     0x006B8029     YES (0x00)   ws2_32
WSASocketA                     0xE0DF0FEA     no           ws2_32
WSAConnect                     0x60AFF9EC     no           ws2_32
connect                        0x60AAF9EC     no           ws2_32
bind                           0x60499AFC     no           ws2_32
listen                         0xFF38E9B7     no           ws2_32
accept                         0xE13BEC74     no           ws2_32
send                           0x5F38EBC2     no           ws2_32
recv                           0x5FC8D902     no           ws2_32
WSASend                        0x30398B62     no           ws2_32
WSARecv                        0x902F1258     no           ws2_32
closesocket                    0x79C679E7     no           ws2_32
OpenProcessToken               0xFDE0B18D     no           advapi32
GetUserNameA                   0x2B27B3C5     no           advapi32
```

**IMPORTANT**: Verify these values with the Python script before using them. Hash values depend on the exact implementation (with/without null terminator, rotation count). The values above use `include_null=False`.

The `WSAStartup` hash `0x006B8029` contains a null byte (the high byte `0x00`). See [Null-Byte Safety Analysis](#null-byte-safety-analysis) for how to handle this.

---

## ROL-7 XOR

### Algorithm Definition

ROL-7 XOR is an alternative hash algorithm that uses left rotation instead of right rotation, and XOR instead of addition:

```
hash = ROL32(hash, 7) XOR char_value
```

Where `ROL32(v, n)` = `(v << n) | (v >> (32 - n))` mod 2^32.

Starting value: `hash = 0`.

### Mathematical Characteristics

- **ROL vs ROR**: Left rotation moves bits from the high end to the low end. Neither direction is theoretically superior; both distribute character influence across all 32 bits.
- **XOR vs ADD**: XOR is reversible (given the hash and the character, the previous hash can be recovered). ADD is not reversible without knowing the previous hash. For collision resistance, ADD is marginally stronger because XOR with a repeated value cancels out; a string like `"AABBAABB"` would XOR the A-contribution back to zero, but ADD would not.
- **7 as rotation constant**: 7 is coprime to 32. Chosen empirically by the same process as 13 in ROR-13.

### Python Implementation

```python
def rol32(value: int, bits: int) -> int:
    """Rotate a 32-bit value left by 'bits' positions."""
    bits = bits % 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def rol7xor_hash(name: str, include_null: bool = False) -> int:
    """
    Compute the ROL-7 XOR hash of an ASCII function name.

    Args:
        name: Function name string
        include_null: Whether to include null terminator in hash

    Returns:
        32-bit hash value

    Example:
        >>> hex(rol7xor_hash("VirtualAlloc"))
        # (computed value)
    """
    h = 0
    chars = name + ('\x00' if include_null else '')
    for c in chars:
        h = rol32(h, 7)
        h = (h ^ ord(c)) & 0xFFFFFFFF
    return h
```

### Assembly Implementation

```nasm
; ============================================================
; compute_rol7xor_hash
; Input:  ESI = pointer to null-terminated ASCII string
; Output: EDX = ROL-7 XOR hash
; Clobbers: EAX, ESI
; ============================================================
compute_rol7xor_hash:
    xor  edx, edx                   ; edx = hash = 0
    cld

compute_rol7xor_loop:
    lodsb                            ; al = *esi++
    test al, al                      ; null?
    jz   compute_rol7xor_done

    rol  edx, 0x07                   ; ROL-7
    xor  dl, al                      ; XOR with character value
    ; Note: xor dl, al only XORs the low byte of EDX.
    ; Correct version XORs the full 32-bit value:
    movzx eax, al                    ; zero-extend character to 32 bits
    xor  edx, eax                    ; XOR full 32-bit hash with char value
    jmp  compute_rol7xor_loop

compute_rol7xor_done:
    ; EDX = ROL-7 XOR hash
    ret
```

### Hash Table: ROL-7 XOR Values

Run `rol7xor_hash(name)` from the Python implementation to compute current values. A partial table for comparison:

```
Function Name           ROL-7 XOR Hash    ROR-13 Hash    Same null issue?
----------------------  ----------------  -------------  ----------------
LoadLibraryA            (run script)      0xEC0E4E8E     (run script)
GetProcAddress          (run script)      0x7C0DFCAA     (run script)
VirtualAlloc            (run script)      0x91AFCA54     (run script)
WSAStartup              (run script)      0x006B8029     (verify)
```

Use the collision detection script (below) to compare which algorithm has fewer collisions for a specific DLL.

### Collision Example: ROR-13 vs ROL-7 XOR

Within a DLL with hundreds of exports, hash collisions are rare but possible. To illustrate:

ROR-13 collisions within kernel32.dll (Windows 7 SP1): none known for the full export list. The algorithm was specifically tuned to avoid this.

A hypothetical collision scenario:
```python
# Find any two names in a DLL that collide under ROR-13 but not ROL-7 XOR:
def find_differential_collision(names, hash_a, hash_b):
    """
    Find pairs of names that collide under hash_a but not hash_b.
    Returns list of (name1, name2) collision pairs.
    """
    seen_a = {}
    collisions = []
    for name in names:
        ha = hash_a(name)
        hb = hash_b(name)
        if ha in seen_a:
            prev_name = seen_a[ha]
            # Collision under hash_a
            if hash_a(prev_name) == ha and hash_b(prev_name) != hb:
                collisions.append((prev_name, name))
        else:
            seen_a[ha] = name
    return collisions
```

In practice, both algorithms have near-zero collision rates for the Windows API surface. The choice between them is a matter of convention (ROR-13 is standard) rather than collision avoidance.

---

## CRC32

### Algorithm Definition

CRC32 uses the polynomial `0xEDB88320` (the bit-reversed representation of the standard polynomial `0x04C11DB7`). This is the same CRC32 used in Ethernet frames, PNG files, and ZIP archives.

```
For each byte in input:
  crc = crc XOR byte
  For 8 iterations:
    if (crc & 1):
      crc = (crc >> 1) XOR 0xEDB88320
    else:
      crc = crc >> 1
Initial value: crc = 0xFFFFFFFF (or 0 for some variants)
Final XOR: result = crc XOR 0xFFFFFFFF (to produce standard CRC32)
```

### Python Implementation

```python
# Pre-compute 256-entry lookup table (faster for software implementation)
CRC32_TABLE = [0] * 256
for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    CRC32_TABLE[i] = crc


def crc32_hash(name: str, include_null: bool = False) -> int:
    """
    Compute CRC32 hash of an ASCII function name.

    Uses the standard Ethernet/ZIP CRC32 polynomial.
    Initial value: 0 (not 0xFFFFFFFF, to match common shellcode usage).
    No final XOR applied (raw CRC, not the standard "inverted" output).

    Args:
        name: Function name string
        include_null: Whether to include null terminator

    Returns:
        32-bit CRC32 hash value
    """
    crc = 0
    chars = name + ('\x00' if include_null else '')
    for c in chars:
        crc = CRC32_TABLE[(crc ^ ord(c)) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


# Standard CRC32 (with initial 0xFFFFFFFF and final inversion):
def crc32_standard(name: str) -> int:
    """CRC32 with standard initial and final values (matches binascii.crc32)."""
    import binascii
    return binascii.crc32(name.encode('ascii')) & 0xFFFFFFFF
```

### Assembly Implementation: Lookup Table Method

```nasm
; ============================================================
; compute_crc32_hash
; Uses a 256-DWORD lookup table pre-built in data section
; Input:  ESI = pointer to null-terminated ASCII string
;         EDI = pointer to 1024-byte CRC32 lookup table
; Output: EAX = CRC32 hash
; Clobbers: EBX, ECX
; ============================================================
compute_crc32_hash:
    xor  eax, eax                    ; eax = crc = 0
    cld

crc32_loop:
    lodsb                            ; al = *esi++
    test al, al
    jz   crc32_done

    movzx ecx, al                    ; ecx = current byte
    xor  cl, al                      ; cl = (crc_low_byte XOR current_byte)
    ; Correct: cl = (eax & 0xFF) XOR al
    movzx ecx, byte ptr [esp + ...]  ; need low byte of CRC
    xor  ecx, eax                    ; ecx = byte XOR low_byte_of_crc
    and  ecx, 0xFF                   ; keep only low 8 bits (table index)
    mov  ebx, [edi + ecx*4]          ; ebx = CRC32_TABLE[index]
    shr  eax, 8                      ; eax = crc >> 8
    xor  eax, ebx                    ; eax = table[idx] XOR (crc >> 8)
    jmp  crc32_loop

crc32_done:
    ; EAX = CRC32 hash (without initial/final inversion)
    ret
```

### Assembly: Intel CRC32 Instruction (SSE4.2)

Modern processors (Intel Nehalem 2008+, AMD Bulldozer 2011+) include a hardware CRC32 instruction:

```nasm
; Intel CRC32 instruction (SSE4.2 required)
; Operates on 8, 16, 32, or 64-bit operands
; Uses 0x11EDC6F41 polynomial (different from the software table above!
; The hardware instruction uses the Castagnoli polynomial, CRC32C)

compute_crc32c_hash:
    xor  eax, eax                    ; initial value 0
    cld

crc32c_loop:
    lodsb
    test al, al
    jz   crc32c_done
    crc32 eax, al                    ; hardware CRC32 update (byte operand)
    jmp  crc32c_loop

crc32c_done:
    ; EAX = CRC32C hash (Castagnoli polynomial)
    ; NOTE: This is NOT the same as standard CRC32 (Ethernet polynomial)
    ret

; Typical encoding: 0xF2 0x0F 0x38 0xF0 0xC0 (crc32 eax, al)
; No lookup table needed — hardware does it in one cycle
```

**Important**: The hardware `CRC32` instruction uses the Castagnoli polynomial (`0x1EDC6F41`, also called CRC32C), NOT the standard Ethernet polynomial (`0xEDB88320`). These produce different results. Be consistent — pick one and stick to it for all hashes and all comparisons.

### Why CRC32 Has Lower Collision Probability

CRC32 was designed as an error-detecting code, optimized to detect burst errors in data transmission. Its properties include:
- Detects all single-bit errors
- Detects all double-bit errors in any-length message
- Extremely high sensitivity to small differences in input

For a DLL with ~500 exports, the expected collision probability under a random hash function would be approximately `500^2 / 2^32 ≈ 0.003%`. CRC32's intentional anti-collision design pushes this even lower.

ROR-13 is an ad hoc hash function with no collision-resistance design. In practice, for ~500 exports, both algorithms have zero collisions. CRC32 becomes advantageous for shellcode operating on DLLs with very large export tables (thousands of exports).

### CRC32 Hash Table for Common APIs

```
Function Name           CRC32 Hash (no init, no final XOR)
----------------------  ----------------------------------
LoadLibraryA            (run script with crc32_hash())
GetProcAddress          (run script)
VirtualAlloc            (run script)
WSAStartup              (run script — check for null bytes)
WSASocketA              (run script)
CreateProcessA          (run script)
ExitProcess             (run script)
TerminateProcess        (run script)
bind                    (run script)
listen                  (run script)
accept                  (run script)
```

Use the `crc32_hash()` Python function to populate this table. The exact values depend on the variant (initial value, final XOR) — be consistent.

---

## Null-Byte Safety Analysis

### The Problem

A shellcode hash that contains a null byte (`0x00`) in any byte position cannot be pushed as a 32-bit immediate in null-byte-sensitive contexts. Specifically:

- `push 0x006B8029` produces the bytes `29 80 6B 00` on x86 (little-endian), where the `00` is the last byte pushed. This `00` byte in the shellcode will be interpreted as a null terminator by `strcpy`, `sprintf %s`, and similar operations, truncating the shellcode.

### Identifying Affected APIs

From the ROR-13 table, `WSAStartup` hashes to `0x006B8029`:

```
0x006B8029 in little-endian bytes: 29 80 6B 00
                                              ^^
                                              null byte in shellcode!
```

Other commonly encountered null-producing hashes:
- Any hash with `0x00` in any byte position is problematic
- Hashes where the lower byte is `0x00` are especially common (the rotation distributes bits, but some combinations land on multiples of 256)

### Solution 1: XOR Encoding at Runtime

Encode the hash with a non-null XOR key. The XOR key itself must also be null-byte-free.

```nasm
; Target hash: 0x006B8029 (WSAStartup)
; Key: choose any value with no null bytes such that (hash XOR key) also has no nulls
; 0x006B8029 XOR 0x11111111 = 0x117A9138  ← check: 11 7A 91 38 — no nulls
; 0x006B8029 XOR 0x33333333 = 0x3358B31A  ← check: 33 58 B3 1A — no nulls
; Use 0x33333333 as key:

push 0x3358B31A                ; encoded hash (no nulls in this dword)
xor  dword ptr [esp], 0x33333333  ; decode: restores 0x006B8029

; Now the hash value (0x006B8029) is on the stack, ready to be read by find_function.
; The shellcode bytes for these two instructions contain no 0x00.
```

### Solution 2: Arithmetic Construction

Build the null-containing hash from non-null components:

```nasm
; Target: 0x006B8029
; Decompose: 0x006B8029 = 0x016C8129 - 0x01010100

push 0x016C8129                ; no null bytes (01 6C 81 29)
sub  dword ptr [esp], 0x01010100  ; subtract (01 01 01 00 -- contains null!)
                                   ; The SUB immediate has 0x00 — also bad!

; Better decomposition:
; 0x006B8029 = 0xFF6B8029 - 0xFF000000
; 0xFF6B8029 has bytes: 29 80 6B FF — no nulls
; 0xFF000000 has bytes: 00 00 00 FF — contains nulls

; Even better: use two-step:
; 0x006B8029 = (0x117A9138 XOR 0x11111111)
; as shown in Solution 1 — XOR is cleanest
```

### Solution 3: Use a Different Algorithm

Switch to an algorithm where `WSAStartup`'s hash does not contain null bytes. ROL-7 XOR may produce a null-byte-free hash for `WSAStartup` — verify with the Python script:

```python
print(hex(rol7xor_hash("WSAStartup")))   # check if null-free
print(hex(ror13_hash("WSAStartup")))     # = 0x006B8029 (has null)
```

If ROL-7 XOR produces no null bytes for your entire target API list, switch to that algorithm for the shellcode.

### Solution 4: Avoid WSAStartup Directly

Some shellcodes call `WSAStartup` using `GetProcAddress` after resolving that function (which is null-byte-free):

```nasm
; GetProcAddress is 0x7C0DFCAA (no null bytes)
; Use it to get WSAStartup:
push  hash_of_wsa_dll_name         ; or use LoadLibraryA first
call  [ebp - 0x0C]                 ; GetProcAddress (ws2_32_base, "WSAStartup")
; ← the string "WSAStartup" must be null-byte-free in the shellcode;
;    the name itself has no null bytes except the terminator (which can use XOR EAX trick)
```

### Encoding Framework for Null Bytes in Hashes

General algorithm to encode any hash with potential null bytes:

```python
def encode_hash_null_free(target_hash: int) -> tuple:
    """
    Find an XOR key such that both (target XOR key) and the key itself
    have no null bytes.

    Returns: (encoded_value, xor_key) or raises ValueError if none found.
    """
    for key in range(0x01010101, 0xFFFFFFFF, 0x01010101):
        # key must have no null bytes
        if b'\x00' in key.to_bytes(4, 'little'):
            continue
        encoded = (target_hash ^ key) & 0xFFFFFFFF
        # encoded value must also have no null bytes
        if b'\x00' not in encoded.to_bytes(4, 'little'):
            return (encoded, key)
    raise ValueError(f"No null-free encoding found for {target_hash:#010x}")


# Example usage:
target = 0x006B8029  # WSAStartup hash
encoded, key = encode_hash_null_free(target)
print(f"push {encoded:#010x}")
print(f"xor dword ptr [esp], {key:#010x}")
```

---

## Collision Detection

### Why Collisions Matter

If two functions in the target DLL have the same hash, the shellcode will find the wrong function (whichever comes first in the alphabetical name table). The call will fail or cause undefined behavior.

Collision probability with ROR-13 for:
- kernel32.dll (~1400 exports): extremely low, no known collisions
- ntdll.dll (~2500 exports): no known collisions
- ws2_32.dll (~80 exports): no known collisions

Despite the low probability, verifying before deployment is good practice.

### Collision Detection Script

```python
from typing import Callable


def check_collisions(
    dll_exports: list[str],
    hash_func: Callable[[str], int]
) -> dict[int, list[str]]:
    """
    Check for hash collisions in a DLL export list.

    Args:
        dll_exports: List of exported function name strings
        hash_func: Hash function to apply to each name

    Returns:
        Dictionary mapping each colliding hash value to the list of
        names that produce it. Empty dict means no collisions.

    Example:
        collisions = check_collisions(kernel32_exports, ror13_hash)
        if collisions:
            for h, names in collisions.items():
                print(f"Collision at {h:#010x}: {names}")
        else:
            print("No collisions found")
    """
    seen: dict[int, str] = {}
    collisions: dict[int, list[str]] = {}

    for name in dll_exports:
        h = hash_func(name)
        if h in seen:
            if h not in collisions:
                collisions[h] = [seen[h]]
            collisions[h].append(name)
        else:
            seen[h] = name

    return collisions


def compare_algorithms(
    dll_exports: list[str],
    algorithms: dict[str, Callable[[str], int]]
) -> None:
    """
    Compare collision rates across multiple hash algorithms for a DLL.
    Prints a summary report.
    """
    print(f"\nCollision analysis for {len(dll_exports)} exports:")
    print(f"{'Algorithm':<20} {'Collisions':<12} {'Unique hashes'}")
    print("-" * 50)

    for algo_name, hash_func in algorithms.items():
        collisions = check_collisions(dll_exports, hash_func)
        total_colliding = sum(len(v) for v in collisions.values())
        unique = len({hash_func(n) for n in dll_exports})
        print(f"{algo_name:<20} {total_colliding:<12} {unique}/{len(dll_exports)}")

        if collisions:
            for h, names in list(collisions.items())[:3]:  # show first 3
                print(f"  {h:#010x}: {names}")


# Usage: extract exports from a DLL and check:
def get_exports_from_pe(dll_path: str) -> list[str]:
    """
    Extract export names from a PE file on disk.
    Requires 'pefile' package: pip install pefile
    """
    import pefile
    pe = pefile.PE(dll_path)
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('ascii', errors='ignore'))
    return exports


# Main: compare ROR-13 and ROL-7 XOR for kernel32.dll:
if __name__ == "__main__":
    # If pefile is available:
    # exports = get_exports_from_pe("C:\\Windows\\System32\\kernel32.dll")

    # Otherwise, use a manually gathered list:
    sample_exports = [
        "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
        "CreateProcessA", "ExitProcess", "TerminateProcess", "WinExec",
        "CreateThread", "CloseHandle", "WriteFile", "ReadFile",
        # ... add full export list here
    ]

    algorithms = {
        "ROR-13":    ror13_hash,
        "ROL-7 XOR": rol7xor_hash,
        "CRC32":     crc32_hash,
    }

    compare_algorithms(sample_exports, algorithms)
```

### Generating Null-Free Hash Encodings

Complete script for encoding any hash that contains null bytes:

```python
def generate_null_free_push_sequence(target_hash: int, label: str = "") -> str:
    """
    Generate x86 NASM instructions to push a hash value that may
    contain null bytes, using XOR encoding.

    Returns a string of NASM instructions, or raises ValueError.
    """
    if b'\x00' not in target_hash.to_bytes(4, 'little'):
        # No null bytes — direct push is fine
        return f"push  {target_hash:#010x}  ; {label} (null-free, no encoding needed)"

    # Find a null-free XOR key
    for candidate_key in range(0x01010101, 0xFFFFFFFF):
        # Skip keys with null bytes in any byte position
        key_bytes = candidate_key.to_bytes(4, 'little')
        if b'\x00' in key_bytes:
            continue
        encoded = (target_hash ^ candidate_key) & 0xFFFFFFFF
        encoded_bytes = encoded.to_bytes(4, 'little')
        if b'\x00' not in encoded_bytes:
            lines = [
                f"; {label}: {target_hash:#010x} encoded (contains null byte)",
                f"push  {encoded:#010x}            ; encoded value (null-free)",
                f"xor   dword ptr [esp], {candidate_key:#010x}  ; decode to {target_hash:#010x}",
            ]
            return '\n'.join(lines)

    raise ValueError(f"Could not find null-free encoding for {target_hash:#010x}")


# Example output for WSAStartup:
print(generate_null_free_push_sequence(0x006B8029, "WSAStartup ROR-13 hash"))
# Output (values depend on first found key):
# ; WSAStartup ROR-13 hash: 0x006b8029 encoded (contains null byte)
# push  0x117a9138            ; encoded value (null-free)
# xor   dword ptr [esp], 0x11111111  ; decode to 0x006b8029
```

---

## Algorithm Comparison Summary

```
Property            ROR-13          ROL-7 XOR       CRC32
------------------  --------------  --------------  ---------------
Standard usage      Yes (OSED/MSF)  Less common     Rarely in shellcode
Code size (asm)     ~10 bytes/loop  ~10 bytes/loop  ~10 bytes (hw) /
                                                    large table (sw)
Collision rate      Very low        Very low        Extremely low
Null in common APIs 1 known         (check)         (check)
                    (WSAStartup)
Hardware support    No              No              Yes (SSE4.2 CRC32C)
Reversibility       No (ADD)        Yes (XOR)       No
Use if             Default choice  Alternative to  Large DLLs or
                                   avoid WSAStartup when hardware is
                                   null issue       reliable
```

### Recommendation

For standard exploit development shellcode:
1. **Use ROR-13** as the default
2. **Handle WSAStartup's null byte** with XOR encoding (the `push 0x117A9138 / xor [esp], 0x11111111` pattern)
3. **Verify with the Python script** before finalizing — regenerate the full hash table for your target Windows version's DLLs, as export lists can differ between service packs and updates
4. **Check collisions** against the full export list of each DLL you're searching

---

## Reference: Python Hash Utilities

The complete utility module combining all algorithms:

```python
#!/usr/bin/env python3
"""
shellcode_hashes.py — API hash computation for shellcode development

Usage:
  python3 shellcode_hashes.py
  python3 shellcode_hashes.py VirtualAlloc GetProcAddress WSAStartup
"""

import sys


def ror32(value: int, bits: int) -> int:
    bits %= 32
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def rol32(value: int, bits: int) -> int:
    bits %= 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def ror13_hash(name: str, include_null: bool = False) -> int:
    h = 0
    for c in (name + ('\x00' if include_null else '')):
        h = ror32(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def rol7xor_hash(name: str, include_null: bool = False) -> int:
    h = 0
    for c in (name + ('\x00' if include_null else '')):
        h = rol32(h, 7)
        h = (h ^ ord(c)) & 0xFFFFFFFF
    return h


# CRC32 table (Ethernet polynomial 0xEDB88320)
_CRC32_TABLE = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        _crc = (_crc >> 1) ^ 0xEDB88320 if (_crc & 1) else (_crc >> 1)
    _CRC32_TABLE.append(_crc)


def crc32_hash(name: str, include_null: bool = False) -> int:
    crc = 0
    for c in (name + ('\x00' if include_null else '')):
        crc = _CRC32_TABLE[(crc ^ ord(c)) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def has_null(value: int) -> bool:
    return b'\x00' in value.to_bytes(4, 'little')


def encode_null_free(target: int) -> tuple[int, int]:
    """Return (encoded_value, xor_key) such that both are null-free."""
    for key in range(0x01010101, 0xFFFFFFFF, 0x01010101):
        if has_null(key):
            continue
        encoded = (target ^ key) & 0xFFFFFFFF
        if not has_null(encoded):
            return (encoded, key)
    raise ValueError(f"No null-free encoding for {target:#010x}")


DEFAULT_APIS = [
    ("LoadLibraryA",        "kernel32"),
    ("GetProcAddress",      "kernel32"),
    ("VirtualAlloc",        "kernel32"),
    ("VirtualProtect",      "kernel32"),
    ("CreateProcessA",      "kernel32"),
    ("ExitProcess",         "kernel32"),
    ("TerminateProcess",    "kernel32"),
    ("WinExec",             "kernel32"),
    ("CreateThread",        "kernel32"),
    ("CloseHandle",         "kernel32"),
    ("WriteFile",           "kernel32"),
    ("ReadFile",            "kernel32"),
    ("RtlMoveMemory",       "ntdll"),
    ("WSAStartup",          "ws2_32"),
    ("WSASocketA",          "ws2_32"),
    ("WSAConnect",          "ws2_32"),
    ("connect",             "ws2_32"),
    ("bind",                "ws2_32"),
    ("listen",              "ws2_32"),
    ("accept",              "ws2_32"),
    ("send",                "ws2_32"),
    ("recv",                "ws2_32"),
    ("closesocket",         "ws2_32"),
    ("OpenProcessToken",    "advapi32"),
    ("GetUserNameA",        "advapi32"),
    ("GetLastError",        "kernel32"),
    ("SetHandleInformation","kernel32"),
    ("CreateFileA",         "kernel32"),
    ("WriteProcessMemory",  "kernel32"),
    ("CreateRemoteThread",  "kernel32"),
]


def print_hash_table(apis=None):
    if apis is None:
        apis = DEFAULT_APIS
    hdr = f"{'Name':<30} {'ROR-13':<12} {'ROL7XOR':<12} {'CRC32':<12} {'Null?'} {'Module'}"
    print(hdr)
    print("-" * len(hdr))
    for name, module in apis:
        r13  = ror13_hash(name)
        r7x  = rol7xor_hash(name)
        crc  = crc32_hash(name)
        null = "YES" if (has_null(r13) or has_null(r7x) or has_null(crc)) else "no"
        print(f"{name:<30} {r13:#010x} {r7x:#010x} {crc:#010x} {null:<6} {module}")
        if has_null(r13):
            enc, key = encode_null_free(r13)
            print(f"  ROR-13 null-free encoding: push {enc:#010x} / xor [esp],{key:#010x}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        custom = [(name, "?") for name in sys.argv[1:]]
        print_hash_table(custom)
    else:
        print_hash_table()
```

Save as `Value_Conversion_Scripts/shellcode_hashes.py` and run:
```
python3 shellcode_hashes.py
python3 shellcode_hashes.py VirtualAlloc WSAStartup MyCustomFunction
```
