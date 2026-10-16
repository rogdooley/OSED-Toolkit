# OSED x86 Assembly -- Bad-Character Recognition and Investigation

**Compact field reference | Static recognition in IDA, dynamic verification in WinDbg**

> Purpose: Identify potential bad-character restrictions by recognizing
> assembly patterns during static analysis, then confirm or refute each
> hypothesis dynamically.  This is a field reference for analysts who
> already understand x86 stack frames, calling conventions, and exploit
> development.  All examples use 32-bit Intel x86 assembly.

---

## 1. Instruction-Pattern Catalog

### 1.1 NUL Termination

```asm
.text:00401230    mov     al, [esi]
.text:00401232    test    al, al
.text:00401234    jz      short loc_401260   ; exit loop on 0x00
.text:00401236    mov     [edi], al
.text:00401238    inc     esi
.text:00401239    inc     edi
.text:0040123A    jmp     short loc_401230
```

**What it does.** Copies bytes one at a time from [ESI] to [EDI], stopping
when a zero byte is encountered.  The zero byte itself is not copied (or
is copied and then the loop exits -- check whether the store precedes or
follows the test).

**Why it suggests a constraint.** If a NUL byte appears in controlled
input before the end of the payload, the copy terminates early.  Bytes
after the NUL never reach the destination.

**What static analysis cannot confirm.** Whether this routine is actually
on the data path between the input source and the vulnerable sink.  A
binary may contain many string-copy loops; only those on the exploit's
data path matter.

**WinDbg verification.**
- `bp 00401230` -- break at loop entry.
- After the loop exits: `db <destination> L100` and compare against the
  transmitted sequence.
- If the copy stopped early, the byte at the termination point in the
  source buffer is the candidate delimiter.

---

### 1.2 Direct Delimiter Checks

```asm
.text:004018A0    movzx   eax, byte ptr [esi+ecx]
.text:004018A4    cmp     al, 0Dh            ; carriage return
.text:004018A6    jz      short loc_4018C0   ; branch if match
.text:004018A8    cmp     al, 0Ah            ; line feed
.text:004018AA    jz      short loc_4018C0
.text:004018AC    cmp     al, 20h            ; space
.text:004018AE    jz      short loc_4018C0
.text:004018B0    inc     ecx
.text:004018B1    cmp     ecx, edx
.text:004018B3    jb      short loc_4018A0
```

**What it does.** Scans a buffer byte by byte, comparing each byte
against 0x0D, 0x0A, and 0x20.  On a match, control transfers to
`loc_4018C0`.

**Why it suggests a constraint.** If the branch target terminates
parsing, truncates, or splits the buffer, any of these bytes in the
payload would end or alter processing.

**What static analysis cannot confirm.** What happens at the branch
target.  The branch might terminate a field (delimiter), skip the byte
(deletion), replace it (substitution), or simply record a state
transition.  Follow the branch target before concluding.

**WinDbg verification.**
- `bp 004018A0` -- break at the comparison entry.
- `bp 004018C0` -- break at the branch target.
- Send a payload containing 0x0D in a known position.  When the branch
  target is hit, inspect what the routine does with the byte and the
  remaining data.
- Compare `db <destination>` against expected bytes.

---

### 1.3 String-Function Recognition

Common C runtime string functions appear in IDA as named imports or as
inlined instruction sequences.

```asm
; strcpy inlined as rep movsb with NUL scan
.text:00402100    mov     edi, [ebp+dst]
.text:00402103    mov     esi, [ebp+src]
.text:00402106    or      ecx, 0FFFFFFFFh    ; ECX = -1
.text:00402109    xor     eax, eax           ; AL = 0
.text:0040210B    repne   scasb              ; scan for NUL in dst (to find end)
.text:0040210D    not     ecx                ; ECX = strlen(dst) + 1
.text:0040210F    sub     edi, ecx           ; rewind EDI to dst start
.text:00402111    mov     edx, ecx           ; save count
.text:00402113    mov     esi, [ebp+src]
.text:00402116    mov     ecx, edx
.text:00402118    rep     movsb              ; copy
```

**What it does.** Scans the destination for a NUL terminator to find its
length, then copies that many bytes from source.  This is a strcat-like
pattern.

**Why it suggests a constraint.** NUL-sensitive: the copy length is
derived from a NUL scan.  If the source contains a NUL, `repne scasb` on
the source (in a `strcpy` variant) would stop early.

**Other string functions to watch for:**

| Import / pattern | NUL-sensitive | Delimiter behavior |
|---|---|---|
| `strcpy` / `lstrcpyA` | Yes -- copies until NUL | Terminates at 0x00 |
| `strncpy` | Yes -- pads or truncates at N | Terminates at 0x00 or length cap |
| `strlen` / `lstrlenA` | Yes -- counts until NUL | Returns short count if embedded NUL |
| `strtok` | Yes | Splits on any byte in delimiter set |
| `strchr` | Yes | Returns pointer to first occurrence |
| `strcspn` | Yes | Returns offset of first delimiter-set byte |
| `memcpy` / `rep movsd` | No -- copies explicit count | Not NUL-sensitive by itself |

**WinDbg verification.**
- `bp <import_address>` -- break on the string function call.
- At the break: `dd @esp L4` to read arguments (destination, source,
  length if applicable).
- `db <source>` and `db <destination>` before and after the call.
- For `strtok`: inspect the delimiter string argument (`db <arg2>`).

---

### 1.4 Character Normalization (Case Conversion, Range Checks)

```asm
.text:00403500    movzx   eax, byte ptr [esi]
.text:00403503    cmp     al, 41h            ; 'A'
.text:00403505    jb      short loc_403520   ; below 'A' -- skip
.text:00403507    cmp     al, 5Ah            ; 'Z'
.text:00403509    ja      short loc_403520   ; above 'Z' -- skip
.text:0040350B    add     al, 20h            ; convert to lowercase
.text:0040350D    mov     [esi], al
.text:0040350F    loc_403520:
.text:0040350F    inc     esi
```

**What it does.** Checks whether a byte falls in the ASCII uppercase
range (0x41-0x5A) and adds 0x20 to convert it to lowercase.

**Why it suggests a constraint.** Bytes 0x41-0x5A will be transformed in
the destination.  This is a substitution, not a deletion -- the byte
count is preserved, but specific byte values change.  Shellcode using
uppercase ASCII bytes would be altered.

**What static analysis cannot confirm.** Whether the normalization runs
on the data path that reaches the exploit payload.  Also whether the
transformation is reversible through encoding (it usually is).

**WinDbg verification.**
- `bp 00403500` -- break at the loop start.
- Send a payload containing bytes 0x41-0x5A at known positions.
- After the loop completes: `db <buffer>` and verify which bytes changed.
- Record the exact mapping (input byte -> output byte).

---

### 1.5 Byte Transformations (XOR, AND, OR, ADD, SUB, ROL, ROR, NOT)

```asm
.text:00404200    movzx   eax, byte ptr [esi+ecx]
.text:00404204    xor     al, 7Fh
.text:00404206    mov     [edi+ecx], al
.text:00404209    inc     ecx
.text:0040420A    cmp     ecx, edx
.text:0040420C    jb      short loc_404200
```

**What it does.** Reads each byte from [ESI+ECX], XORs it with 0x7F,
and writes the result to [EDI+ECX].

**Why it suggests a constraint.** Every byte in the payload will be
XORed with 0x7F before reaching the destination.  This is a reversible
transformation: to place byte B at the destination, send B XOR 0x7F.
However, the pre-transformation byte must survive any earlier processing
stages (transport delimiters, NUL checks) intact.

**Common transformation patterns:**

| Instruction | Effect | Reversibility |
|---|---|---|
| `xor al, imm8` | Bitwise toggle | XOR with same key |
| `and al, imm8` | Mask bits | Irreversible -- information lost |
| `or al, imm8` | Force bits high | Irreversible |
| `add al, imm8` | Arithmetic shift (mod 256) | `sub al, imm8` |
| `sub al, imm8` | Arithmetic shift (mod 256) | `add al, imm8` |
| `rol al, imm8` | Rotate left | `ror al, imm8` |
| `not al` | Bitwise complement | `not al` |

**WinDbg verification.**
- `bp 00404200` -- break at the transform loop.
- `bp 0040420C` -- break at the loop exit.
- Send bytes 0x00-0xFF at known offsets; compare source and destination
  byte by byte.
- Record which input bytes produce which output bytes.
- For irreversible transforms (AND, OR): some distinct input bytes
  produce the same output byte.  The constraint is on the output, not
  the input.

---

### 1.6 Byte Deletion (Source Advances Without Destination)

```asm
.text:00405300    movzx   eax, byte ptr [esi]
.text:00405303    cmp     al, 25h            ; '%'
.text:00405305    jz      short loc_405320   ; skip this byte
.text:00405307    mov     [edi], al          ; store to destination
.text:00405309    inc     edi                ; advance destination
.text:0040530A    loc_405320:
.text:0040530A    inc     esi                ; always advance source
.text:0040530B    dec     ecx
.text:0040530C    jnz     short loc_405300
```

**What it does.** Copies bytes from source to destination, but when the
byte equals 0x25 ('%'), it skips the store and destination increment.
The source pointer always advances.

**Why it suggests a constraint.** Byte 0x25 is deleted from the output.
All subsequent bytes shift left by one position for each deleted byte.
This means the overwrite offset changes if a deleted byte precedes the
return address.

**Critical distinction:** Deletion is not the same as termination.  Bytes
*after* a deleted byte are still copied; they just shift position.

**WinDbg verification.**
- `bp 00405300` -- break at the loop start.
- `bp 00405305 ".if (@eax == 0x25) {} .else {gc}"` -- conditional break
  only when the skip triggers.
- After the loop: compare `db <source>` with `db <destination>`.
- Count the positional shift.  If the EIP overwrite relies on a fixed
  offset, any deleted byte before that offset invalidates the offset.

---

### 1.7 Byte Insertion or Expansion

```asm
.text:00406100    movzx   eax, byte ptr [esi]
.text:00406103    cmp     al, 26h            ; '&'
.text:00406105    jnz     short loc_406120
.text:00406107    mov     dword ptr [edi], 26706D61h  ; "amp&" (little-endian)
.text:0040610D    add     edi, 4             ; destination advances 4
.text:00406110    jmp     short loc_406130
.text:00406112    loc_406120:
.text:00406112    mov     [edi], al
.text:00406114    inc     edi                ; destination advances 1
.text:00406115    loc_406130:
.text:00406115    inc     esi                ; source advances 1
.text:00406116    dec     ecx
.text:00406117    jnz     short loc_406100
```

**What it does.** For each byte: if it equals 0x26 ('&'), writes a
4-byte expansion ("amp&") and advances the destination by 4.  Otherwise,
copies the byte and advances by 1.

**Why it suggests a constraint.** The destination grows faster than the
source.  If the destination buffer has a fixed capacity, expansion can
cause an overflow even when the source fits.  Also, byte 0x26 does not
survive intact -- it is replaced by a multi-byte sequence.

**WinDbg verification.**
- `bp 00406100` -- break at loop start.
- Send a payload with 0x26 at known positions.
- After the loop: `db <destination>` -- observe the expanded output
  and measure the total length increase.
- Verify whether the expansion overflows the destination allocation.

---

### 1.8 Escape-Sequence Processing

```asm
.text:00407400    movzx   eax, byte ptr [esi]
.text:00407403    cmp     al, 5Ch            ; backslash '\'
.text:00407405    jnz     short loc_407430   ; not escape -- normal copy
.text:00407407    inc     esi                ; consume the backslash
.text:00407408    dec     ecx
.text:00407409    jz      short loc_407450   ; end of input after backslash
.text:0040740B    movzx   eax, byte ptr [esi]
.text:0040740E    cmp     al, 6Eh            ; 'n'
.text:00407410    jnz     short loc_407420
.text:00407412    mov     byte ptr [edi], 0Ah ; replace \n with LF
.text:00407415    jmp     short loc_407440
.text:00407417    loc_407420:
.text:00407417    mov     [edi], al          ; unknown escape -- copy literal
.text:00407419    loc_407430:
.text:00407419    mov     [edi], al          ; normal byte -- copy
.text:0040741B    loc_407440:
.text:0040741B    inc     edi
.text:0040741C    inc     esi
.text:0040741D    dec     ecx
.text:0040741E    jnz     short loc_407400
```

**What it does.** Processes escape sequences: a backslash followed by
'n' becomes 0x0A.  The source consumes two bytes while the destination
produces one.

**Why it suggests a constraint.** Two-byte sequences in the input
collapse to one byte in the output, shifting all subsequent byte
positions.  Additionally, the byte 0x5C (backslash) itself triggers
special handling -- it is consumed but not copied directly.

**WinDbg verification.**
- `bp 00407400` -- loop entry.
- `bp 00407403` -- the escape check.
- Send a payload with 0x5C at known positions; track source and
  destination pointers independently.
- After the loop: compare source length vs destination length.

---

### 1.9 Stateful Parsers (Context-Dependent Behavior)

```asm
.text:00408600    movzx   eax, byte ptr [esi]
.text:00408603    test    [ebp+var_flags], 1  ; are we inside quotes?
.text:0040860A    jz      short loc_408630    ; no -- check delimiters
.text:0040860C    cmp     al, 22h             ; '"' -- closing quote
.text:0040860E    jnz     short loc_408620    ; not a quote -- copy verbatim
.text:00408610    and     [ebp+var_flags], 0FEh ; clear quote flag
.text:00408617    jmp     short loc_408650     ; consume quote, don't copy
.text:00408620:
.text:00408620    mov     [edi], al            ; inside quotes: copy byte as-is
.text:00408622    inc     edi
.text:00408623    jmp     short loc_408650
.text:00408630:
.text:00408630    cmp     al, 2Ch             ; ',' -- delimiter outside quotes
.text:00408632    jz      short loc_408660     ; terminate field
.text:00408634    cmp     al, 22h             ; '"' -- opening quote
.text:00408636    jnz     short loc_408640
.text:00408638    or      [ebp+var_flags], 1   ; set quote flag
.text:0040863F    jmp     short loc_408650     ; consume quote
.text:00408640:
.text:00408640    mov     [edi], al            ; outside quotes: copy byte
.text:00408642    inc     edi
```

**What it does.** A CSV-like parser with a quote-state flag.  Inside
quotes, bytes (including 0x2C) are copied verbatim.  Outside quotes,
0x2C terminates the field.  The quote character 0x22 toggles state and
is consumed without being copied.

**Why it suggests a constraint.** Byte 0x2C is a bad character only
outside quotes.  Byte 0x22 is always consumed (never reaches the
destination).  The same input byte can behave differently depending
on preceding bytes.  This makes single-byte testing insufficient.

**WinDbg verification.**
- `bp 00408600` -- loop entry.
- `ba r1 <address_of_var_flags>` -- hardware read breakpoint on the
  state variable to track transitions.
- Test the same byte (e.g., 0x2C) in two contexts: preceded by 0x22
  and without.
- Compare destination contents in both cases.

---

### 1.10 Length-Dependent Truncation

```asm
.text:00409800    movzx   ecx, word ptr [ebp+arg_len]  ; 16-bit length
.text:00409804    cmp     ecx, 100h
.text:0040980A    jbe     short loc_409820    ; within cap
.text:0040980C    mov     ecx, 100h           ; clamp to 256
.text:00409811    loc_409820:
.text:00409811    lea     edi, [ebp+local_buf]
.text:00409817    mov     esi, [ebp+arg_src]
.text:0040981A    rep     movsb               ; copy ECX bytes
```

**What it does.** Reads a 16-bit length field, clamps it to 0x100
(256) bytes, then copies that many bytes via `rep movsb`.

**Why it suggests a constraint.** Bytes beyond position 256 are silently
dropped.  This is truncation, not deletion -- the first 256 bytes are
intact.  If the return address is at offset 304, the payload never
reaches it through this path alone.

**Signedness trap:** If the length were loaded with `movsx` instead of
`movzx`, a value with bit 15 set (e.g., 0x8000 = 32768 as unsigned,
-32768 as signed) could bypass a signed `jle` comparison while producing
a large unsigned copy count.

**WinDbg verification.**
- `bp 00409811` -- break after the clamp, before the copy.
- `r ecx` -- actual byte count about to be copied.
- After the copy: `db <local_buf> L200` -- verify how many bytes
  actually arrived.

---

### 1.11 File Input Handling

```asm
.text:0040A100    push    0                   ; lpOverlapped = NULL
.text:0040A102    lea     eax, [ebp+bytesRead]
.text:0040A105    push    eax                 ; lpNumberOfBytesRead
.text:0040A106    push    400h                ; nNumberOfBytesToRead
.text:0040A10B    lea     ecx, [ebp+buffer]
.text:0040A111    push    ecx                 ; lpBuffer
.text:0040A112    push    [ebp+hFile]         ; hFile
.text:0040A115    call    ds:ReadFile
```

**What it does.** Reads up to 0x400 (1024) bytes from a file handle into
a stack buffer.

**Why it suggests a constraint.** File I/O can introduce constraints
that network I/O does not.  Text-mode file opens (via `fopen` with mode
"r" on Windows) may translate CR+LF (0x0D 0x0A) to LF (0x0A) and treat
0x1A (Ctrl-Z) as EOF.  `ReadFile` in binary mode does not translate, but
`fread` with a text-mode handle does.

**Distinguishing text vs binary mode:**

| Function | Mode indicator | Translation |
|---|---|---|
| `ReadFile` / `WriteFile` | Always binary | None |
| `fopen` + `fread` | "r" = text, "rb" = binary | Text: CR+LF -> LF, 0x1A = EOF |
| `fgets` | Depends on mode | Text mode translates; stops at newline |

**WinDbg verification.**
- `bp <ReadFile_import>` -- break on the read call.
- After return: `db <buffer> L<bytesRead>` -- compare against the file
  contents on disk (use a hex editor for the file).
- If using `fread`: check the file mode by tracing back to the `fopen`
  call and inspecting the mode string argument.

---

### 1.12 Intermediate Buffers and Multi-Stage Processing

```asm
; Stage 1: receive into heap buffer
.text:0040B200    push    0                ; flags
.text:0040B202    push    400h             ; len
.text:0040B207    push    [ebp+heapBuf]    ; buf
.text:0040B20A    push    [ebp+sock]       ; s
.text:0040B20D    call    ds:recv

; Stage 2: decode from heap into stack
.text:0040B240    push    eax              ; received length
.text:0040B241    push    [ebp+heapBuf]    ; source
.text:0040B244    lea     ecx, [ebp+stackBuf]
.text:0040B24A    push    ecx              ; destination
.text:0040B24B    call    sub_4010F0       ; decode routine

; Stage 3: copy decoded data to final destination
.text:0040B260    push    edx              ; decoded length
.text:0040B261    lea     eax, [ebp+stackBuf]
.text:0040B267    push    eax              ; source (decoded)
.text:0040B268    push    [ebp+finalDst]   ; destination
.text:0040B26B    call    sub_401200       ; vulnerable copy
```

**What it does.** Data flows through three stages: network receive into
a heap buffer, decode into a stack buffer, then a final copy to the
vulnerable destination.

**Why it suggests a constraint.** Each stage can introduce, remove, or
transform restrictions.  A byte that survives `recv` intact may be
altered by the decode routine.  A byte that passes through decode may
not survive the final copy if it uses a different method (e.g.,
`strcpy` vs `memcpy`).

**WinDbg verification.**
- `bp <after_recv>` -- inspect `db <heapBuf> L<recv_return>`.
- `bp <after_decode>` -- inspect `db <stackBuf> L<decoded_len>`.
- `bp <after_final_copy>` -- inspect `db <finalDst> L<copy_len>`.
- Compare all three dumps against the transmitted bytes.  The first
  divergence identifies which stage introduced the restriction.

---

## 2. Assembly-Indicator Quick-Reference Table

| Assembly indicator | Suspected behavior | Static confidence | Verification approach |
|---|---|---|---|
| `test al, al` + `jz` | NUL termination | Medium | Compare source/destination lengths |
| `cmp al, imm8` + `jz` to skip store | Byte deletion | Medium | Track src/dst pointer difference |
| `cmp al, imm8` + `jz` to exit loop | Delimiter termination | Medium | Check destination after the loop |
| `xor al, imm8` before store | Reversible transformation | High | Compare input/output byte pairs |
| `and al, imm8` before store | Irreversible masking | High | Map input to output; check collisions |
| `add al, 20h` with range check | Case normalization | High | Send uppercase bytes, verify output |
| Separate src/dst index increments | Filtering or expansion | Medium | Track both index values |
| State variable + conditional branch | Context-dependent processing | Low | Test same byte in different contexts |
| `movzx` vs `movsx` on length | Signedness-dependent truncation | High | Test with bit-15-set length values |
| `rep movsb` with clamped ECX | Length truncation | High | Check ECX before copy; compare counts |
| `repne scasb` + `rep movsb` | String copy (NUL-sensitive) | High | Embed NUL in payload; check dest length |

---

## 3. IDA Static-Analysis Workflow

### 3.1 Locate Input Functions

Search the Imports window for:

- Network: `recv`, `recvfrom`, `WSARecv`, `InternetReadFile`
- File: `ReadFile`, `fread`, `fgets`, `_read`
- Other: `GetWindowTextA`, `RegQueryValueExA`, command-line APIs

For each, press `X` to list cross-references.  Follow each caller.

### 3.2 Identify the Original Input Buffer

At the call site, read the buffer argument:

```asm
push    400h              ; len
push    [ebp+inputBuf]    ; buf  <-- this is the receive buffer
push    [ebp+sock]
call    ds:recv
```

If `inputBuf` is a local (`[ebp-N]`), note the stack frame size.
If it is a heap pointer, trace its allocation (`malloc`, `HeapAlloc`,
`VirtualAlloc`).

### 3.3 Trace the Data Path to the Vulnerable Copy

From the input buffer, follow every read reference.  At each step:

1. Is the data copied, transformed, or branched on?
2. What is the destination and its capacity?
3. What determines the copy length?
4. Does the routine alter, skip, or expand any bytes?

Build a linear chain: **input -> [stage 1] -> [stage 2] -> ... -> sink**.

### 3.4 Identify Intermediate Buffers and Processing

At each stage, record:

| Stage | Source | Destination | Capacity | Copy method | Byte modifications |
|---|---|---|---|---|---|
| recv | network | heapBuf | 0x400 | recv(len) | None |
| decode | heapBuf | stackLocal | 0x200 | loop + xor | XOR 0x7F |
| copy | stackLocal | destBuf | 0x100 | strcpy | NUL-terminated |

### 3.5 Recognize Suspicious Patterns

At each processing stage, look for the patterns in Section 1:

- **Comparisons against immediate bytes** in a copy loop (Section 1.2)
- **Arithmetic on the copied byte** before storing (Sections 1.4, 1.5)
- **Asymmetric pointer advancement** (Sections 1.6, 1.7)
- **State-dependent branches** (Section 1.9)
- **Length clamping or narrowing** (Section 1.10)

### 3.6 Choose WinDbg Breakpoints

For each suspicious stage:

| What to verify | Where to break | What to inspect |
|---|---|---|
| Input arrives intact | After `recv` / `ReadFile` return | `db <buffer> L<count>` |
| Processing alters bytes | Start and end of processing loop | Source vs destination bytes |
| Copy reaches destination | After copy call or loop | `db <destination> L<expected>` |
| Specific byte triggers branch | At the comparison instruction | `r eax`, flag state, branch taken |

---

## 4. WinDbg Command Reference

### 4.1 Essential Commands

```text
bp <address>              Set software breakpoint
bl                        List breakpoints
bc <id>                   Clear breakpoint by ID
bc *                      Clear all breakpoints
g                         Continue execution
t                         Step into (single instruction)
p                         Step over (skip calls)
r                         Display all registers
r eax                     Display one register
db <address> L100         Byte dump, 256 bytes
dd <address> L20          DWORD dump, 32 dwords
u <address> L20           Disassemble 32 instructions forward
uf <symbol>               Disassemble entire function
dps @esp L20              Stack dump with symbol resolution
? <expression>            Evaluate expression
.formats <value>          Show value in decimal, hex, binary, char
```

### 4.2 Breaking Before vs After a Transformation

**Before:** Shows the input byte and whether the branch will be taken.
Useful for confirming which bytes trigger special handling.

```text
bp 00404200               ; break at start of XOR loop
                          ; inspect: r eax (input byte), source buffer
```

**After:** Shows the output byte and destination state.  Useful for
confirming the transformation result.

```text
bp 0040420C               ; break at loop exit
                          ; inspect: db <destination> L100
```

For a single-byte investigation, combine both:

```text
bp 00404204 ".printf \"IN: %02x  OUT: %02x\\n\", @eax, (@eax ^ 0x7f); gc"
```

This logs each input/output pair without stopping.

### 4.3 Inspecting EBP-Relative Stack Buffers

```text
; Local buffer at [ebp-12Ch] in a function with breakpoint at copy
db @ebp-12c L100          ; dump local buffer contents
? @ebp + 4 - (@ebp - 12c); distance to saved return address = 0x130
dd @ebp+4 L1              ; saved return address
dd @ebp L1                ; saved EBP
```

### 4.4 Inspecting Register-Held Heap Pointers

```text
; After recv, EAX = bytes received, [ebp+heapBuf] = buffer pointer
dd @ebp-1c L1             ; read the heap pointer
db poi(@ebp-1c) L100      ; dereference and dump contents
!address poi(@ebp-1c)     ; verify region type and protection
```

### 4.5 Comparing Two Buffers

```text
; Manual comparison: dump both and visually compare
db 0014DD00 L40           ; source (receive buffer)
db 0019F200 L40           ; destination (stack buffer after copy)

; Scripted byte comparison (basic)
.for (r $t0 = 0; @$t0 < 0x100; r $t0 = @$t0 + 1) {
  .if (by(0014DD00 + @$t0) != by(0019F200 + @$t0)) {
    .printf "MISMATCH at offset %03x: src=%02x dst=%02x\n",
            @$t0, by(0014DD00+@$t0), by(0019F200+@$t0)
  }
}
```

---

## 5. Pitfalls and Misinterpretations

### 5.1 A Comparison Is Not Proof of a Bad Character

A `cmp al, 0Dh` instruction proves that the code *inspects* byte 0x0D.
It does not prove that 0x0D is forbidden.  The branch target might:
- Mark a record boundary (the byte is consumed normally afterward)
- Count occurrences (no data modification)
- Trigger a state transition that has no effect on the current byte

**Always follow the branch target.**

### 5.2 Delimiters May Be State-Dependent

A byte that acts as a delimiter in one parser state may be copied
verbatim in another (Section 1.9).  Single-byte bad-character testing
cannot detect this.  Test candidate bytes in multiple contexts:
- At the start of input
- In the middle of a field
- Immediately after a state-changing byte
- At field boundaries

### 5.3 Transformation vs Deletion

If a byte is present in the destination but has a different value, it
was *transformed*, not deleted.  The byte count is preserved.
Offsets remain valid.  The constraint may be circumventable by encoding.

If a byte is absent and subsequent bytes shift left, it was *deleted*.
Offsets change.  Every payload byte after the deletion point is
displaced.

### 5.4 Deletion Shifts Subsequent Bytes

If byte 0x25 is deleted at position 50, then what was at position 51
is now at position 50.  If the return-address overwrite relies on
offset 304, and one byte is deleted before that offset, the return
address is now at offset 303 in the source but 304 in the destination.
Compensate in the payload or avoid the deleted byte.

### 5.5 Embedded NUL and Trailing Memory

If a NUL-terminated copy stops at an embedded NUL, the destination
buffer may contain stale data from a previous operation beyond the
NUL.  `db` will show bytes there, but they are not from your payload.
Verify by sending different payloads and checking whether the bytes
beyond the NUL change.

### 5.6 Test Sequence Overflow

A 255-byte (0x01-0xFF) or 256-byte (0x00-0xFF) test sequence may
exceed the destination buffer capacity.  If the destination is only
128 bytes, the test itself causes a different overflow.  Size the
test sequence to fit the specific destination or test in smaller
ranges.

### 5.7 Signed vs Unsigned Comparisons

```asm
cmp     al, 80h
jb      short loc_pass     ; unsigned: 0x00-0x7F pass
```

```asm
cmp     al, 80h
jl      short loc_pass     ; signed: 0x00-0x7F AND 0x80-0xFF (negative) pass
```

`jb`/`ja` use unsigned semantics.  `jl`/`jg` use signed semantics.
For bytes 0x80-0xFF (high-bit set), the two comparisons produce
opposite results.  Misreading the condition changes the set of
restricted bytes entirely.

### 5.8 Adjacent-Byte Dependencies

Some constraints depend on byte pairs or sequences, not individual
bytes.  Examples:
- Escape processing: 0x5C followed by 0x6E becomes 0x0A
- UTF-8-like multi-byte sequences: a lead byte determines how many
  following bytes are consumed
- Protocol framing: a length byte followed by that many data bytes

Single-byte testing will not reveal these.

### 5.9 Reversible Transformations and Encoding

A byte that is XORed, rotated, or arithmetically shifted can often be
pre-encoded so it arrives correctly at the destination.  The
constraint is not "byte X is bad" but "byte X must be sent as Y to
arrive as X."  This is only viable if Y itself is not restricted by
an earlier processing stage.

### 5.10 Path-Specific Constraints

Bad-character restrictions apply to a specific data path, not
necessarily the entire binary.  A network handler and a file handler
in the same binary may have entirely different restrictions.  A probe
command and an exploit command may traverse different parsing routines.
Test the actual exploit path.

---

## 6. Failure-Driven Troubleshooting

| Symptom | Candidate causes | Diagnostic action |
|---|---|---|
| Payload never reaches the breakpoint | Wrong command/handler; header mismatch; recv blocking on incomplete read | Break at recv; verify bytes arrive; trace dispatch |
| Received bytes intact, final buffer differs | Intermediate processing stage transforms data | Break after each stage; find first divergence |
| Bytes disappear after a particular position | NUL termination; length truncation; delimiter | Check the byte at the cut-off position; trace the copy method |
| All bytes after one position shift left | Byte deletion before that position | Identify the deleted byte; count the shift |
| Only high-bit bytes (0x80-0xFF) change | Case conversion or signed comparison; masking; charset normalization | Check for `and al, 7Fh` or `cmp`+signed branch; test 0x80 specifically |
| Behavior differs between repeated probes | ASLR rebasing; heap layout variance; timing-dependent state | Restart process; test with fixed addresses; check for race conditions |
| Candidate byte causes crash before inspection | The byte triggers a different code path (not the one being tested) | Break earlier (at receive or parse); trace which branch the byte causes |
| Byte works in one parser state but not another | Stateful parser; quote/escape context | Identify the state variable; test the byte in both states (Section 1.9) |
| First 128 bytes correct, then corruption | Destination buffer smaller than test sequence; separate overwrite | Check destination capacity; reduce test sequence size |

---

## 7. One-Page Rapid Reference

See the companion document:
**OSED_x86_Bad_Character_Quick_Reference.md**

---

## 8. Relationship to the OSED Exam Field Guide

This document complements sections 7 and 7.1 of the OSED Exam Field
Guide (v4.3).  The field guide covers the *investigation workflow*
(what to do at each boundary).  This document covers *pattern
recognition* (what assembly sequences to look for and what they mean).

Cross-references:
- Field Guide section 7: bad-character testing procedure
- Field Guide section 7.1: multi-stage tracing
- Field Guide section 14: common failure patterns
- This document section 2: instruction-pattern quick table
- This document section 6: failure-driven troubleshooting
