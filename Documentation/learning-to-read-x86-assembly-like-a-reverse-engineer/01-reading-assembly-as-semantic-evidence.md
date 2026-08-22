# 1. Reading Assembly as Semantic Evidence

## Learning objectives

By the end of this chapter you should be able to:

- Separate compiler scaffolding from programmer intent.
- Read an instruction sequence as information flow instead of syntax.
- Maintain a fact ledger without prematurely inventing C source.
- Explain what question the CPU is answering at each decision point.

## Concept discussion

Reverse engineering is not decompilation by hand. A compiler has already erased
source-level names, comments, some types, and many boundaries between statements.
What remains is executable evidence. Your job is to recover the simplest model
that explains that evidence.

The CPU does not know about "valid packets", "users", or "commands". It answers
smaller questions:

- Is this value zero?
- Is this unsigned length larger than a limit?
- What address is `base + index * scale + offset`?
- Which function address should be called?
- How many bytes should be copied?

The programmer wrote logic in terms of domain concepts. The compiler lowered that
logic into register movement, memory access, condition flags, and control flow.
The reverse engineer climbs back up from CPU questions to programmer assumptions.

**Exam note**: OSED exam binaries will not have symbols. There will be no
function names, no variable names, no type information -- only raw disassembly.
The fact-ledger approach described in the preface is your primary analysis
method. Every instruction is a piece of evidence; your job is to organize that
evidence into a coherent model without relying on labels that do not exist.

## Common compiler patterns

- Save/restore registers: compiler obligation, usually not domain logic.
- `xor eax, eax`: often materializes zero, frequently a success return or boolean false.
- `cmp reg, imm` followed by conditional jump: a branch question.
- `test reg, reg`: zero/null/empty check.
- `lea reg, [mem]`: address or arithmetic, not a memory read.
- `push arg; call target; add esp, n`: argument setup and caller cleanup.

## Fully annotated example

Assembly first:

```asm
sub_401000:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]
    test    eax, eax
    jz      short fail
    cmp     dword ptr [eax], 4D434D44h
    jnz     short fail
    xor     eax, eax
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     ebp
    retn
```

Annotated reading:

```asm
push ebp / mov ebp, esp
; Standard frame. This tells us where arguments live, not what the program means.

mov eax, [ebp+8]
; Load the first stack argument.

test eax, eax
; Ask: is the argument zero? Since the next use dereferences EAX, this is a null
; pointer check.

jz fail
; If the pointer is null, return failure.

cmp dword ptr [eax], 4D434D44h
; Read four bytes from the pointed-to object and compare them to a constant.
; The argument is a pointer to a structure or buffer whose first dword is a tag.

jnz fail
; If the tag does not match, return failure.

xor eax, eax
; Return 0. In Windows C code, 0 commonly means success for internal helpers.
```

The CPU is answering: "Did I receive a non-null pointer whose first four bytes
match the expected tag?"

The programmer likely wrote a validation helper. The compiler assumes `[ebp+8]`
is the only argument used here and that reading `[eax]` is safe after the null
check. The programmer assumes the caller passed a pointer to at least four
readable bytes.

## Reverse engineering thought process

Start with facts:

- One argument is read from `[ebp+8]`.
- That value is checked for zero.
- If nonzero, four bytes at that address are read.
- Two paths return: `0` and `-1`.

Then hypotheses:

- Argument is a pointer.
- The first dword is a magic, signature, opcode, or type tag.
- The function is a validator.

Do not name it `check_header` yet unless cross-references prove the domain.

### Reading in IDA vs raw disassembly

IDA applies heuristics to make disassembly more readable: it guesses variable
names (`var_4`, `arg_0`), infers types, creates cross-reference labels, and
sometimes renames functions based on string proximity or import usage. These
annotations are hypotheses, not facts.

When you see IDA label a stack variable as `nSize` or rename a function to
`process_request`, that is an analyst's guess (or a prior analyst's comment)
propagated through the database. It may be wrong. It often is.

**Strong evidence** comes from the instructions themselves:

- Addresses and offsets: `[ebp+8]` is the first argument. That is a machine
  fact. IDA calling it `arg_0` adds no information.
- Instruction bytes: `cmp dword ptr [eax], 4D434D44h` proves a 4-byte
  comparison against a specific constant. The constant is a fact.
- Operand sizes: `word ptr`, `byte ptr`, `dword ptr` tell you the width of
  the access. These come from the encoding, not from IDA.
- Control flow: the branch targets are encoded in the instruction stream.

**Weak evidence** comes from IDA's analysis layer:

- Variable names like `buf`, `len`, `result` -- these are guesses that may
  reflect a previous analyst's assumptions, not the actual program logic.
- Type annotations like `int`, `char *` -- IDA infers these from usage
  patterns but frequently gets them wrong, especially for signedness.
- Function names derived from string proximity -- a function near the string
  "login" is not necessarily a login function.

Use IDA's annotations as starting hypotheses, but always verify them against
the instruction-level evidence. When the annotation contradicts the instruction,
trust the instruction.

## Common mistakes

- Treating `test eax,eax` as arithmetic. It is usually a question about zero.
- Calling the constant a string without checking endianness and context.
- Ignoring the failure return convention.
- Assuming the pointer is attacker-controlled before walking callers.

## Exercises

### Exercise 1

Assembly only:

```asm
sub_401050:
    mov     eax, [esp+4]
    test    eax, eax
    jz      short bad
    cmp     byte ptr [eax+2], 1
    jnz     short bad
    mov     eax, 1
    retn
bad:
    xor     eax, eax
    retn
```

Answer before reading the solution:

- What does this code accomplish?
- Why does it exist?
- What data is important?
- What can be ignored?

### Exercise 2

```asm
sub_4010A0:
    push    ebp
    mov     ebp, esp
    mov     ecx, [ebp+8]
    test    ecx, ecx
    jz      short ret_zero
    movzx   eax, byte ptr [ecx]
    movzx   edx, byte ptr [ecx+1]
    shl     eax, 8
    or      eax, edx
    add     eax, [ebp+0Ch]
    pop     ebp
    retn
ret_zero:
    xor     eax, eax
    pop     ebp
    retn
```

Answer before reading the solution:

- How many arguments does this function take?
- What arithmetic is performed on the data?
- What is the final return value in terms of the inputs?
- What does the `shl`/`or` sequence accomplish?

### Exercise 3

```asm
sub_4010D0:
    push    ebp
    mov     ebp, esp
    push    esi
    mov     esi, [ebp+8]
    call    dword ptr [__imp__GetLastError@0]
    test    eax, eax
    jz      short success
    cmp     eax, [esi+4]
    ja      short fail
    mov     dword ptr [esi], 1
    xor     eax, eax
    pop     esi
    pop     ebp
    retn
fail:
    mov     dword ptr [esi], 0
    mov     eax, 0FFFFFFFFh
    pop     esi
    pop     ebp
    retn
success:
    mov     dword ptr [esi], 1
    xor     eax, eax
    pop     esi
    pop     ebp
    retn
```

Answer before reading the solution:

- What Win32 API is called and what does its return value represent?
- What are the two conditions under which the function writes `1` to `[esi]`?
- What structure field at `[esi+4]` is used as a threshold?
- What is the calling convention of this function?

## Challenge problems

### Challenge 1

```asm
sub_401080:
    push    ebp
    mov     ebp, esp
    mov     ecx, [ebp+8]
    xor     eax, eax
    test    ecx, ecx
    jz      short done
    cmp     word ptr [ecx], 5A4Dh
    setz    al
done:
    pop     ebp
    retn
```

Explain why this is not merely a "compare function". Identify the programmer's
likely assumption about the pointed-to data.

**OSED connection**: This pattern -- checking the first two bytes of a memory
region for the `MZ` signature -- appears frequently in PE loaders, reflective
DLL injection, and process hollowing. In reflective injection, shellcode walks
the PEB to locate loaded modules, then validates the DOS header signature
before parsing PE headers to resolve exports. In process hollowing, the
injector maps a new image into a suspended process and must verify the PE
structure before fixing up the entry point. Recognizing this two-byte check
as a DOS header validation is a shortcut that immediately narrows the function's
role to PE manipulation.

### Challenge 2

```asm
sub_4010F0:
    push    ebp
    mov     ebp, esp
    push    esi
    push    edi
    mov     esi, [ebp+8]
    mov     edi, [ebp+0Ch]
    test    esi, esi
    jz      short ret_neg
    test    edi, edi
    jz      short ret_neg
    movzx   eax, byte ptr [esi+3]
    movzx   ecx, byte ptr [edi+3]
    sub     eax, ecx
    imul    eax, [ebp+10h]
    pop     edi
    pop     esi
    pop     ebp
    retn
ret_neg:
    mov     eax, 0FFFFFFFFh
    pop     edi
    pop     esi
    pop     ebp
    retn
```

Answer before reading the solution:

- How many arguments does this function take?
- What does the function compute and return?
- Why are both pointers null-checked independently?
- What domain might this represent?

## Solutions with reasoning

### Exercise 1 solution

The function reads one argument from `[esp+4]`, checks it for null, reads one byte
at offset `+2`, and returns `1` only if that byte equals `1`. It likely tests a
field inside a small structure or record.

Plausible pseudocode, introduced only after the reasoning:

```c
int is_enabled(const unsigned char *p) {
    if (!p) return 0;
    return p[2] == 1;
}
```

The important data is the pointer and byte offset `+2`. The absence of an EBP
frame is not important by itself; this is still a normal function.

### Exercise 2 solution

The function takes two arguments: a pointer in `[ebp+8]` and an integer in
`[ebp+0Ch]`. After a null check on the pointer, it reads two unsigned bytes at
offsets `+0` and `+1`, shifts the first byte left by 8, and ORs in the second.
This reconstructs a 16-bit big-endian value from two consecutive bytes. The
function then adds the second argument to this value and returns the result.

Fact ledger:

- Two arguments: pointer and integer.
- Byte at `[ecx]` is loaded unsigned, shifted left 8 bits.
- Byte at `[ecx+1]` is loaded unsigned, ORed into the low byte.
- The `shl 8 / or` sequence is big-endian 16-bit reconstruction.
- The second argument is added to the reconstructed value.
- Null pointer returns 0.

Plausible pseudocode:

```c
int offset_from_header(const unsigned char *p, int base) {
    if (!p) return 0;
    unsigned short val = (p[0] << 8) | p[1];
    return val + base;
}
```

The big-endian reconstruction is the key semantic clue. This pattern appears in
network protocol parsing (network byte order is big-endian) and in file format
parsing for formats that use big-endian fields (Java class files, PNG chunks,
TLS records).

### Exercise 3 solution

The function takes one argument -- a pointer to a structure. It calls
`GetLastError`, which takes no arguments (the `@0` suffix confirms zero bytes
of parameters) and returns the last Win32 error code for the calling thread.

Three paths:

1. `GetLastError` returns 0 (no error): write `1` to `[esi]`, return 0.
2. `GetLastError` returns nonzero but `<=` the threshold at `[esi+4]`:
   write `1` to `[esi]`, return 0.
3. `GetLastError` returns a value `>` the threshold at `[esi+4]`:
   write `0` to `[esi]`, return -1.

The `ja` (jump if above) is an unsigned comparison. The dword at `[esi+4]`
acts as a maximum tolerable error code. The dword at `[esi]` is a status
flag set by this function.

Plausible pseudocode:

```c
int check_error_threshold(STATUS_BLOCK *s) {
    DWORD err = GetLastError();
    if (err == 0 || err <= s->max_error) {
        s->ok = 1;
        return 0;
    }
    s->ok = 0;
    return -1;
}
```

The calling convention is cdecl -- the function uses `retn` without an
immediate operand, so the caller is responsible for cleaning the argument.

### Challenge 1 solution

The code asks whether a non-null pointer begins with the word value `0x5A4D`,
which represents ASCII bytes `M` (`0x4D`) and `Z` (`0x5A`) as loaded on a
little-endian machine. `setz al` materializes the comparison result as a boolean.
The programmer assumes the pointer references at least two readable bytes. An
exploit developer asks whether that pointer can point near an invalid page,
because no structured exception handling appears in the function.

### Challenge 2 solution

The function takes three arguments: two pointers (`[ebp+8]` and `[ebp+0Ch]`)
and an integer (`[ebp+10h]`). Both pointers are null-checked. From each pointer,
a single unsigned byte at offset `+3` is read. The function computes:
`(ptr1[3] - ptr2[3]) * arg3` and returns the result.

Fact ledger:

- Three arguments: pointer, pointer, integer.
- Both pointers are validated independently -- either being null causes -1
  return.
- Only byte offset `+3` is read from each pointer. This is a specific field
  in a structure or a specific position in a buffer.
- `sub eax, ecx` computes the difference of two unsigned bytes. The result
  is a signed 32-bit value (because `movzx` promoted each byte to 32 bits
  before subtraction).
- `imul eax, [ebp+10h]` multiplies the difference by the third argument.
  `imul` with two operands is a signed multiply.
- The function returns a signed scaled difference.

Plausible pseudocode:

```c
int scaled_delta(const unsigned char *a, const unsigned char *b, int scale) {
    if (!a || !b) return -1;
    return (a[3] - b[3]) * scale;
}
```

This could represent a weighted comparison of a specific field, such as a
priority byte, a version number, or a pixel channel value. The independent
null checks suggest the two pointers may come from different sources, not
two elements of the same array.

### Verify in WinDbg

To verify the concepts from this chapter on a live binary:

```
uf sub_401000
```
Unassemble the function to see the raw instruction stream. Compare what WinDbg
shows with what IDA shows -- they should agree on instructions but may differ
on annotations.

```
bp sub_401000; g
```
Set a breakpoint at the function entry and run. When the breakpoint hits:

```
dd poi(ebp+8) L4
```
Display 4 dwords starting at the address pointed to by the first argument.
This lets you see the actual tag value being compared against `4D434D44h`
and verify whether the comparison succeeds or fails.

## Key takeaways

- Assembly instructions are evidence about the programmer's intent, not a
  transcript of source code. Read them as facts to be organized, not lines
  to be translated.

- The fact ledger (inputs, outputs, reads, writes, branch questions) prevents
  premature commitment to a source-level narrative. Fill it out before writing
  pseudocode.

- IDA annotations (variable names, type guesses, function names) are
  hypotheses, not facts. When they contradict the instructions, trust the
  instructions.

- Constants, offsets, and operand sizes are strong evidence. Return conventions
  and import names are medium evidence. Decompiler output and guessed names
  are weak evidence.

- Always ask: "What question is the CPU answering at this decision point?"
  That question is closer to the programmer's intent than any line-by-line
  translation.

## See also

- `x86-osed-assembly-reference/05-eflags-and-conditional-execution.md` --
  detailed coverage of flags, TEST, CMP, and conditional jumps
- `x86-osed-assembly-reference/06-core-instruction-reference.md` -- instruction
  semantics for MOV, XOR, TEST, CMP, and other basics
- `x86-osed-assembly-reference/18-pe-structures-and-export-resolution.md` --
  PE header structures relevant to the MZ challenge problem
- `x86-osed-assembly-reference/23-ida-pro-reading-guide.md` -- how to read
  IDA's output critically
- `osed-reversing-guide/01-register-model.md` -- register roles and conventions
- `osed-reversing-guide/07-data-flow.md` -- tracing data flow through registers
  and memory
- `DRILLS/function_analysis.md` -- drill template for practicing single-function
  analysis with a fact ledger

---
