# Reading Assembly as Semantic Evidence

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

## Common mistakes

- Treating `test eax,eax` as arithmetic. It is usually a question about zero.
- Calling the constant a string without checking endianness and context.
- Ignoring the failure return convention.
- Assuming the pointer is attacker-controlled before walking callers.

## Exercises

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

## Challenge problems

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

## Solutions with reasoning

Exercise solution:

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

Challenge solution:

The code asks whether a non-null pointer begins with the word value `0x5A4D`,
which represents ASCII bytes `M` (`0x4D`) and `Z` (`0x5A`) as loaded on a
little-endian machine. `setz al` materializes the comparison result as a boolean.
The programmer assumes the pointer references at least two readable bytes. An
exploit developer asks whether that pointer can point near an invalid page,
because no structured exception handling appears in the function.

---
