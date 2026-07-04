# Chapter 2 — Memory, Addressing Modes, and Pointer Arithmetic

## 1. Objective

After this chapter you can read any x86 memory operand
`[base + index*scale + disp]`, translate it back into the C pointer or array
expression that produced it, recognize `lea` as address arithmetic rather than a
memory access, and infer element sizes (and therefore types) from the `scale` and
`disp` the compiler chose.

## 2. Background

C hides addresses behind names and types. `arr[i]`, `p->field`, `*(base + n)` are
all *address computations* the compiler performs for you using the sizes of the
types involved. x86 does not have types, so all of that collapses into a single,
uniform addressing expression the CPU evaluates in hardware. The good news: that
expression is small and total. Every memory access in x86 is some subset of:

```
   effective address = base + index * scale + displacement
```

where `base` and `index` are registers, `scale` is 1, 2, 4, or 8, and
`displacement` is a constant. Because C's pointer arithmetic *is* "multiply the
index by the element size and add," the `scale` and `disp` the compiler picks are
a direct fingerprint of the original types. Reading them backward recovers
structure.

## 3. Mental model

Read every `[...]` as a tiny formula and ask what C expression yields it:

```
   [ebx]                 *ebx                      (deref a pointer)
   [ebx+4]               *(ebx+4)  OR  ebx->field_at_4   (fixed offset -> struct field or [1] of dword)
   [ebx+eax]             *(ebx+eax)                (byte array index, element size 1)
   [ebx+eax*4]           ebx[eax]  where elem is 4 bytes  (int/ptr array)
   [ebx+eax*4+8]         (struct at ebx).arr[eax], arr starting +8, 4-byte elems
```

The mapping rule, memorize the *reasoning* not the table:

- **scale = element size.** `*1` → bytes (`char`), `*2` → words (`short`), `*4` →
  dwords (`int`, pointers, `float`), `*8` → qwords (`__int64`, `double`).
- **displacement = fixed offset from a base**, which means either a **struct field
  offset** (base is a struct pointer) or the **start of an array within a larger
  object**, or a **stack local's slot** (base is EBP/ESP — see Chapter 3).
- **index register = the thing that varies at runtime** — a loop counter, an
  argument index. If it's `*scale`, it's being used as an *array index*, and the
  compiler scaled it by the element size for you.

The single most important consequence: **`*scale` tells you the element size, and
element size tells you the type.** You recover `int arr[]` vs `char arr[]` purely
from whether the compiler wrote `*4` or `*1`.

## 4. Assembly examples

```asm
; Example A: array of ints, classic scaled index
    mov     eax, [ebp+i]        ; eax = i  (a local, Chapter 3)
    mov     ecx, [ebp+arr]      ; ecx = base pointer 'arr'
    mov     edx, [ecx+eax*4]    ; edx = arr[i]   <- *4 means 4-byte elements
```

`[ecx + eax*4]`: base `arr`, index `i`, scale 4. That is exactly the address of
`arr[i]` for a 4-byte element type. We conclude `arr` points to 4-byte elements —
`int` or a pointer — *because the scale is 4*, not because of any name.

```asm
; Example B: struct field access (fixed displacement, no index)
    mov     eax, [ebp+p]        ; eax = p  (a pointer)
    mov     ecx, [eax+8]        ; ecx = *(p + 8) = p->field_at_offset_8
    mov     edx, [eax+0Ch]      ; edx = p->field_at_offset_0x0C
```

Fixed displacements `+8` and `+0xC` with the *same base pointer* mean we're
reaching into a structure. Two dword fields, one at offset 8 and one at 0xC (12),
tells us the struct is at least 16 bytes and has dword-sized fields there. This is
the raw material of struct recovery (Chapter 8).

```asm
; Example C: lea is arithmetic, NOT a load
    lea     eax, [ebx+ebx*4]    ; eax = ebx * 5   (no memory touched!)
    lea     ecx, [edx+ecx*8-1]  ; ecx = edx + ecx*8 - 1
    lea     eax, [ebp-40h]      ; eax = address of the local at ebp-0x40
```

`lea` (Load Effective Address) computes the address expression and stores the
*number*, without dereferencing. The CPU has a fast address-adder, so compilers
abuse `lea` for cheap multiply-add. `lea eax, [ebx+ebx*4]` is `ebx*5` — the
compiler turned `x * 5` into one instruction. And `lea eax, [ebp-40h]` is the
idiom for **"take the address of a local"** — the `&buf` you'll see feeding
`gets`, `strcpy`, `recv`, etc. (Chapter 10).

```asm
; Example D: byte string walk (scale 1, pointer increments)
    mov     al, [esi]           ; al = *esi
    inc     esi                 ; esi++  (pointer arithmetic on char* => +1)
```

`inc esi` advancing a pointer by 1 confirms 1-byte elements: a `char *` walk.

## 5. Equivalent C

```c
// A
int x = arr[i];               // [ecx + eax*4]

// B
struct S { char pad[8]; int a; int b; };  // fields at +8 and +0xC
int a = p->a;                 // [eax+8]
int b = p->b;                 // [eax+0xC]

// C
int y = x * 5;                // lea eax,[ebx+ebx*4]
char *q = &buf[0];            // lea eax,[ebp-0x40]

// D
char c = *p; p++;             // mov al,[esi]; inc esi
```

## 6. Reverse engineering methodology

To decode a memory operand:

1. **Identify the four parts.** base, index, scale, displacement. Any may be
   absent.
2. **Classify the base.** EBP/ESP → a stack local or argument (Chapter 3). A
   general register loaded from an argument or `malloc` → a heap/pointer object.
   An absolute address (`dword_40A000`) → a global.
3. **Read the scale as element size** → candidate element type.
4. **Read the displacement** as a field offset (struct) or slot (stack), and start
   sketching the layout.
5. **Watch whether the index varies in a loop** → it's an array traversal;
   whether it's fixed → it's a specific field.
6. **Treat `lea` specially.** If the destination is later dereferenced, `lea`
   produced an address (`&something`). If it's used as a number in arithmetic, the
   compiler used `lea` as a multiply-add and you should simplify it algebraically.

## 7. Common compiler idioms

- **Strength reduction via `lea`.** `x*3` → `lea eax,[eax+eax*2]`; `x*5` →
  `[eax+eax*4]`; `x*9` → `[eax+eax*8]`. Recognize these as multiplication by a
  constant, and back-solve the constant.
- **Shifts for power-of-two multiply/divide.** `shl eax, 2` is `*4`; `sar eax, 3`
  is signed `/8`. `imul` appears only for non-trivial constants or variables.
- **`add`/`inc` on a pointer inside a loop** = pointer post-increment; the amount
  is the element size (1 for `char*`, 4 for `int*`/`T**`).
- **Base+index+scale+disp all present** = indexing an array that lives at a fixed
  offset inside a struct: `obj->table[i]`.
- **`movzx`/`movsx` on the loaded value** = the element is smaller than a dword
  and is being promoted; confirms `char`/`short` and its signedness (Chapter 1).

## 8. Common mistakes

- **Reading `lea` as a memory load.** It never touches memory. `lea eax,[eax+eax*4]`
  does not read address `eax*5`; it *computes* `eax*5`. Misreading this invents
  phantom dereferences.
- **Assuming scale 1 means `char`.** Scale 1 with no index just means a direct
  deref or a fixed offset; the element could be anything if accessed a dword at a
  time. Confirm with the *size of the move* (`mov al` vs `mov eax`).
- **Confusing "offset into struct" with "array index."** A *fixed* displacement is
  a field; a *variable* index (`*scale`) is an array subscript. `[eax+8]` is a
  field; `[eax+ecx*8]` is `arr[ecx]` of 8-byte elements.
- **Forgetting the move width.** `mov al, [eax+edi]` reads one byte even if the
  object is larger; the access width, not the object, sets the element size here.

## 9. Exercises

1. Decode each and give the C: `[esi+edi*2]`, `[eax+10h]`, `[ecx+eax*8+4]`,
   `lea edx,[eax+eax*2]`.
2. In `mov cl, [ebx+eax]` followed by `inc eax`, what is the element size, the
   likely element type, and the C loop body?
3. You see `lea eax, [ebp-2Ch]` then `push eax` then `call sub_401500`. What is
   being passed to the function, and why does that matter for exploitation?
4. Distinguish, from the operand alone, `obj->count` from `arr[k]`. What in the
   encoding tells them apart?

## 10. Summary

- Every x86 memory access is `[base + index*scale + disp]`; that single formula
  encodes all of C's pointer arithmetic.
- **Scale = element size = a type hint.** `*4` → 4-byte elements (int/pointer),
  `*1` → bytes (char).
- **Fixed displacement = struct field or stack slot; variable scaled index =
  array subscript.**
- `lea` computes an address/number without dereferencing; compilers use it for
  cheap multiply-add and for `&local`. Simplify it algebraically.
- Access width (`al`/`ax`/`eax`) and `movzx`/`movsx` refine the element type and
  its signedness.
