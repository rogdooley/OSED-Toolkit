# Chapter 8 — Structures, Arrays, and Heap vs Stack

## 1. Objective

After this chapter you can recover a `struct` layout from field-offset accesses,
tell arrays from structures, distinguish stack, heap, and global allocations by
where their base pointer comes from, and read allocation sizes so you know how big
an object is and what fields it contains. This turns opaque `[reg+N]` accesses into
a typed data model.

## 2. Background

C aggregates — structs and arrays — are a fiction the compiler maintains with
arithmetic. A `struct` is a base address plus fixed field offsets; an array is a
base address plus a scaled index. At the machine level both are just
`[base + something]`. The difference, and it's the whole of struct recovery, is:

- **Struct field** → *fixed* displacement (`[eax+0]`, `[eax+8]`, `[eax+0xC]`), each
  offset a different named member.
- **Array element** → *variable* scaled index (`[eax+ecx*4]`), the same member type
  repeated.

The *storage class* — stack, heap, or global — is not a property of the type; it's
where the base pointer was born. You read it from the base's origin: EBP/ESP-relative
(stack), returned by an allocator (heap), or an absolute address (global). Each has
different lifetime and different exploitation implications, so you must classify it.

## 3. Mental model

To recover a struct, collect every access sharing a base pointer and lay out the
offsets:

```
   observed accesses          inferred layout of *p
   -----------------          ---------------------
   mov eax,[esi+0]     -->     +0x00  field_0   (dword; access width = eax)
   mov cx, [esi+4]     -->     +0x04  field_4   (word;  access width = cx)
   mov dl, [esi+6]     -->     +0x06  field_6   (byte)
   lea edi,[esi+8]     -->     +0x08  buffer[..] (address taken -> array/inline buf)
   mov eax,[esi+28h]   -->     +0x28  field_28
                              size >= 0x2C (last field + its width)
```

Where the base comes from = the storage class:

```
   base pointer origin                    storage class    lifetime
   -----------------------------------    -------------    -----------------------
   lea reg,[ebp-N]  / [esp+N]             STACK            until function returns
   call malloc/HeapAlloc/new -> eax       HEAP             until free/HeapFree
   dword_XXXXXX (absolute) / offset g     GLOBAL/.data     process lifetime
   [ebp+8] passed in                      CALLER'S (any)   depends on caller
```

Field *sizes* come from the **access width** (`al`/`ax`/`eax` = 1/2/4 bytes) and
from the *gaps* between offsets (a field at +4 followed by one at +8 is 4 bytes;
a gap larger than the access width means padding or an inline array/sub-struct).
The compiler's **alignment padding** (fields aligned to their size, struct to its
largest member) explains gaps that aren't real fields — don't invent a member to
fill a pad byte.

## 4. Assembly examples

```asm
; Example A: struct recovery from a heap object
    push    30h                 ; size = 0x30 bytes  -> the object is 48 bytes
    call    malloc
    add     esp, 4
    mov     esi, eax            ; esi = base of the heap struct  (HEAP class)

    mov     dword ptr [esi], 0          ; field +0x00 = 0   (dword)
    mov     dword ptr [esi+4], 1        ; field +0x04 = 1   (dword)
    mov     byte  ptr [esi+8], 41h      ; field +0x08 = 'A' (byte -> char/flag)
    lea     eax, [esi+0Ch]              ; &field +0x0C  -> address taken => buffer
    push    eax
    call    sub_401700                  ; fills the inline buffer at +0x0C
```

Derivation: `malloc(0x30)` → a 48-byte heap object based at `esi`. Fields at +0,
+4 (dwords), a byte flag at +8, and at +0xC the *address is taken* and passed to a
fill routine → an inline buffer starting at offset 0xC. The object is 0x30 bytes,
so that buffer is up to `0x30 - 0xC = 0x24` bytes. We've recovered a struct without
a single name:

```c
struct S {          // total 0x30
    int   a;        // +0x00
    int   b;        // +0x04
    char  flag;     // +0x08
    /* +0x09..0x0B padding */
    char  buf[0x24];// +0x0C
};
```

```asm
; Example B: array vs struct — telling them apart
    ; (i) array: same operation, VARIABLE index
    mov     eax, [ebp+i]
    mov     ecx, [esi+eax*4]    ; base[i], 4-byte elems, i varies  -> ARRAY

    ; (ii) struct: DIFFERENT operations, FIXED offsets
    mov     ecx, [esi+0]        ; field a
    mov     edx, [esi+4]        ; field b (different semantics)
```

The array access uses a *runtime* index (`eax*4`) — one element type repeated. The
struct accesses use *constant* offsets with different subsequent handling — distinct
members. That distinction (variable scaled index vs fixed displacement) is the
entire test.

```asm
; Example C: stack vs global base
    lea     esi, [ebp-40h]      ; STACK object: base is EBP-relative, dies at return
    ; vs
    mov     esi, offset dword_40A020  ; GLOBAL object: fixed .data address, lives forever
```

## 5. Equivalent C

```c
// A
struct S { int a, b; char flag; char buf[0x24]; };
struct S *p = malloc(sizeof *p);   // 0x30
p->a = 0; p->b = 1; p->flag = 'A';
fill(p->buf);

// B(i) array; B(ii) struct
int x = base[i];                   // variable index
int a = p->a, b = p->b;            // fixed offsets

// C
char local[0x40];                  // stack, dies at return
static int g_val;                  // global, .data
```

## 6. Reverse engineering methodology

1. **Group accesses by base register.** Every `[reg+K]` sharing a `reg` that holds
   one object contributes to that object's layout.
2. **Classify the storage.** Trace the base to its origin: `lea [ebp-N]` (stack),
   allocator return (heap), absolute/`offset` (global), or an incoming argument
   (caller's — follow up the call graph).
3. **Read the allocation size** (the argument to `malloc`/`HeapAlloc`/`new`) — it's
   an upper bound on the struct and tells you total size before you've seen every
   field.
4. **Tabulate offsets and widths.** For each distinct `K`, note the access width
   (`al`/`ax`/`eax`) → field size. Fill the layout; mark address-taken offsets as
   inline buffers/sub-structs.
5. **Account for alignment.** Gaps that match natural alignment are padding, not
   fields. Don't fabricate members to fill them.
6. **Distinguish array vs struct** at each access: variable scaled index = array;
   fixed displacement = field.
7. **Define the type in IDA** (Local Types / `Structures` window, `Alt+Q`), then
   apply it to the base register (`Y` / "set type"). IDA will re-annotate every
   `[reg+K]` with the field name — massively improving readability and catching
   offsets you missed.
8. **Verify in WinDbg** with `dt` (if symbols) or `dd <base> L<n>` and inspect the
   field values against your model.

## 7. Common compiler idioms

- **`malloc`/`HeapAlloc` size = object size** (sometimes `count * elem` computed
  inline via `imul`/`lea` — that reveals element size and count of an array of
  structs).
- **`memset(obj, 0, size)`** right after allocation (often `rep stosd` with
  ECX=size/4) — zero-initialization of the whole struct; the size confirms total
  object size.
- **Inline buffers** appear as an offset whose *address is taken* (`lea`) and
  passed to a copy/fill, rather than loaded as a scalar.
- **Nested structs** show as a sub-range of offsets with their own internal
  structure; a `lea [base+K]` passed to a function that then does its own `[reg+J]`
  accesses = a pointer to an inner struct at +K.
- **Global structs/arrays** as `dword_XXXX`, `byte_XXXX` — consecutive globals IDA
  named separately are often one array or struct; re-group them.
- **`this`-based access** (`[ecx+K]`) in C++ methods — same recovery, base is the
  object pointer in ECX (Chapter 4).

## 8. Common mistakes

- **Inventing fields for padding.** A 3-byte gap after a `char` before an aligned
  `int` is alignment, not three `char` members.
- **Merging two different objects** because they happen to reuse a register. Track
  the base's *value*, not the register name; ESI may hold object A, then object B.
- **Reading an inline buffer as a scalar field.** If the address is taken and
  filled, it's a buffer/array, not a dword.
- **Assuming stack vs heap from the type.** The same struct can live on the stack in
  one function and the heap in another. Storage class = where the base came from,
  every time.
- **Trusting `malloc` size as exact field sum.** It may include trailing slack or a
  flexible array. It's an upper bound and a strong hint, not gospel.
- **Missing element size in arrays of structs.** `[base + i*0x30]` means 0x30-byte
  elements — an array of the 48-byte struct from Example A, not 48 separate ints.

## 9. Exercises

1. From these accesses recover the struct and its minimum size: `mov eax,[edi]`,
   `mov [edi+4], bx` (word), `mov byte ptr [edi+6], 1`, `lea eax,[edi+8]` passed to
   a 16-byte copy, `mov ecx,[edi+18h]`.
2. `push 0x140 / call malloc / imul eax, esi, 0x28` nearby, with accesses
   `[base+ecx*0x28]`. What kind of object is this, how many elements, and what is
   each element?
3. Given `mov esi, offset dword_409000` and later `[esi+ecx*4]`, what is the storage
   class and what's the object? How does its lifetime differ from a `[ebp-N]`
   version?
4. You see a 3-byte gap between a field at +9 and one at +0xC. Is +9..+0xB three
   char fields or padding? What evidence would settle it?

## 10. Summary

- Structs are base + fixed offsets; arrays are base + variable scaled index. That
  distinction is the core of aggregate recovery.
- Storage class (stack/heap/global) = where the base pointer was born
  (EBP-relative / allocator return / absolute address), not a property of the type.
- Allocation size bounds the object and often encodes element size × count for
  arrays of structs.
- Field sizes come from access widths and inter-offset gaps; account for alignment
  padding instead of inventing members.
- Define the recovered struct in IDA and apply it to propagate names; confirm the
  layout against live memory in WinDbg.
