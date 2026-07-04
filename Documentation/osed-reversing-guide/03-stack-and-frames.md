# Chapter 3 — The Stack and Stack Frames

## 1. Objective

After this chapter you can draw a function's stack frame from its disassembly,
explain the exact relationship between ESP and EBP, locate arguments (positive
EBP offsets) and locals (negative EBP offsets), and — crucially for exploitation —
find where the **saved return address** and **saved EBP** sit relative to a buffer.
This chapter is the backbone of every overflow you will build.

## 2. Background

The stack is a region of memory the CPU manages with implicit rules, and the
compiler layers a *frame* discipline on top of it. Two independent things are
happening and you must not conflate them:

- **The hardware stack.** `push` writes a dword and subtracts 4 from ESP; `pop`
  reads a dword and adds 4. `call` pushes the return address then jumps; `ret`
  pops it into EIP. This is fixed CPU behavior.
- **The compiler's frame.** To give each function a stable place for its arguments
  and locals, the compiler dedicates EBP as an anchor. Arguments end up *above*
  the anchor, locals *below* it. The anchor doesn't move during the function even
  though ESP does (pushes for calls, `alloca`, etc.), which is exactly why a
  separate frame pointer exists.

**The stack grows toward lower addresses.** Draw it that way once and keep the
picture forever: newer data is *lower* on the page, older data is *higher*.

## 3. Mental model

The canonical frame, drawn with high addresses at top (older) and low at bottom
(newer), *after* a standard prologue has run:

```
   higher addresses (older)
   +--------------------------+
   |   arg2                    |  [ebp+0Ch]      caller pushed these
   |   arg1                    |  [ebp+08h]      before 'call'
   +--------------------------+
   |   return address          |  [ebp+04h]      pushed by CALL
   +--------------------------+
   |   saved EBP (caller's)    |  [ebp+00h]  <== EBP points HERE
   +--------------------------+
   |   local_1                 |  [ebp-04h]
   |   local_2                 |  [ebp-08h]
   |   buffer[...]             |  [ebp-40h ...]  locals grow downward
   +--------------------------+  <== ESP points at the current top
   lower addresses (newer)
```

Read this picture as a coordinate system anchored at EBP:

- **`[ebp+8]`, `[ebp+0xC]`, `[ebp+0x10]`, ...** — **arguments**, in order. `+8`
  is the first argument because `+0` is saved EBP and `+4` is the return address,
  each 4 bytes.
- **`[ebp+4]`** — the **saved return address**. This is what an overflow
  overwrites to hijack EIP.
- **`[ebp+0]`** — the **saved caller EBP**.
- **`[ebp-4]`, `[ebp-8]`, ...** — **locals**. More negative = allocated
  "deeper." A char buffer often occupies a range like `[ebp-0x40]`..`[ebp-1]`.

The exploitation-critical relationship falls right out of this: if a buffer starts
at `[ebp-0x40]` and you can write past its end, you march *upward* through the
locals, over saved EBP at `[ebp+0]`, and into the return address at `[ebp+4]`.
The distance from the buffer's start to the return address is
`0x40 + 4 (saved EBP) = 0x44` bytes. Chapter 10 formalizes this; here, just see
*why* the geometry produces that number.

### ESP vs EBP — the distinction that trips everyone

Both point into the stack, but they answer different questions:

- **ESP = "where is the top right now?"** It moves constantly — every `push`,
  every `call`, every argument setup shifts it. It is a *volatile cursor*.
- **EBP = "where is my frame anchored?"** Set once in the prologue, restored in
  the epilogue, otherwise constant. It is a *stable reference*.

Because EBP is stable, the compiler addresses arguments and locals as `[ebp±N]`
with fixed offsets — the offsets don't change no matter how much ESP moves. This
is the entire reason the frame pointer exists. When the compiler *omits* it
(optimized code, `/Oy`), it addresses everything as `[esp±N]` instead and must
adjust those offsets every time ESP moves — readable, but you have to track ESP
(Chapter 11).

## 4. Assembly examples

```asm
; A function taking two args, with a 0x40-byte buffer local
func:
    push    ebp                 ; save caller's frame anchor at [esp]
    mov     ebp, esp            ; EBP now anchors THIS frame (points at saved EBP)
    sub     esp, 40h            ; carve 0x40 bytes of locals; ESP drops
    ; --- frame is now established; the picture in section 3 holds ---

    mov     eax, [ebp+8]        ; eax = arg1
    mov     ecx, [ebp+0Ch]      ; ecx = arg2
    lea     edx, [ebp-40h]      ; edx = &buffer  (address of first local byte)

    ; ... body uses [ebp-40h..] as the buffer, [ebp+8/0xC] as args ...

    mov     esp, ebp            ; discard locals (ESP back to saved-EBP slot)
    pop     ebp                 ; restore caller's EBP; ESP now at return address
    retn                        ; pop return address into EIP
```

Walk the prologue as *establishing the coordinate system*:

- `push ebp` puts the caller's anchor on the stack (so we can restore it) and
  drops ESP by 4.
- `mov ebp, esp` makes EBP point at that saved value. From this instant,
  `[ebp+0]` = saved EBP, `[ebp+4]` = return address, `[ebp+8]` = first argument —
  the offsets are now *defined*.
- `sub esp, 40h` reserves locals below EBP. `0x40` is the total local size (the
  compiler may pad it beyond the sum of local sizes for alignment).

The epilogue reverses it exactly: `mov esp, ebp` frees the locals in one move
(equivalent to `add esp, 40h` here), `pop ebp` restores the caller's anchor, and
`retn` returns. MSVC often compresses `mov esp,ebp / pop ebp` into the single
instruction `leave`.

```asm
; Argument setup at a CALL SITE (the OTHER side of the frame)
    push    ecx                 ; push arg2 (args pushed right-to-left in cdecl/stdcall)
    push    eax                 ; push arg1
    call    func                ; pushes return address, jumps
    add     esp, 8              ; caller cleans 2 args (8 bytes) => __cdecl
```

The `push`es before a `call` are the arguments; count them to count the arguments.
Whether the *caller* (`add esp, 8` after) or the *callee* (`retn 8`) cleans them
tells you the calling convention (Chapter 4).

## 5. Equivalent C

```c
int func(int arg1, int arg2) {   // [ebp+8], [ebp+0xC]
    char buffer[0x40];           // [ebp-0x40 .. ebp-1]
    // ... uses arg1, arg2, buffer ...
    return /* eax */;
}

// call site
func(a, b);                      // push b; push a; call; add esp,8
```

## 6. Reverse engineering methodology

To reconstruct a frame:

1. **Confirm the prologue** and read the `sub esp, N` — `N` is the total local
   area size.
2. **Anchor at EBP.** Mentally (or in IDA's stack view, `Ctrl+K` on a frame
   variable) mark `[ebp+0]=savedEBP`, `[ebp+4]=retaddr`, `[ebp+8]=arg1`,
   `[ebp+0xC]=arg2`, ...
3. **Enumerate locals** by collecting every distinct `[ebp-K]` the body touches;
   the set of `K` values reveals the local layout and their sizes (from the access
   width and neighboring offsets).
4. **Enumerate arguments** by collecting every `[ebp+8+4m]` touched. The largest
   one hints at the argument count (but varargs and unused args complicate this —
   confirm at the call site by counting pushes).
5. **Locate the danger geometry.** Note where any buffer (`lea` of a `[ebp-K]`
   passed to a copy routine) starts, and compute its distance to `[ebp+4]`.
6. **Verify in WinDbg.** Break at the function, `dd @ebp-0x40 L20` to see the
   buffer, `dd @ebp L4` to see saved EBP and return address, and confirm your
   offsets against real memory.

IDA already names these for you: `arg_0` = `[ebp+8]`, `arg_4` = `[ebp+0xC]`,
`var_4` = `[ebp-4]`, `var_40` = `[ebp-0x40]`. Trust the offsets in the names, but
still verify the *size* and *use* yourself — the name is a slot, not a type.

## 7. Common compiler idioms

- **`push ebp / mov ebp, esp / sub esp, N`** — the standard prologue. Its presence
  = an EBP-anchored frame.
- **`leave`** — equivalent to `mov esp, ebp / pop ebp`. Same epilogue, one opcode.
- **`retn N`** — callee-cleanup return (`__stdcall`); `N` bytes of args freed.
  Bare `retn` with a caller-side `add esp, N` = `__cdecl`.
- **Security cookie** — `mov eax, ___security_cookie / xor eax, ebp / mov
  [ebp-4], eax` in the prologue and a matching `__security_check_cookie` in the
  epilogue. This is `/GS` stack-canary code, not program logic (Chapter 10).
- **Frame-pointer omission** — no `push ebp`; everything is `[esp+N]`. Optimized
  builds; see Chapter 11.

## 8. Common mistakes

- **Drawing the stack growing up.** Then every offset sign is backwards and the
  overflow direction is wrong. Growth is toward *lower* addresses; overflow writes
  toward *higher* addresses (over saved EBP, then retaddr).
- **Forgetting the two dwords between the first local and the first argument.**
  `[ebp+0]` (saved EBP) and `[ebp+4]` (retaddr) sit between locals and args. The
  first argument is `[ebp+8]`, not `[ebp+4]`.
- **Assuming `sub esp, N` equals the number of source variables.** `N` includes
  alignment padding, spilled temporaries, and cookie slots. It's the *frame size*,
  not the variable count.
- **Reading `[esp+N]` as a fixed slot without tracking ESP.** In FPO code ESP
  moves; the same slot has a different `N` after each push. Track ESP explicitly.
- **Confusing saved EBP with the return address.** Overwriting `[ebp+0]` corrupts
  the caller's frame pointer; overwriting `[ebp+4]` hijacks EIP. They are adjacent
  but do very different things.

## 9. Exercises

1. A function's prologue is `push ebp / mov ebp, esp / sub esp, 0x80`. A buffer is
   accessed at `[ebp-0x80]`. How many bytes from the start of that buffer to the
   saved return address? Show the arithmetic.
2. At a call site you see three `push`es, a `call`, and then `retn` inside the
   callee is `retn 0Ch`. Which calling convention, how many arguments, and who
   cleans the stack?
3. In WinDbg you break at a function's first body instruction and run
   `dd @ebp L4`. Explain what each of the four dwords is.
4. Why can the compiler use fixed `[ebp+8]` for arg1 throughout the function even
   though the body does many `push`es and `call`s that move ESP?

## 10. Summary

- The stack grows down; `push` lowers ESP, `pop` raises it, `call` pushes retaddr,
  `ret` pops it.
- The prologue establishes an EBP-anchored coordinate system: `[ebp+0]` saved EBP,
  `[ebp+4]` return address, `[ebp+8..]` arguments, `[ebp-4..]` locals.
- **ESP is a volatile cursor; EBP is a stable anchor.** Fixed-offset addressing of
  args/locals is *why* the frame pointer exists.
- The distance from a buffer local to `[ebp+4]` is the overflow offset to EIP —
  read it straight off the geometry.
- Confirm every reconstructed offset against real memory in WinDbg before trusting
  it.
