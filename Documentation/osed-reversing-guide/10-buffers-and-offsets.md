# Chapter 10 — Deriving Buffer Sizes and Overwrite Offsets

## 1. Objective

After this chapter you can derive, from disassembly, the size of a stack buffer,
the exact byte offset from the start of that buffer to the saved return address,
and how stack protections (`/GS` cookie) and frame layout affect that offset. You
will be able to compute the "EIP offset" statically and then confirm it in WinDbg
with a cyclic pattern — the core measurement of a stack overflow exploit.

## 2. Background

Everything in Chapters 3 and 9 converges here. A stack buffer overflow works
because a buffer local sits *below* the saved return address in memory (Chapter 3),
and an unbounded copy (Chapter 9) writes past the buffer's end, marching upward
over saved registers, saved EBP, and finally the return address. To hijack EIP you
must know precisely how many bytes of input land before the 4 bytes that overwrite
`[ebp+4]`. That number is the **offset**, and getting it wrong by even one byte
means your return address lands in the wrong place.

You derive the offset two ways and make them agree: **statically** from the frame
geometry, and **dynamically** from a cyclic ("De Bruijn") pattern in WinDbg. Static
tells you what it *should* be; dynamic proves it and catches anything the static
model missed (saved registers, cookies, alignment, compiler-inserted slack).

## 3. Mental model

The overflow travels *up* the stack from the buffer toward the return address:

```
   memory layout during the vulnerable copy (high addr at top):

   +------------------------+  [ebp+08h]   arg1
   +------------------------+  [ebp+04h]   RETURN ADDRESS   <== target (overwrite this)
   +------------------------+  [ebp+00h]   saved EBP        <== 4 bytes
   +------------------------+  [ebp-04h]   saved-reg / cookie slot (maybe)
   |  ...other locals...    |
   +------------------------+  [ebp-40h]   buffer[0]        <== copy starts writing here
   +------------------------+
        write direction:  buffer[0] ---> upward ---> retaddr

   offset(buffer -> retaddr) = (distance buffer..ebp)  +  4 (saved EBP)
                             = (0x40)                   +  4   = 0x44   (=68)
   ...IF no saved registers or cookie sit between the buffer and saved EBP.
```

The formula in words: **offset = (EBP − &buffer) + 4**. `(EBP − &buffer)` is how
far the buffer start is below the saved-EBP slot; the `+4` steps over saved EBP to
reach the return address at `[ebp+4]`.

But the frame is rarely that clean. Adjustments you must account for:

- **Saved registers** (`push esi/edi/ebx` in the prologue) live *between* the
  locals and saved EBP in some layouts, or the buffer may be higher up among the
  locals than `[ebp-buffersize]`. What actually matters is the buffer's real offset
  from EBP, which you read from the `lea`/access, not an assumed `-buffersize`.
- **`/GS` security cookie** — a canary at `[ebp-4]` checked before `ret`. It sits
  between the locals and saved EBP. If your overflow crosses it, the check fails and
  the process aborts *before* `ret` — so a naive stack smash won't reach EIP. (You
  then need a different technique: SEH overwrite, an overwrite that avoids the
  cookie, or an info leak. Recognizing the cookie tells you which path you're on.)
- **Alignment / frame slack** — `sub esp, N` may exceed the sum of locals; extra
  padding shifts nothing about the buffer→EBP distance but explains "why is the
  frame bigger than my variables."

So the reliable static offset is derived from the *actual* buffer offset relative to
EBP (from the `lea reg, [ebp-X]` that feeds the copy), plus 4, plus any cookie/saved
data *the overflow path crosses* — and then you confirm with a pattern.

## 4. Assembly examples

```asm
; Vulnerable function: recv into a big buffer, strcpy-shaped copy into a small one
vuln:
    push    ebp
    mov     ebp, esp
    sub     esp, 44h            ; 0x44 bytes of locals (buffer + maybe slack)
    ; ... no push esi/edi/ebx here, no cookie -> clean frame

    lea     eax, [ebp-40h]      ; &dst buffer  -> buffer is at EBP-0x40
    push    [ebp+0Ch]           ; src = attacker string
    push    eax                 ; dst
    call    my_strcpy           ; unbounded copy (proven in Chapter 9)

    mov     esp, ebp
    pop     ebp
    retn
```

Static derivation:
- Buffer starts at `[ebp-0x40]` (from the `lea`). So `EBP − &buffer = 0x40`.
- Offset to return address = `0x40 + 4 (saved EBP) = 0x44 = 68` bytes.
- Therefore input bytes `0..67` fill up to and including saved EBP, and bytes
  `68..71` overwrite `[ebp+4]`, the return address.
- The `sub esp, 44h` (0x44) is *frame size*, coincidentally close to the offset,
  but note the offset came from the buffer's EBP-relative position (0x40) **+ 4**,
  not from the frame size. Don't conflate them — that coincidence breaks the moment
  there are other locals.

```asm
; Same function but with a /GS cookie — the overflow can't naively reach EIP
vuln_gs:
    push    ebp
    mov     ebp, esp
    sub     esp, 44h
    mov     eax, ___security_cookie
    xor     eax, ebp            ; canary = cookie ^ ebp
    mov     [ebp-4], eax        ; stored at [ebp-4], between locals and saved EBP
    ...
    lea     eax, [ebp-40h]
    ...
    call    my_strcpy
    ...
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    ___security_check_cookie   ; aborts if canary was corrupted
    mov     esp, ebp
    pop     ebp
    retn
```

Now the path from `buffer[0]` at `[ebp-0x40]` to the return address crosses the
cookie at `[ebp-4]`. A linear overflow that reaches `[ebp+4]` *must* have trampled
`[ebp-4]`, so `__security_check_cookie` fails and the program terminates before
`ret`. The static offset is still 0x44, but the presence of the cookie tells you a
straight EIP overwrite won't work — you've learned the exploit *strategy* from the
frame, which is the real payoff of reading it.

## 5. Equivalent C

```c
// vuln
void vuln(int sock, char *attacker_input) {
    char dst[0x40];              // [ebp-0x40]
    my_strcpy(dst, attacker_input);   // unbounded -> overflow at offset 0x44 to retaddr
}
// input layout: [ 0x40 bytes fill dst .. saved EBP ][ 4 bytes = new EIP ][ ... ]
//                 <----------- 0x44 (68) ----------->
```

## 6. Reverse engineering methodology

1. **Find the buffer's EBP offset** from the `lea reg, [ebp-X]` (or `[esp+X]` in
   FPO code) that feeds the vulnerable copy. That `X` is `EBP − &buffer`.
2. **Confirm the copy is unbounded** (Chapter 9). If it's bounded, there's no
   overflow (or a limited one) — quantify the max bytes it can write.
3. **Enumerate what sits between the buffer and `[ebp+4]`:** other locals, saved
   registers (`push ebx/esi/edi` in the prologue → `pop` in epilogue), and a `/GS`
   cookie at `[ebp-4]`. Anything the linear overflow crosses is part of the offset
   *and* may trigger a protection.
4. **Compute the static offset** to the return address = buffer-to-EBP distance +
   4. If a cookie or SEH is involved, note the strategy change.
5. **Confirm dynamically** in WinDbg: send a cyclic pattern (e.g., MSF pattern /
   `!py mona pattern_create`), let it crash, read the faulting `EIP`, and look up
   the offset (`pattern_offset`). It should match your static number; if not, the
   difference is exactly the saved registers/cookie/slack you missed — reconcile it.
6. **Verify control:** replace the 4 offset bytes with a marker (`0x42424242`) and
   confirm `EIP = 42424242` at the crash. Now the offset is proven.

## 7. Common compiler idioms

- **`sub esp, N`** = frame size (locals + slack), an *upper bound* on the buffer's
  distance from EBP but not the offset itself.
- **`lea reg, [ebp-X]` feeding a copy** = the buffer at offset X; this is the number
  to trust.
- **`push ebx/esi/edi`** in the prologue = callee-saved registers on the stack;
  depending on layout they may sit between locals and saved EBP and add to the
  offset — measure, don't assume.
- **`___security_cookie` / `xor eax, ebp` / `[ebp-4]` / `__security_check_cookie`**
  = `/GS`. Signals "linear stack smash to EIP is blocked; consider SEH/other."
- **`mov large_size` / `call __chkstk`** = a big frame (>1 page) probed into
  existence; large buffers live here.
- **SEH frame setup** (`push offset handler / push fs:[0] / mov fs:[0], esp`) =
  structured exception handling on the stack; an overflow may target the SEH record
  instead of the return address (a whole separate technique).

## 8. Common mistakes

- **Using the frame size (`sub esp, N`) as the offset.** The offset is
  buffer-to-EBP + 4. They coincide only when the buffer is the *lowest* local and
  there are no saved registers/cookie — often false. Read the buffer's actual `lea`.
- **Forgetting the +4 for saved EBP.** The return address is `[ebp+4]`, one dword
  above saved EBP. Off-by-4 puts your address in saved EBP instead of EIP.
- **Ignoring saved registers between buffer and saved EBP.** They add to the byte
  distance; the cyclic pattern will reveal the discrepancy — reconcile it, don't
  hand-wave.
- **Missing the `/GS` cookie** and wondering why the process dies before `ret`
  despite a "correct" offset. The cookie check runs first.
- **Not verifying dynamically.** Static geometry is a hypothesis; the pattern is the
  proof. Skipping it is how you burn exam time on an offset that's 8 bytes off.
- **Assuming little-endian is handled for you.** The 4 EIP bytes go into memory
  little-endian; your target address `0x00401234` is written `34 12 40 00`.

## 9. Exercises

1. A function does `sub esp, 0x60`, saves no registers, no cookie, and the vulnerable
   buffer is at `[ebp-0x50]`. What is the offset from buffer start to the return
   address? Why isn't it 0x60?
2. Same function but with `push esi / push edi` in the prologue and the buffer at
   `[ebp-0x50]`. Does the buffer→retaddr offset change? Explain what the saved
   registers do and do not affect here.
3. You compute a static offset of 0x44 but the cyclic pattern says EIP was
   controlled at offset 0x4C. Name three things that could account for the 8-byte
   difference and how you'd confirm which.
4. A frame contains `___security_cookie` / `xor eax, ebp` / `mov [ebp-4], eax`. Your
   offset math is correct, but the process aborts before returning. Why, and what
   changes about your approach?

## 10. Summary

- Overflow offset to the return address = (buffer's distance below EBP) + 4 for
  saved EBP; read the buffer's distance from the `lea [ebp-X]` that feeds the copy,
  not from the frame size.
- Account for anything the linear overflow crosses: other locals, saved registers,
  and especially a `/GS` cookie at `[ebp-4]`.
- The `/GS` cookie means a straight stack-smash to EIP is blocked (it's checked
  before `ret`) — recognizing it redirects you to SEH/other techniques.
- Static geometry gives a hypothesis; a cyclic pattern in WinDbg proves the exact
  offset and catches saved-register/cookie/slack surprises.
- Remember little-endian when placing the 4 EIP bytes.
