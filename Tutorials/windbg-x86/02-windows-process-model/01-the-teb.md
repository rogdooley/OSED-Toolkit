# Exercise 01 — The TEB (Thread Environment Block)

## The question

The FS segment register points at the current thread's TEB. Where exactly does
it point, and what is at offset `0x30`?

---

## Setup

Attach to any running x86 process. `stack_lab_x86.exe HelloWorld` works fine.
Break anywhere in the process after `main` has started.

---

## Step 1 — Find the TEB address

The FS segment register, on x86 Windows, is loaded by the kernel to point to
the TEB of the currently executing thread. The TEB is also known as the Thread
Information Block (TIB).

Two ways to find the TEB address:

**Method A — WinDbg pseudo-register:**

```
0:000> r $teb
```

**Method B — Read the TEB's own `Self` field:**

The TEB structure has a field at offset `0x18` called `Self` — a pointer to
the TEB itself. That means `fs:[0x18]` is a pointer to the start of the TEB:

```
0:000> dd fs:[18] L1
```

Both should give you the same address. Call it `TEB_ADDR`.

**Method C — dt:**

```
0:000> dt ntdll!_TEB @$teb
```

This dumps the entire TEB with field names. Scroll through it — it's large.
The fields relevant to exploit development are near the top.

---

## Step 2 — Read the TEB's critical fields manually

The TEB layout for x86 (abbreviated; full definition in `Documentation/Windows/WindowsInternals/TEB.md`):

```
Offset  Size  Field
0x00    4     ExceptionList      (pointer to first SEH EXCEPTION_REGISTRATION_RECORD)
0x04    4     StackBase          (top of the thread's stack, highest address)
0x08    4     StackLimit         (bottom of the thread's committed stack)
0x0c    4     SubSystemTib
0x10    4     FiberData
0x14    4     ArbitraryUserPointer
0x18    4     Self               (points to TEB itself — useful for locating TEB address)
...
0x30    4     ProcessEnvironmentBlock   <-- the one you need
```

Read the key fields manually with `dd`:

```
0:000> dd TEB_ADDR L0x0d          ; read first 13 DWORDs (0x34 bytes / 4)
```

Identify:
- Offset `0x00`: ExceptionList. Dereference it with `dd poi(TEB_ADDR)` — you
  should see the first SEH record on the stack.
- Offset `0x04`: StackBase. Compare to your current `esp` — `esp` should be
  below StackBase (stack grows down).
- Offset `0x08`: StackLimit. The lowest committed stack address.
- Offset `0x18`: Self. Should equal `TEB_ADDR`.
- Offset `0x30`: PEB pointer. This is the payload.

---

## Step 3 — Read `fs:[0x30]` exactly as shellcode would

In shellcode, the TEB is accessed via the FS segment without knowing the TEB
address:

```asm
mov eax, fs:[0x30]   ; EAX = PEB address
```

In WinDbg, the equivalent:

```
0:000> dd fs:[30] L1
```

The single DWORD at that address is the PEB pointer. Write it down. Call it
`PEB_ADDR`.

Cross-check:

```
0:000> r $peb
```

Both should match.

---

## Step 4 — The SEH chain lives in the TEB

At `TEB+0x00` is `ExceptionList`, a pointer to the first node in the
Structured Exception Handling (SEH) chain. This is important for OSED's SEH
exploitation module — the chain is not stored on the stack, it is stored in
the TEB. The stack just holds the chain nodes.

Verify:

```
0:000> dd poi(TEB_ADDR) L2
```

The first DWORD of the first SEH record is the `Next` pointer (next record or
`0xFFFFFFFF` = end of chain). The second DWORD is the handler pointer.

Run the osed-windbg SEH walker as a cross-check:

```
0:000> dx @$osed().seh()
```

The output should list the same chain you are reading manually.

---

## Step 5 — `StackBase` and `StackLimit`

```
0:000> dd TEB_ADDR+4 L2
```

- `[TEB+0x04]` = StackBase (highest stack address, where it started)
- `[TEB+0x08]` = StackLimit (current committed bottom)

Compare to `esp`:

```
0:000> ? StackBase - esp        ; how much stack space has been used
0:000> ? esp - StackLimit       ; how much stack space remains committed
```

In a heavily recursive program or with a small stack, the difference
`esp - StackLimit` approaches zero. Windows extends the stack on demand
by committing more pages from the reserved region.

---

## Checkpoint

Answer in your notes (no debugger allowed):

1. What CPU instruction does x86 shellcode use to reach the TEB?
2. At what TEB offset is the PEB pointer? (Decimal and hex.)
3. What is `fs:[0x18]` and why is it useful?
4. Where is the SEH chain head pointer stored — the stack or the TEB?
5. What is the TEB field that tells you the absolute top of the current
   thread's stack?

---

## Offset cheat sheet (x86 TEB)

```
fs:[0x00]   ExceptionList (SEH chain head)
fs:[0x04]   StackBase
fs:[0x08]   StackLimit
fs:[0x18]   Self (pointer to TEB)
fs:[0x30]   ProcessEnvironmentBlock (PEB pointer)
```

Keep this. You will type `fs:[30]` many times before this series is done.
