## 13. Chapter 3 API: WriteProcessMemory (advanced)

WPM bypasses DEP by *obeying* it. Instead of making a data page executable, you
**copy your shellcode into memory that is already executable** — a code cave in a
non-ASLR module's `.text` — then jump there. No protection change at all.

```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,               // -1 (0xFFFFFFFF) = current process (null-free!)
    LPVOID  lpBaseAddress,          // an ALREADY-EXECUTABLE dest (code cave)
    LPCVOID lpBuffer,               // source: your shellcode on the stack
    SIZE_T  nSize,                  // bytes to copy
    SIZE_T *lpNumberOfBytesWritten  // writable scratch pointer (like VP's OldProtect)
);
```

New reasoning required, and why it's the advanced chapter:

- **`hProcess = -1`** — the pseudo-handle to self; conveniently `0xFFFFFFFF`, no
  bad bytes.
- **`lpBaseAddress`** — you must *find* a code cave: a run of unused executable
  bytes in a non-ASLR module (padding between functions, or a large `.text` gap).
  `compression.dll` at `0x61500000` is a fine host. Extra recon vs. VP/VA.
- **`lpBuffer`** — your shellcode's current stack address (same runtime
  resolution as before).
- **`lpNumberOfBytesWritten`** — another `_Out_` writable pointer (same trap as
  VP's fourth arg).
- **Control transfer is manual** — WPM does *not* jump to the cave for you. After
  it returns, you need one more gadget (`jmp`/`ret` into `lpBaseAddress`) to
  execute the freshly written code.

> **The lesson WPM teaches.** DEP is a *page-permission* mitigation, not a
> *shellcode* mitigation. If you put your bytes where execution is already
> allowed, there is nothing to bypass. That reframing — "don't fight the
> permission, satisfy it" — is worth more than the technique itself. Reserve WPM
> for when protection-flipping is blocked or a clean cave is handy; it has more
> moving parts than VP/VA and should not be your default.

---

---

[← Previous](12-virtualalloc.md) · [Index](00-index.md) · [Next →](14-aslr-outlook.md)
