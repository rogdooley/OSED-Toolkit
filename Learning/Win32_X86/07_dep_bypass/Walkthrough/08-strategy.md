## 8. Strategy: the fake frame and the plan

Our goal: call **`VirtualProtect`** to turn the stack page holding our shellcode
from `RW` to `RWX`, then return into the shellcode.

### 8.1 Why VirtualProtect first

> **Design decision — API choice.** The student's mental model of DEP is "this
> page is data; make it code." `VirtualProtect` maps onto that one-to-one:
>
> ```
> shellcode is on the stack  →  stack is RW  →  make it RWX  →  VirtualProtect
> ```
>
> `VirtualAlloc` (Chapter 12) and `WriteProcessMemory` (Chapter 13) reach the
> same end by other means, and both work against this binary (compression.dll
> imports VA and VP). We lead with VirtualProtect because its semantics are the
> most direct expression of the mitigation we are defeating — and because it
> gives a gorgeous debugging checkpoint: `!vprot` shows `PAGE_READWRITE` before
> and `PAGE_EXECUTE_READWRITE` after. You can literally watch DEP fall.

### 8.2 The prototype and the fake frame

```c
BOOL VirtualProtect(
    LPVOID lpAddress,      // page holding shellcode
    SIZE_T dwSize,         // 0x201 is plenty (< one page); any 1..0x1000 works per page
    DWORD  flNewProtect,   // PAGE_EXECUTE_READWRITE = 0x40
    PDWORD lpflOldProtect  // pointer to a WRITABLE dword (receives old protection)
);
```

When you *return into* a function via ROP, the dword at ESP is taken as the
return address and the following dwords as arguments. So you lay a **fake frame**
on the stack:

```
[ &VirtualProtect ]   ← ESP points here when we "return" into VP
[ return address  ]   ← where VP returns → our shellcode
[ lpAddress       ]   ← shellcode address (== return address)
[ dwSize          ]   ← 0x201
[ flNewProtect    ]   ← 0x40
[ lpflOldProtect  ]   ← a writable scratch dword
```

Everything you don't know at build time (VP's runtime address, the shellcode's
stack address) and everything containing bad chars (`0x40`, `0x201`, small
sizes) gets shipped as a **placeholder** and patched in place by ROP.

### 8.3 The one gotcha VirtualAlloc doesn't have

`lpflOldProtect` is an `_Out_` pointer: VP **writes** the previous protection
there. Pass junk and VP faults on the write. It must point at a valid, writable
dword you don't care about. This spawns a small ROP sub-goal — "produce a
writable scratch pointer" — which is good practice.

### 8.4 The plan, organized by primitive

We will build the chain as a sequence of named primitives, not a flat list:

```
P0  Acquire a stack pointer          (copy ESP → working register)
P1  Resolve VirtualProtect from IAT  (deref the fixed IAT slot)
P2  Store API address into frame
P3  Store return address (= shellcode)
P4  Store lpAddress      (= shellcode)
P5  Store dwSize         (0x201)
P6  Store flNewProtect   (0x40)
P7  Store lpflOldProtect (writable scratch)
P8  Pivot ESP onto the fake frame and fire
```

Each primitive below follows the same ritual: state the problem, search rp++,
list candidates, reject the bad ones with a reason, choose, verify, and show the
stack changing. Let's build.

---

---

[← Previous](07-proving-dep.md) · [Index](00-index.md) · [Next →](09-building-the-chain.md)
