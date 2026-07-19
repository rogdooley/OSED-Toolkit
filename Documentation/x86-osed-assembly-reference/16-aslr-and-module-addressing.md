# 16. ASLR and Module Addressing

## Image Base and RVA

Every PE module has a **preferred image base** (e.g., 0x00400000 for
executables, 0x10000000 for DLLs). If loaded at that address, all pointers in
the binary work without modification.

A **Relative Virtual Address (RVA)** is an offset from the module's loaded base:

```
VA  = ModuleBase + RVA
RVA = VA - ModuleBase
```

If the module loads at a different base (relocation), the loader patches
absolute addresses using the relocation table.

## ASLR

Address Space Layout Randomization randomizes the base address of modules,
stack, and heap each time the process starts. With ASLR:

- Gadget addresses change every run
- Hardcoded addresses in exploits break
- Each module has an independent random base

## Fixed vs. Randomized Modules

Not all modules opt in to ASLR. Modules compiled without `/DYNAMICBASE` in
their PE header load at their preferred base every time. These are the modules
from which ROP gadgets can reliably be taken.

Check in WinDbg:

```
0:000> !nmod                       (with narly extension)
0:000> lm m modulename             (check base address)
```

## Exploiting Non-ASLR Modules

1. Identify a module loaded at a fixed base (application-shipped DLLs are
   common candidates)
2. Verify its base address is consistent across runs
3. Extract gadgets using the fixed RVAs
4. Compute gadget VAs: `gadget_VA = fixed_base + gadget_RVA`

## Partial Pointer Overwrites

If only the low 2 bytes of a return address can be overwritten, ASLR does not
protect the full address -- the low 16 bits of a module's base are often
predictable (e.g., page-aligned). This narrows the entropy enough for a
probabilistic attack.

## Information Leaks

If the application leaks a pointer (via format string, error message, or
protocol response), the attacker can compute the module base at runtime:

```
leaked_VA = base + known_RVA
base = leaked_VA - known_RVA
```

With the base known, all RVAs resolve to correct VAs despite ASLR.
