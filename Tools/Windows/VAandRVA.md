The core confusion is exactly one thing: **everything stored in the export directory is an RVA**. The base gets added once to produce a VA, and that VA is what you use from then on. Never add the base again.The short version of the rule:

**If you just read a raw dword from inside the PE image, it's an RVA — add base. Once you've added base, that address is a VA — use it directly for all subsequent WinDbg commands.**

The trap you hit is that `0x756f8678` looks like a VA because it has the high bits of `kernel32`'s load address in it, but that's coincidence — it's actually a small RVA (`0x00078678`) that you computed correctly. The mistake was treating the correct result as if it still needed the base.

One debugging check that helps: if the result of `base + rva` produces something outside the mapped range of `kernel32` (say, above `0x757xxxxx`), you double-added. `ead78678` is the tell — way outside the module's VA range.