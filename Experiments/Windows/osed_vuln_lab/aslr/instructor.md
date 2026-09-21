# Instructor Validation Notes

Keep exact values build-specific. Rebuilding can change RVAs and the overflow offset.

## ASLR-01

Require evidence from separate process launches. The invariant is the function RVA, not any virtual address.

## ASLR-02

`OP_LEAK` (`0x1004`) accepts an empty version-2 query record and returns a
framed binary result containing the live address of
`osedhelper!helper_get_anchor`. The student should recover the response fields
and prove the value's provenance with module mapping or `ln`.

## ASLR-03

Validate these relationships against the current DLL:

```text
anchor_rva = helper_get_anchor_va - helper_base
proof_rva  = helper_aslr_proof_va - helper_base
recovered_base = leak - anchor_rva
derived_proof  = recovered_base + proof_rva
```

Do not provide numeric RVAs. The exercise fails pedagogically if values are copied across builds.

## ASLR-04

The student's payload should contain build-specific padding followed by the little-endian derived proof VA. `helper_aslr_proof` prints the success marker and exits cleanly. This proves disclosure-assisted reuse of existing executable code; it is not yet a full ROP-based DEP bypass.

Classification: **A** for independent provenance, RVA arithmetic, and fresh-leak control; **B** after one targeted hint; **C** after receiving the opcode or equation; **D** if VA/RVA/base remain conflated.

## Next Exercise

After an A or B result, replace the single-function return with a small module-relative ROP chain and verify a benign `VirtualProtect` call frame. Revalidate every gadget RVA against the current DLL before using it.
