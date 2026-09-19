# Staged Hints

Read only the next hint for the active exercise.

## ASLR-01

1. Use `lm m osedhelper` once the DLL is loaded.
2. `x osedhelper!*anchor*` gives a convenient function VA.
3. Subtract the module start from that VA for each run.

## ASLR-02

1. Start from response strings and their cross-references in IDA.
2. The protocol dispatch compares five opcode values.
3. The disclosure opcode is `0x1004`.

## ASLR-03

1. An RVA is relative to the loaded image base, not the start of `.text`.
2. Verify the leak with `ln <leaked_va>`.
3. A valid x86 image base should end in at least three hexadecimal zeroes.

## ASLR-04

1. Use `OP_ROP` with a cyclic pattern and inspect EIP at the access violation.
2. The scaffold's `trigger` mode accepts your discovered offset and derived target.
3. Set `bp <derived_proof_va>` before sending the final packet.
