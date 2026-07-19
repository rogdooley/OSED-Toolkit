# 20. API Hashing

## Why Hash?

Comparing full API name strings requires embedding those strings in the
shellcode (space-expensive) or finding them at runtime. Hashing reduces each
API name to a 32-bit constant:

1. Compute a hash of each exported name during the PEB/PE walk
2. Compare the hash against a known target constant
3. When matched, use the corresponding function address

## Common Hash Algorithm: ROR-13-ADD

```asm
compute_hash:
    xor edx, edx          ; hash = 0
    xor ecx, ecx
hash_loop:
    mov cl, [esi]          ; load next byte of function name
    test cl, cl
    jz hash_done           ; stop at null terminator
    ror edx, 0x0D          ; rotate right by 13
    add edx, ecx           ; add character
    inc esi
    jmp hash_loop
hash_done:
    ; EDX = computed hash
```

The rotation constant (13) is arbitrary but widely used. Different shellcode
projects use different constants.

## Case Sensitivity

Export names are case-sensitive. If the hash algorithm does not normalize case,
the target constant must match the exact casing in the export table. Some
implementations convert to uppercase before hashing to handle inconsistencies.

## Collision Handling

Hash collisions are possible -- two different function names producing the same
32-bit hash. In practice, collisions within a single module's export table are
rare with a good rotation constant. If collisions are a concern, use a wider
hash or add the module name to the hash computation.

## Module + Function Hashing

Some implementations hash the module name (e.g., "kernel32.dll") and the
function name separately, then combine them (add, xor, or concatenate) to
produce a single lookup key. This avoids matching the wrong function in the
wrong module.

## Finding Hash Constants

To use a hash-based resolver, you need the precomputed hash for each target
API. Compute it offline:

```python
def ror13_hash(name: bytes) -> int:
    h = 0
    for b in name:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
    return h

print(hex(ror13_hash(b"WinExec")))         # example
print(hex(ror13_hash(b"ExitProcess")))      # example
```
