### Building unconditional jumps without JMP

Goal:
    Always take a conditional jump

Methods:

1. Explicit flag setup
    xor ecx, ecx
    test ecx, ecx
    je short X

2. Implicit flag setup
    cmp eax, eax
    je short X

3. Arithmetic side-effect
    sub eax, eax
    je short X

4. Reuse known flags
    (if ZF already known)
    je short X

Key idea:
    Control flags → control execution