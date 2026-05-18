start:
    jmp short callsite

resolver:
    pop esi
    int3

callsite:
    call resolver