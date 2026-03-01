gdb -q ./call_demo

set disassembly-flavor intel
layout split

break main
run

disassemble /m main

break add1

info registers rip rsp
x/8gx $rsp

disassemble /m add1

CALL:
push next_instruction
jump to function

RET:
pop into RIP
