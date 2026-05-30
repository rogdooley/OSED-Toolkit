from capstone import CS_ARCH_X86, CS_MODE_32, Cs

with open("shell_reverse.bin", "rb") as f:
    code = f.read()

md = Cs(CS_ARCH_X86, CS_MODE_32)
instructions = list(md.disasm(code, 0))

print(f"File size:            {len(code)} bytes")
print(f"Instruction count:    {len(instructions)}")
print(f"Avg bytes/insn:       {len(code) / len(instructions):.2f}")
print()

for insn in instructions:
    print(
        f"0x{insn.address:04x}  {insn.bytes.hex():<16}  {insn.mnemonic:<8} {insn.op_str}"
    )
