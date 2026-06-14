# Value Conversion Scripts

Small command-line helpers for shellcode-oriented byte conversion.

## Canonical tool

Use `string2hex.py` for string, IPv4, and `sockaddr_in` conversions:

```bash
# Installed entry point
value-convert string "calc.exe"
value-convert string --string-format wide "calc.exe"
value-convert string --file inputs.txt
value-convert string --arch x64 --chunk-size 8 --format push "ABCDEFGH"
value-convert ip 192.168.1.2
value-convert sockaddr --ip 192.168.1.2 --port 4444
value-convert sockaddr --current --port 4444
value-convert sockaddr --vpn --port 4444 --interface tun0

# ASCII strings
python3 Tools/Value_Conversion_Scripts/string2hex.py string "calc.exe"

# Multiple strings
python3 Tools/Value_Conversion_Scripts/string2hex.py string "WinExec" "ExitProcess"

# File input: one string per line, blank lines skipped
python3 Tools/Value_Conversion_Scripts/string2hex.py string --file inputs.txt

# Wide Windows strings (UTF-16LE)
python3 Tools/Value_Conversion_Scripts/string2hex.py string --string-format wide "calc.exe"

# x64-oriented output with 8-byte chunks
python3 Tools/Value_Conversion_Scripts/string2hex.py string --arch x64 --chunk-size 8 --format push "ABCDEFGH"

# IPv4 literals
python3 Tools/Value_Conversion_Scripts/string2hex.py ip 192.168.1.2

# sockaddr_in field values for IP + port
python3 Tools/Value_Conversion_Scripts/string2hex.py sockaddr --ip 192.168.1.2 --port 4444

# Use your current host IP
python3 Tools/Value_Conversion_Scripts/string2hex.py sockaddr --current --port 4444

# Try to pick a VPN-style interface IP
python3 Tools/Value_Conversion_Scripts/string2hex.py sockaddr --vpn --port 4444 --interface tun0

# Legacy positional form still works
python3 Tools/Value_Conversion_Scripts/string2hex.py sockaddr 192.168.1.2 4444

# Deprecated compatibility wrapper for IPv4
python3 Tools/Value_Conversion_Scripts/ip2hex.py 192.168.1.2
```

## Output modes

- `--format hex` prints only the little-endian values.
- `--format push` prints assembly-ready instructions.
- `--format both` prints both views.

## sockaddr_in

For `sockaddr_in`, the important fields are:

- `sin_family` is `AF_INET`, which is `0x0002`.
- `sin_port` is the TCP/UDP port number, and the immediate you load into `ax` is the byte-swapped form. For example, `9001` becomes `0x2923` for `mov ax, 0x2923`.
- `sin_addr` is the IPv4 address as a little-endian DWORD, so `192.168.1.2` becomes `0x0201a8c0`.
- `sin_zero` is eight zero bytes.

`--current` and `--vpn` are shortcuts:

- `--current` asks the system for the primary non-loopback IPv4 address.
- `--vpn` scans active interfaces and prefers names like `tun0`, `tap0`, `wg0`, or `ppp0`.
- `--interface IFACE` lets you force a specific adapter such as `tun0`.

## String formats

- `--string-format ascii` treats the input as normal bytes.
- `--string-format wide` encodes the input as UTF-16LE Windows wide strings.

Wide strings intentionally contain null bytes between ASCII characters. UTF-16LE represents each ASCII character as two bytes, so `calc.exe` becomes `63 00 61 00 6c 00 ...`. That is expected and often useful when building Windows `W`-API inputs.
