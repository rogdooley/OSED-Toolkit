# Value Conversion Scripts

Small command-line helpers for shellcode-oriented byte conversion.

## Canonical tool

Use `string2hex.py` for string and IPv4 conversions:

```bash
# Installed entry point
value-convert string "calc.exe"
value-convert string --string-format wide "calc.exe"
value-convert string --file inputs.txt
value-convert string --arch x64 --chunk-size 8 --format push "ABCDEFGH"
value-convert ip 192.168.1.2

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

# Deprecated compatibility wrapper for IPv4
python3 Tools/Value_Conversion_Scripts/ip2hex.py 192.168.1.2
```

## Output modes

- `--format hex` prints only the little-endian values.
- `--format push` prints assembly-ready instructions.
- `--format both` prints both views.

## String formats

- `--string-format ascii` treats the input as normal bytes.
- `--string-format wide` encodes the input as UTF-16LE Windows wide strings.

Wide strings intentionally contain null bytes between ASCII characters. UTF-16LE represents each ASCII character as two bytes, so `calc.exe` becomes `63 00 61 00 6c 00 ...`. That is expected and often useful when building Windows `W`-API inputs.
