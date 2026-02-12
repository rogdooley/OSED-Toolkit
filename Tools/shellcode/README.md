# Shellcode Utilities

This is a small helper module for early exploit-dev workflows:

- Parse bytes from common copy/paste formats (hex, `\\xNN`, C arrays, Python bytes literals)
- Analyze constraints (length, hashes, badchar presence)
- Reformat for Python/C exploit skeletons

## CLI

### Parse hex from stdin, analyze, and format as Python

```bash
echo "9090cc" | python -m Tools.shellcode.cli.sc_tool --in-format hex --out-format py
```

### Parse `\\xNN` string and format as C

```bash
echo "\\x90\\x90\\xcc" | python -m Tools.shellcode.cli.sc_tool --in-format escaped --out-format c --var sc
```

### Read raw bytes from a `.bin` file

```bash
python -m Tools.shellcode.cli.sc_tool --bin shellcode.bin --no-format
```

## Badchars

Defaults to checking `00,0a,0d`. Override with:

```bash
... --badchars 00,0a,0d,20
```
