# 21. String Construction in Shellcode

## Pushing Strings Backward

Strings are built on the stack by pushing DWORDs in reverse order (last 4
characters first):

```asm
; Build "calc.exe\0" on the stack
xor eax, eax
push eax                   ; null terminator (4 zero bytes)
push 0x6578652E            ; ".exe" -> 2E 65 78 65
push 0x636C6163            ; "calc" -> 63 61 6C 63
mov ebx, esp               ; EBX -> "calc.exe\0"
```

Memory at ESP after these pushes:

```
ESP+0x00: 63 61 6C 63   "calc"
ESP+0x04: 2E 65 78 65   ".exe"
ESP+0x08: 00 00 00 00   "\0\0\0\0"
```

Read left to right, this is `calc.exe\0` followed by three padding zeros.

## How to Compute the DWORD Values

Take the target string, split into 4-byte chunks, reverse each chunk's byte
order for little-endian:

```
String: "calc"
ASCII:   63 61 6C 63
DWORD (little-endian): 0x636C6163

String: ".exe"
ASCII:   2E 65 78 65
DWORD (little-endian): 0x6578652E
```

## Handling Odd Lengths

If the string length is not a multiple of 4, pad the last chunk. If the
padding bytes would be zero and zeros are bad characters, use a register
write instead:

```asm
; "cmd\0" = 63 6D 64 00  -> problem: contains 0x00
; Solutions:
; 1. Push as part of the null terminator push (if aligned)
; 2. Use XOR encoding
; 3. Write the last byte separately:
push 0x00646D63           ; only works if 0x00 is not a bad char
; Or:
push 0x01646D63           ; push with dummy byte
mov byte ptr [esp+3], 0   ; zero out the dummy (but 0x00 in the instruction!)
; Or use xor:
xor eax, eax
mov [esp+3], al           ; AL = 0 from xor, instruction encodes without literal 0x00
```

## Avoiding Bad Characters in Strings

If any byte of the string is a bad character, XOR-encode the string and decode
at runtime:

```asm
push 0x6578652E ^ 0x41414141   ; XOR-encoded ".exe"
xor dword ptr [esp], 0x41414141 ; decode in place
```

## Unicode (UTF-16LE) Strings

Windows API functions with `W` suffix expect UTF-16LE strings. Each ASCII
character becomes 2 bytes (character + 0x00):

```
"cmd" in UTF-16LE: 63 00 6D 00 64 00 00 00
```

This is impractical to push directly because of embedded null bytes. Use the
`A` (ANSI) versions of APIs when possible, or build the Unicode string
byte-by-byte.
