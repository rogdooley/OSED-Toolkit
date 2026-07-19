# 22. Format-String Assembly Concepts

## Variadic Arguments on x86

`printf`-family functions use cdecl with variadic arguments:

```asm
push arg3              ; 3rd format argument
push arg2              ; 2nd format argument
push arg1              ; 1st format argument
push offset fmt_string ; format string
call printf
add esp, 0x10          ; caller cleans up
```

The format string parser walks up the stack, consuming arguments based on
format specifiers. Each `%x`, `%s`, `%n`, etc. reads the next DWORD from the
stack.

## Format Specifiers

| Specifier | Action |
|-----------|--------|
| `%x` | Read DWORD from stack, print as hex |
| `%s` | Read DWORD from stack as pointer, print string at that address |
| `%n` | Read DWORD from stack as pointer, write character count to that address |
| `%hn` | Same as `%n` but writes only 16 bits (short) |
| `%hhn` | Same as `%n` but writes only 8 bits (char) |

## Why Format Strings Are Dangerous

If the format string itself is attacker-controlled:

```c
printf(user_input);    // vulnerable: user_input IS the format string
```

The attacker controls which specifiers are processed. `%x` reads stack values
(information disclosure). `%n` writes to memory (arbitrary write).

## Parameter Indexing

Direct parameter access allows targeting a specific stack argument:

```
%5$x     -- print the 5th argument as hex
%5$n     -- write character count to address pointed to by 5th argument
```

This avoids needing to pop through intervening arguments with dummy `%x`
specifiers.

## Write-What-Where with %n

`%n` writes the **number of characters printed so far** to the address pointed
to by the corresponding argument. By controlling the character count and the
target address:

1. Place the target address on the stack (often in the format string itself)
2. Use `%Nc` (print N characters of padding) to control the character count
3. Use `%n` (or `%hn` / `%hhn`) to write the count to the target address

## Partial Writes with %hn

Writing a full 32-bit value with `%n` requires printing billions of characters.
Instead, split the target value into two 16-bit halves and write each with
`%hn`:

```
Target value: 0xAABBCCDD
Write 0xCCDD to target_addr     using %hn  (after printing 0xCCDD chars)
Write 0xAABB to target_addr+2   using %hn  (after printing 0xAABB chars total)
```

The character count is cumulative across the entire printf call. To write the
second half, compute the additional padding needed:

```
second_padding = target_high - current_count  (mod 0x10000 if wraparound needed)
```

## %hhn for Byte-Granularity Writes

`%hhn` writes a single byte (the low 8 bits of the character count). Four
`%hhn` writes can construct any 32-bit value:

```
Write byte 0 to addr+0   (count mod 256 = target_byte_0)
Write byte 1 to addr+1   (count mod 256 = target_byte_1)
Write byte 2 to addr+2   (count mod 256 = target_byte_2)
Write byte 3 to addr+3   (count mod 256 = target_byte_3)
```

## Little-Endian Address Placement

When the format string itself contains target addresses (for `%n` to use as
pointers), those addresses are placed in the format string buffer in
little-endian byte order. The format string parser reads them as DWORDs from
the stack.
