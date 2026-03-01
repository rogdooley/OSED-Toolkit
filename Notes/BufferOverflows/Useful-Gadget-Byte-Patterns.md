# Useful Gadget Byte Patterns (x86, x64, arm64)

This is a quick reference for common ROP/JOP gadget byte patterns during exploit development.

## Scope and caveats

- Bytes below are shown in memory order.
- `arm64` instructions are fixed 4-byte encodings (little-endian byte order shown).
- A matching byte sequence is not automatically a usable gadget; always verify disassembly, alignment, side effects, and badchars.

## x86 (32-bit)

| Purpose                | Bytes                  | Notes                        |
| ---------------------- | ---------------------- | ---------------------------- |
| `ret`                  | `C3`                   | Most common chain terminator |
| `ret imm16`            | `C2 ?? ??`             | Stack cleanup variant        |
| `leave ; ret`          | `C9 C3`                | Common epilogue pivot        |
| `pop eax ; ret`        | `58 C3`                | Load arg/value               |
| `pop ecx ; ret`        | `59 C3`                | Load arg/value               |
| `pop edx ; ret`        | `5A C3`                | Load arg/value               |
| `pop ebx ; ret`        | `5B C3`                | Load arg/value               |
| `pop esi ; ret`        | `5E C3`                | Load arg/value               |
| `pop edi ; ret`        | `5F C3`                | Load arg/value               |
| `jmp esp`              | `FF E4`                | Classic stack redirection    |
| `call esp`             | `FF D4`                | Alternate stack redirection  |
| `push esp ; ret`       | `54 C3`                | Control transfer to stack    |
| `xchg eax, esp ; ret`  | `94 C3`                | Stack pivot via `EAX`        |
| `add esp, imm8 ; ret`  | `83 C4 ?? C3`          | Small pivot/skip             |
| `add esp, imm32 ; ret` | `81 C4 ?? ?? ?? ?? C3` | Larger pivot/skip            |
| `int 0x80 ; ret`       | `CD 80 C3`             | Linux 32-bit syscall path    |

## x64 (AMD64)

| Purpose                | Bytes                     | Notes                        |
| ---------------------- | ------------------------- | ---------------------------- |
| `ret`                  | `C3`                      | Most common chain terminator |
| `ret imm16`            | `C2 ?? ??`                | Rare but useful in pivots    |
| `leave ; ret`          | `C9 C3`                   | Frame-based pivot            |
| `pop rax ; ret`        | `58 C3`                   | Load value                   |
| `pop rcx ; ret`        | `59 C3`                   | Windows arg 1                |
| `pop rdx ; ret`        | `5A C3`                   | Windows arg 2 / Linux arg 3  |
| `pop rbx ; ret`        | `5B C3`                   | Scratch                      |
| `pop rsi ; ret`        | `5E C3`                   | Linux arg 2                  |
| `pop rdi ; ret`        | `5F C3`                   | Linux arg 1                  |
| `pop r8 ; ret`         | `41 58 C3`                | Windows arg 3                |
| `pop r9 ; ret`         | `41 59 C3`                | Windows arg 4                |
| `jmp rsp`              | `FF E4`                   | Classic redirection in x64   |
| `call rsp`             | `FF D4`                   | Alternate redirection        |
| `push rsp ; ret`       | `54 C3`                   | Control transfer to stack    |
| `xchg rax, rsp ; ret`  | `48 94 C3`                | Strong stack pivot           |
| `add rsp, imm8 ; ret`  | `48 83 C4 ?? C3`          | Small pivot/skip             |
| `add rsp, imm32 ; ret` | `48 81 C4 ?? ?? ?? ?? C3` | Larger pivot/skip            |
| `syscall ; ret`        | `0F 05 C3`                | Linux x64 syscall path       |

## arm64 (AArch64)

| Purpose                    | Bytes                  | Notes                                           |
| -------------------------- | ---------------------- | ----------------------------------------------- |
| `ret`                      | `C0 03 5F D6`          | Returns to `X30`                                |
| `ret xN`                   | `?? ?? 5F D6`          | `ret xN` variants exist; disassemble to confirm |
| `br x0`                    | `00 00 1F D6`          | Indirect branch (JOP-style)                     |
| `br x16`                   | `00 02 1F D6`          | Common in PLT-style stubs                       |
| `blr x0`                   | `00 00 3F D6`          | Indirect call                                   |
| `nop`                      | `1F 20 03 D5`          | Filler/alignment                                |
| `svc #0`                   | `01 00 00 D4`          | Linux syscall trap                              |
| `mov sp, x29`              | `BF 03 00 91`          | Often appears in epilogues                      |
| `ldp x29, x30, [sp], #imm` | pattern: `FD 7B ?? A8` | Canonical epilogue pattern family               |

## Quick search strategy

- Start from control-transfer bytes first (`ret`, `jmp/call rsp`, `br`, `blr`), then validate full gadgets in a disassembler.
- Treat wildcard bytes (`??`) as immediate/register fields.
- Re-check for badchars after address selection.
- Prefer gadgets in non-ASLR or known-image modules when applicable to your target model.
