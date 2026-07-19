# 27. Fast-Reference Tables

## Register Summary

| Register | Size | Typical role | Caller/Callee saved |
|----------|------|-------------|---------------------|
| EAX | 32 | Return value, accumulator | Caller |
| EBX | 32 | General purpose, base | Callee |
| ECX | 32 | Counter, fastcall arg1, this | Caller |
| EDX | 32 | Data, mul/div high, fastcall arg2 | Caller |
| ESI | 32 | Source index, string ops | Callee |
| EDI | 32 | Dest index, string ops | Callee |
| ESP | 32 | Stack pointer | -- |
| EBP | 32 | Frame pointer (convention) | Callee |

## Flags Summary

| Flag | Bit | Meaning |
|------|-----|---------|
| CF | 0 | Carry / unsigned overflow |
| PF | 2 | Parity of low byte |
| ZF | 6 | Result is zero |
| SF | 7 | Result is negative (MSB set) |
| OF | 11 | Signed overflow |
| DF | 10 | String direction (0=fwd, 1=bwd) |

## Operand Sizes

| Qualifier | Size | Register examples |
|-----------|------|-------------------|
| BYTE PTR | 8 bit | AL, BL, CL, DL, AH, BH, CH, DH |
| WORD PTR | 16 bit | AX, BX, CX, DX, SI, DI, SP, BP |
| DWORD PTR | 32 bit | EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP |

## Conditional Jump Quick Reference

| Unsigned | Signed | Condition |
|----------|--------|-----------|
| JA | JG | > |
| JAE | JGE | >= |
| JB | JL | < |
| JBE | JLE | <= |
| JE | JE | == |
| JNE | JNE | != |

## Calling Conventions

| Convention | Args | Cleanup | First reg args | Suffix example |
|------------|------|---------|----------------|----------------|
| cdecl | R-to-L stack | Caller | None | `add esp, N` after call |
| stdcall | R-to-L stack | Callee | None | `ret N` |
| fastcall | R-to-L stack | Callee | ECX, EDX | `ret N` (N excludes reg args) |
| thiscall | R-to-L stack | Callee | ECX (this) | `ret N` |

## Stack Effects

| Instruction | ESP change |
|-------------|-----------|
| `push reg` | ESP -= 4 |
| `pop reg` | ESP += 4 |
| `call target` | ESP -= 4 |
| `ret` | ESP += 4 |
| `ret N` | ESP += 4 + N |
| `pushad` | ESP -= 32 |
| `popad` | ESP += 32 |
| `pushfd` | ESP -= 4 |
| `popfd` | ESP += 4 |
| `sub esp, N` | ESP -= N |
| `add esp, N` | ESP += N |
| `enter N, 0` | ESP -= (4 + N) |
| `leave` | ESP = EBP + 4 |

## Common Gadget Effects

| Gadget | Stack consumed | Registers changed |
|--------|---------------|-------------------|
| `pop eax; ret` | 8 | EAX |
| `pop eax; pop ecx; ret` | 12 | EAX, ECX |
| `xchg eax, esp; ret` | 4 (at new ESP) | EAX, ESP |
| `mov [edi], eax; ret` | 4 | memory at [EDI] |
| `add esp, 0x20; ret` | 0x24 | ESP |
| `pushad; ret` | -28 (net: push 32, pop 4) | ESP |
| `mov eax, [eax]; ret` | 4 | EAX |
| `neg eax; ret` | 4 | EAX, flags |
| `inc eax; ret` | 4 | EAX, flags |

## Page Protection Constants

| Constant | Value |
|----------|-------|
| PAGE_NOACCESS | 0x01 |
| PAGE_READONLY | 0x02 |
| PAGE_READWRITE | 0x04 |
| PAGE_EXECUTE | 0x10 |
| PAGE_EXECUTE_READ | 0x20 |
| PAGE_EXECUTE_READWRITE | 0x40 |
| PAGE_EXECUTE_WRITECOPY | 0x80 |

## Allocation Type Constants

| Constant | Value |
|----------|-------|
| MEM_COMMIT | 0x1000 |
| MEM_RESERVE | 0x2000 |
| MEM_COMMIT \| MEM_RESERVE | 0x3000 |

## PE Export Resolution Offsets

| Field | Location |
|-------|----------|
| e_lfanew | DllBase + 0x3C |
| Export Dir RVA | DllBase + e_lfanew + 0x78 |
| NumberOfNames | ExportDir + 0x18 |
| AddressOfFunctions | ExportDir + 0x1C |
| AddressOfNames | ExportDir + 0x20 |
| AddressOfNameOrdinals | ExportDir + 0x24 |

## PEB Walking Offsets

| Step | Offset |
|------|--------|
| TEB -> PEB | FS:[0x30] |
| PEB -> Ldr | PEB + 0x0C |
| Ldr -> InLoadOrderModuleList | Ldr + 0x0C |
| Ldr -> InMemoryOrderModuleList | Ldr + 0x14 |
| Ldr -> InInitializationOrderModuleList | Ldr + 0x1C |
| Entry -> DllBase | Entry + 0x18 |
| Entry -> BaseDllName | Entry + 0x2C |

## SEH Chain Offsets

| Field | Location |
|-------|----------|
| SEH chain head | FS:[0x00] |
| Next record | [record + 0x00] |
| Handler | [record + 0x04] |
| Chain terminator | Next = 0xFFFFFFFF |

## Common WinDbg Commands

| Command | Purpose |
|---------|---------|
| `r` | Show registers |
| `u <addr>` | Disassemble |
| `ub <addr>` | Disassemble backward |
| `uf <addr>` | Disassemble function |
| `dd <addr>` | Display DWORDs |
| `db <addr>` | Display bytes |
| `dc <addr>` | Bytes + ASCII |
| `da <addr>` | Display ASCII string |
| `du <addr>` | Display Unicode string |
| `dps <addr>` | Pointers with symbols |
| `dds <addr>` | DWORDs with symbols |
| `k` / `kb` / `kv` | Call stack |
| `lm` | List modules |
| `!address <addr>` | Memory region info |
| `!vprot <addr>` | Page protection |
| `!teb` | Thread environment block |
| `!peb` | Process environment block |
| `dt <type> <addr>` | Display structure |
| `.exr -1` | Last exception record |
| `.ecxr` | Exception context |
| `!analyze -v` | Verbose crash analysis |
| `bp <addr>` | Set breakpoint |
| `ba r4 <addr>` | Hardware read breakpoint |
| `ba w4 <addr>` | Hardware write breakpoint |
| `sxe av` | Break on access violation |
| `? <expr>` | Evaluate expression |

## Python Packing Formats

| Format | Type | Size | Endian |
|--------|------|------|--------|
| `<I` | uint32 | 4 | Little |
| `<i` | int32 | 4 | Little |
| `<H` | uint16 | 2 | Little |
| `<h` | int16 | 2 | Little |
| `<B` | uint8 | 1 | -- |
| `<b` | int8 | 1 | -- |
| `>I` | uint32 | 4 | Big |
