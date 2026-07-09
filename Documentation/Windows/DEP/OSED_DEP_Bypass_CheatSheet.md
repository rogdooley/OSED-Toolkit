# DEP Bypass — One-Page Cheat-Sheet (x86)

## Workflow (in order — skipping is how exploits die)
1. **Recon:** `.load narly` → `!nmod` → note DEP / ASLR / SafeSEH. Confirm DEP empirically (NOP-on-stack), not from header.
2. **Offsets:** EIP offset; where does ESP point at crash? (padding needed?)
3. **Bad chars:** byte-array through the vuln. FastBack set: `00 09 0A 0B 0C 0D 20`.
4. **Pick gadget module:** app-shipped + non-ASLR + address bytes bad-char-free. Reject main EXE if base has `0x00`.
5. **Gadgets:** `rp-win-x86.exe -f <mod> -r 5 > rop.txt` → anchored `findstr`.
6. **Lay call skeleton** with placeholders → **build chain** → **pivot ESP** → **fire** → **land shellcode**.

## API targets (pick one)
| API | Effect | Args to fake |
|---|---|---|
| **VirtualAlloc** (MEM_COMMIT on committed page) | RW → RWX | lpAddress, dwSize=1, MEM_COMMIT=0x1000, PAGE_EXECUTE_READWRITE=0x40 |
| **VirtualProtect** | RW → RWX in place | lpAddress, dwSize, flNewProtect=0x40, **lpflOldProtect (writable ptr!)** |
| **WriteProcessMemory** | copy shellcode into existing `.text` | hProcess=-1, lpBaseAddress(exec), lpBuffer(src), nSize, *lpNumberOfBytesWritten |

## Null-avoidance tricks (the recurring headache)
| Need | Trick |
|---|---|
| Subtract small `+n` (nulls) | Add negative: `-0x1C = 0xFFFFFFE4` → `pop ecx / add eax,ecx` |
| Value `0x01` | `pop eax=0xFFFFFFFF ; neg eax` |
| `0x1000` | `0x80808080 + 0x7F7F8F80` |
| `0x40` | `0x80808080 + 0x7F7F7FC0` |
| `ADD ESI,4` missing | `inc esi` ×4 (side-effects on junk reg OK) |
| Bad byte in an address/IAT | ship `addr±1`, correct with `add`/`sub` |
| Verify math | WinDbg `? 0 - 1000`, `? -0x1c` |

## Reusable gadget patterns
```
push esp ; ... ; pop <reg> ; ret        ; copy live ESP into a working reg
mov eax, esi ; pop esi ; ret            ; ESI -> EAX (compute in EAX/ECX, cheaper)
push eax ; pop esi ; ret                ; write result back to ESI
pop eax / pop ecx ; ret                 ; load constants
add eax,ecx / sub eax,ecx / neg eax     ; arithmetic (null-free constants)
mov eax, dword [eax] ; ret              ; deref IAT slot -> real API addr
mov dword [esi], eax ; ret              ; THE store primitive (1 per skeleton field)
xchg eax,ebp ; ret + mov esp,ebp ; pop ebp ; ret  ; stack pivot onto fake frame
```

## The core rhythm (repeat once per skeleton field)
> **align ESI to slot** (`inc esi` ×4) → **compute value into EAX** (tricks above) → **`mov [esi], eax`**

## Stack pivot gotcha
`mov esp,ebp ; pop ebp ; ret` **pops one DWORD** → aim EBP **4 bytes before** the API slot so the stray pop eats a dummy and ESP lands exactly on the API address.

## Shellcode landing
- Measure space: `dd eip L40` after API returns. Too small? **grow the buffer** (`0x400→0x600`).
- `msfvenom ... -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python` — **always** pass `-b`.
- Staged payloads (shikata) are big (~544B) — budget room. Dummy `\xcc` first to validate alignment.

## WinDbg quick-ref
```
!nmod                       mitigations (PE header only)
!vprot <addr>               page protection (watch RW->RWX)
dds <addr> Ln / dd Ln       stack dump (with / without symbols)
? <expr>                    evaluate (negatives, split-add)
u <addr> Ln                 disasm (confirm mid-opcode gadgets)
ed esp 90909090 ; r eip=esp prove DEP on the stack
bp <a> ".if @eax=0x40 {} .else {gc}"   conditional bp for reused gadgets
pt / p / g                  step-to-ret / step / go
```

## Time budget
**Spend on:** mitigation recon, bad-char set, module choice, rp++ search fluency, the four tricks + the store rhythm, conditional breakpoints.
**Don't waste on:** "perfect" gadgets (improvise), production pykd finders (rp++ instead), 100% ROP payloads, `NtSetInformationProcess` disable (dead vs Permanent DEP), pre-computing runtime addresses, exotic space-saving (grow the buffer).
