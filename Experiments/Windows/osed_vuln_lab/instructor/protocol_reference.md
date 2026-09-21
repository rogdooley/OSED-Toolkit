# Instructor Protocol Reference

This file contains solution material. Do not include it in the student bundle.
The clients under `python/` are instructor validation and post-exercise tools;
they are not starting scripts for the binary-reversing exercise.

## Packet Format

All integer fields are little endian.

| Offset | Type | Meaning |
|---:|---|---|
| 0 | `uint32` | magic `0x4F534544` (`OSED`) |
| 4 | `uint16` | opcode |
| 6 | `uint16` | control/version flags |
| 8 | `uint32` | body length |
| 12 | bytes | body |

The declared body length must not exceed 8192 bytes. The outer envelope remains
stable across profiles; later profiles evolve the body parser instead of
introducing an unrelated protocol.

## Control Values and Bodies

| Control | Profiles/commands | Body |
|---:|---|---|
| `0x0000` | ping, easy stack commands | Raw command data (`OP_PING` requires zero length). |
| `0x0001` | SEH | One SEH record followed by its data. |
| `0x0201` | DEP/ASLR | One version-2 offset record and optional data. |

The SEH record is:

| Offset | Type | Meaning |
|---:|---|---|
| 0 | `uint16` | record type (`0x0002` for data) |
| 2 | `uint16` | name length |
| 4 | `uint32` | data length |
| 8 | bytes | optional name, then vulnerable-handler data |

Its data starts at `8 + name_length`, and `data_length` must account for the
remainder of the outer body.

The DEP/ASLR version-2 request record is:

| Offset | Type | Meaning |
|---:|---|---|
| 0 | `uint16` | kind (`0x0001` query or `0x0002` data) |
| 2 | `uint16` | options (must be zero) |
| 4 | `uint32` | data offset from the start of this record |
| 8 | `uint32` | data length |

`OP_ROP` requires a data record. `OP_LEAK` requires a query record with zero
data. This gives DEP and ASLR the same request grammar while making the ASLR
exercise add response parsing and pointer provenance.

The leak response uses the same outer header (`OP_LEAK`, control `0x0201`) and
an 8-byte result body: `uint16 status`, `uint16 kind`, and `uint32 value`.
Success is status zero, query kind, and a live pointer in `value`.

## Opcodes

| Value | Symbol | Profiles | Purpose |
|---:|---|---|---|
| `0x1000` | `OP_PING` | all | Neutral connectivity check; returns `PONG`. |
| `0x1001` | `OP_STACK` | easy | Classic stack-overflow path. |
| `0x1002` | `OP_SEH` | seh | SEH-overwrite training path. |
| `0x1003` | `OP_SMALLBUF` | easy | Constrained overflow for staged-payload practice. |
| `0x1004` | `OP_LEAK` | aslr_dep | Controlled helper-module pointer disclosure. |
| `0x1005` | `OP_ROP` | dep, aslr_dep | DEP-aware stack-overflow path. |

## Validation Clients

With the service running on `127.0.0.1:9999`:

```bat
python python\protocol_smoketest.py --host 127.0.0.1 --port 9999
python python\exploit_scaffold.py pattern --opcode stack --length 800
```

Expected smoke-test output is `PONG`. Use these clients to validate a build or
after the learner has independently recovered and documented the protocol.

The scaffold also supports offset calculation, bad-character generation, raw
payload files, and layouts made from learner-supplied return addresses and ROP
bytes. It applies the command-specific body wrapper and rejects requests whose
complete body exceeds the service limit.

## Deterministic Helper Primitives

`osedhelper.dll` contains an intentional x86 gadget bank so every profile is
solvable without relying on accidental compiler output. Exports use neutral
sequence names; learners should inspect and classify them in IDA.

| Export | Profiles | Sequence | Intended use |
|---|---|---|---|
| `helper_sequence_01` | easy, dep, aslr_dep | `jmp esp` | easy EIP redirect and post-API return |
| `helper_sequence_02` | dep, aslr_dep | `pop eax; ret` | register setup |
| `helper_sequence_03` | dep, aslr_dep | `pop ecx; ret` | register setup |
| `helper_sequence_04` | dep, aslr_dep | `pop edx; ret` | register setup |
| `helper_sequence_05` | dep, aslr_dep | `pop ebx; ret` | register setup |
| `helper_sequence_06` | dep, aslr_dep | `pop ebp; ret` | register setup |
| `helper_sequence_07` | dep, aslr_dep | `pop esi; ret` | register setup |
| `helper_sequence_08` | dep, aslr_dep | `pop edi; ret` | register setup |
| `helper_sequence_09` | dep, aslr_dep | `neg eax; ret` | null-free constant construction |
| `helper_sequence_10` | dep, aslr_dep | `xchg eax, ebx; ret` | PUSHAD chain setup |
| `helper_sequence_11` | dep, aslr_dep | `pushad; ret` | VirtualProtect call-frame dispatch |
| `helper_sequence_12` | dep, aslr_dep | `ret` | ROP NOP/trampoline |
| `helper_sequence_13` | seh | `pop eax; pop ebx; ret` | SEH redirect |
| `helper_sequence_14` | dep, aslr_dep | `xchg eax, esp; ret` | stack pivot |
| `helper_sequence_15` | dep, aslr_dep | `mov eax, [eax]; ret` | pointer dereference |
| `helper_sequence_16` | dep, aslr_dep | `xchg eax, esi; ret` | API target setup |
| `helper_sequence_17` | dep, aslr_dep | `mov [esi], eax; ret` | controlled write |
| `helper_sequence_18` | dep, aslr_dep | `add esp, 0x10; ret` | stack adjustment |
| `helper_sequence_19` | dep, aslr_dep | `call eax; ret` | indirect call |
| `helper_sequence_20` | dep, aslr_dep | `jmp eax` | indirect transfer |
| `helper_sequence_21` | easy | `call esp; ret` | alternate easy redirect |
| `helper_sequence_22` | easy | `push esp; ret` | alternate easy redirect |

`helper_writable_slot` supplies writable storage, while
`helper_memory_protect` guarantees a callable wrapper and a VirtualProtect
import. In non-ASLR profiles the DLL uses preferred base `0x62500000` with
relocation disabled. In `aslr_dep`, learners derive the live base and add the
same gadget RVAs.

The repository's `VirtualProtectChain` requires sequences 01-12 plus the
writable slot and callable protection target. Serialize that chain and append
the NOP sled and benign proof bytes directly; no shellcode pointer dword belongs
after `pushad; ret`.
