# DEP-2 and ASLR DEP-2 Staged ROP Design

## Purpose

Add two advanced, local-only Windows x86 profiles to `osed_vuln_lab` without
changing its network protocol:

- `dep2`: fixed-base, DEP-enabled staged ROP and stack-pivot exercise.
- `aslr_dep2`: the same exercise with a randomized helper and an existing
  disclosure-driven base calculation.

The existing `dep` profile remains the introductory DEP lab. It intentionally
permits a conventional `VirtualProtect` call frame; these profiles exist
because that path does not require meaningful ROP construction when input
bytes are unrestricted.

## Constraints

- Keep the existing `OP_ROP` opcode and version-2 request body unchanged.
- Receive and validate the entire request before exploit-relevant work begins.
- Do not add synthetic bad-character filtering.
- Keep the target readable in offline IDA Free: visible imports, calls, data
  references, validation branches, copy operations, and gadget code.
- Do not disclose the staging address through the protocol, an exported getter,
  a returned helper value, or a deliberately preserved register value.
- Keep proof behavior benign and confined to the local training VM.
- Keep instructor solutions, tests, manifests, and debugger scripts out of the
  generated `student_bundle`.

## Selected Architecture

### Profile matrix

| Profile | Service ASLR | Helper ASLR | DEP | Leak | ROP target |
|---|---|---|---|---|---|
| `dep` | off | off | on | no | introductory direct-frame DEP exercise |
| `dep2` | off | off, fixed | on | no | staged chain and required pivot |
| `aslr_dep` | on | on | on | yes | leak-assisted introductory DEP exercise |
| `aslr_dep2` | on | on | on | yes | leak-assisted staged chain and required pivot |

`dep2` and `aslr_dep2` accept `OP_ROP` using the current version-2 record.
There is no new opcode, header, record, or network round trip.

### Runtime preparation

The helper owns three private static objects in writable image memory:

1. An `OSED_STAGE_BYTES` (8192-byte) staging buffer. It receives an exact copy
   of the complete validated ROP data region.
2. A cached `VirtualProtect` function pointer.
3. A proof-status DWORD used only as a deterministic, local execution witness.

During normal service startup, a readable helper initialization routine resolves
`VirtualProtect` with standard Windows loader APIs and stores it in the private
pointer slot. Startup fails if that preparation fails. The vulnerable command
therefore never observes an uninitialized API-pointer slot.

The helper does not import `VirtualProtect` directly and does not export a
callable memory-protection wrapper. It may import the standard loader APIs
needed to resolve the cached pointer. The resolution code and the references to
the private slot are intentionally visible in the helper DLL.

After the existing version-2 parser accepts a request, its record data and
record length are the ROP data region. The helper stages that entire region;
the packet header and version-2 descriptor are not restaged. Before each copy,
the stage routine clears the full buffer and the proof-status DWORD. Static
image storage, rather than initialization style, gives the buffer a stable RVA
for a particular build; it must not be heap allocated.

### Data flow

```text
TCP request -> existing packet validation -> existing v2 record validation
    -> helper stage-copy routine copies the full body into private storage
    -> handler copies only the calibrated first-stage prefix into that buffer
    -> saved EIP executes the short pivot sequence
    -> ESP moves into the staged second-chain area
    -> staged ROP resolves the cached pointer and performs VirtualProtect
    -> return target reaches benign proof bytes in staged storage
```

The stage-copy routine returns status, not a staging pointer. The service must
not intentionally leave the staging base in a general-purpose register at the
overflow return point. The Windows integration test records the register state
at that point to catch an accidental compiler-created shortcut.

### Staging and proof regions

The private static staging buffer has three conceptual
regions in a learner request:

| Region | Address expression | Purpose | Required protection before proof |
|---|---|---|---|
| First-stage mirror | `stage_base + 0` | Copy of the full body, including its initial prefix | writable, non-executable |
| Second-stage chain | `stage_base + stage2_offset` | ROP stack read by `ret` and `pushad` | writable, non-executable |
| Proof bytes | immediately after the serialized second-stage chain | Benign bytes reached only after the protection change | executable after `VirtualProtect` |

`stage2_offset` is chosen by the instructor solution within the staged body;
the service does not parse or advertise it. The second-stage `lpAddress` and
size must cover the proof-byte region. Windows page rounding may also mark part
of the preceding chain storage executable; this does not alter the intended
control flow.

For `dep2`, the stage-buffer, cached-pointer, proof-status, and gadget
addresses are the fixed helper base plus their discovered RVAs. For
`aslr_dep2`, the learner must derive that same helper base from the existing
leak, then add the corresponding independently recovered RVAs. No heap address
or additional disclosure is involved.

```text
stage_base        = helper_base + stage_rva
cached_pointer_va = helper_base + cached_pointer_rva
proof_status_va   = helper_base + proof_status_rva
```

### Structural first-stage constraint

The first-stage capacity is specified as three controlled DWORDs beginning at
saved EIP, or exactly two controlled DWORDs after saved EIP:

```text
saved EIP:       pop eax; ret
ESP + 0:         chosen staged-chain address
ESP + 4:         xchg eax, esp; ret
ESP + 8 onward:  caller-stack state, not attacker-controlled by this request
```

This permits the intended pivot but cannot fit a conventional `stdcall`
`VirtualProtect` frame, which requires a target, return address, and four
arguments after saved EIP. The implementation makes no claim about physically
zeroing caller-stack bytes beyond the local frame. Instead, it constrains the
request-controlled prefix to the three stated DWORDs; bytes after that boundary
must not originate from attacker input in the current request.

`DEP2_STAGE1_COPY_BYTES` is calibrated from the actual MSVC Win32 saved-EIP
offset: it equals the observed offset plus twelve bytes. The Windows integration
test is authoritative: it sends the calibrated prefix, verifies all three
controlled DWORDs, confirms distinct sentinels placed later in the request do
not appear after the boundary, and records the adjacent caller-stack state for
diagnosis. A compiler or flag change that shifts the frame makes that test fail
rather than silently weakening the exercise.

### Required staged ROP vocabulary

The new profiles retain the gadgets needed to:

- load registers;
- dereference the cached API-pointer slot;
- transfer the resolved value into the `PUSHAD` dispatch register;
- construct the size and protection values;
- select writable old-protection storage;
- use `pushad; ret` for the call-frame transition;
- return through `jmp esp` to the staged proof bytes; and
- pivot with `xchg eax, esp; ret`.

They deliberately omit direct indirect-transfer gadgets (`call eax; ret` and
`jmp eax`) and omit the callable memory-protection wrapper. The absence of an
import thunk for `VirtualProtect`, a direct wrapper, and direct-dispatch gadgets
removes the obvious conventional-frame shortcut while leaving the intended
PUSHAD path inspectable.

The instructor solution documents the x86 `PUSHAD` register-to-stack mapping,
the two-return trampoline, every gadget's precondition and side effect, the
cached-pointer dereference, and why the final return reaches the proof region.

### PUSHAD call-frame contract

Immediately before `pushad; ret`, the staged chain must establish:

| Register | Required value | Later use |
|---|---|---|
| `EDI` | address of a single `ret` | first `pushad` trampoline |
| `ESI` | dereferenced cached `VirtualProtect` pointer | second trampoline / API entry |
| `EBP` | `jmp esp` address | `VirtualProtect` return address |
| `EBX` | proof-region size | `dwSize` |
| `EDX` | executable page protection | `flNewProtect` |
| `ECX` | writable old-protection location | `lpflOldProtect` |
| `ESP` | first proof-byte address | `lpAddress` captured by `PUSHAD` |

`PUSHAD` saves `EAX`, `ECX`, `EDX`, `EBX`, original `ESP`, `EBP`, `ESI`, then
`EDI`. Because the stack grows downward, it leaves this layout at the new ESP:

```text
+0x00 EDI             -> ret pops this and transfers to EDI
+0x04 ESI             -> EDI's ret transfers to resolved VirtualProtect
+0x08 EBP             -> VirtualProtect return address (jmp esp)
+0x0c original ESP    -> lpAddress (first proof byte)
+0x10 EBX             -> dwSize
+0x14 EDX             -> flNewProtect
+0x18 ECX             -> lpflOldProtect
+0x1c EAX             -> unused filler
```

The instructor solution and integration test must validate this exact memory
layout at the selected dispatch sequence. Immediately before `PUSHAD`, the
integration test must assert that ESP equals the first proof-byte address, so
the captured original-ESP slot is the intended `lpAddress`. Merely loading the
API arguments into registers is not sufficient.

### Proof-status contract

The stage-copy routine clears the private proof-status DWORD before each
request. The instructor proof bytes execute from the newly executable proof
region and write a fixed success value to that status DWORD before returning.
The instruction sequence is local, deterministic, and benign. Its absolute
status address is derived from the same helper base plus RVA calculation used
for the staging buffer; it is not provided through the network protocol.

## Acceptance criteria

| Requirement | Acceptance criterion |
|---|---|
| First-stage capacity | Runtime inspection shows exactly three controlled DWORDs beginning at saved EIP. |
| Post-EIP boundary | Bytes after the third controlled DWORD do not come from later request bytes; the debugger records their caller-stack state. |
| Staging address | The private static stage buffer is discoverable in helper code/data and equals helper base plus stage RVA. |
| Cached API pointer | It is nonzero before command processing and resolves through the readable startup path. |
| `PUSHAD` layout | The debugger validates the stated EDI/ESI/EBP/original-ESP/EBX/EDX/ECX layout at dispatch. |
| DEP enforcement | The proof page is non-executable before and has the requested executable protection after the successful `VirtualProtect` transition. |
| Successful proof | Staged proof bytes execute and change the private proof-status DWORD to the expected value. |
| ASLR behavior | `aslr_dep2` succeeds across fresh launches with different helper bases. |
| Student bundle | It excludes instructor solution code, test tooling, debugger automation, and generated address manifests. |

## Verification

### Static PE verification

Extend `verify_binaries.py` to:

- recognize `dep2` and `aslr_dep2` mitigation and helper-base expectations;
- require the staging-copy and runtime-preparation code markers;
- require the pivot, dereference, register-loading, `PUSHAD`, and post-call
  transfer primitives;
- reject the direct wrapper export and direct-dispatch exports;
- parse the PE import directory and reject a direct `VirtualProtect` import;
- require the private-stage and runtime-preparation implementation markers; and
- maintain the existing profile-isolation checks.

### Unit tests

Add instructor-only tests for:

- request layout compatibility with the unchanged `OP_ROP` framing;
- the intended three-DWORD first-stage layout beginning at saved EIP;
- second-stage serialization and proof-region placement;
- required and forbidden DEP-2 gadget sets; and
- address derivation for fixed-base and leak-derived ASLR cases.

### Windows integration verification

Add an instructor-only debugger-driven test, run after an MSVC Win32 build,
that:

- confirms the cached API pointer is nonzero before command processing;
- proves no staging pointer is conveniently available in a volatile register at
  the overflow return point;
- proves the first stage reaches the selected pivot gadget;
- proves the pivot sets ESP inside the designated second-stage region and that
  its immediate `ret` consumes the expected first second-stage DWORD;
- confirms the staged chain reaches `VirtualProtect` with the expected call
  frame, including the pre-`PUSHAD` ESP precondition;
- queries and verifies the protection of the page containing the proof region
  before and after the call;
- verifies proof execution occurs at an address within staged storage;
- verifies the proof-status DWORD changes only after successful staged proof
  execution;
- exercises malformed stage addresses, incorrect pivot setup, and an invalid
  `PUSHAD` frame as controlled failures; and
- for `aslr_dep2`, repeats across at least two fresh processes and asserts that
  helper bases differ while the leak-plus-RVA solution continues to work.

The test does not attempt to prove that no imaginable exploitation shortcut
exists. Its goal is to eliminate the obvious routes and reject regressions that
avoid the skills the exercise is intended to teach.

## Files and build impact

- `CMakeLists.txt`: add the two profiles, correct mitigation/linker settings,
  verification targets, and instructor-only test integration.
- `include/osedhelper.h`, `src/osedhelper.c`, `src/osedgadgets.c`: add private
  staging/runtime preparation and profile-specific gadget sets.
- `src/osed_vulnsvc.c`: add the calibrated stage-copy and short first-stage
  handler while preserving the current `OP_ROP` parser.
- `python/verify_binaries.py` and its tests: add import parsing and DEP-2
  profile assertions.
- `python/`: add instructor-only chain layout, solution-reasoning, and Windows
  runtime verification tools; do not include them in `student_bundle`.
- `instructor/`, `training_path.md`, `README.md`, and WinDbg material: explain
  the progression without placing solution values in student-facing files.

## Delivery order

1. Implement and verify `dep2` against an MSVC Win32 build, including the
   negative shortcut checks.
2. Derive `aslr_dep2` from the verified `dep2` implementation by enabling
   helper ASLR and reusing the existing leak path.
3. Verify randomized helper bases across fresh process launches.
4. Commit implementation and instructor material separately from unrelated
   repository work.

## Non-goals

- No protocol change or second network receive.
- No artificial bad-character restriction.
- No student-facing working exploit or target-specific address list.
- No persistent, stealthy, credential-focused, or destructive behavior.
