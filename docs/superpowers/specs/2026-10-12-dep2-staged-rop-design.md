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

The helper owns two private static objects:

1. A writable staging allocation that receives an exact copy of the complete
   validated command body.
2. A cached `VirtualProtect` function pointer.

During normal service startup, a readable helper initialization routine resolves
`VirtualProtect` with standard Windows loader APIs and stores it in the private
pointer slot. Startup fails if that preparation fails. The vulnerable command
therefore never observes an uninitialized API-pointer slot.

The helper does not import `VirtualProtect` directly and does not export a
callable memory-protection wrapper. It may import the standard loader APIs
needed to resolve the cached pointer. The resolution code and the references to
the private slot are intentionally visible in the helper DLL.

### Data flow

```text
TCP request -> existing packet validation -> existing v2 record validation
    -> helper stage-copy routine copies the full body into private storage
    -> vulnerable handler zeroes its stack buffer
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

The private allocation has one physical backing store but three conceptual
regions in a learner request:

| Region | Address expression | Purpose | Required protection before proof |
|---|---|---|---|
| First-stage mirror | `stage_base + 0` | Copy of the short initial bytes; diagnostic context only | writable, non-executable |
| Second-stage chain | `stage_base + stage2_offset` | ROP stack read by `ret` and `pushad` | writable, non-executable |
| Proof bytes | immediately after the serialized second-stage chain | Benign bytes reached only after the protection change | executable after `VirtualProtect` |

`stage2_offset` is chosen by the instructor solution within the staged body;
the service does not parse or advertise it. The second-stage `lpAddress` and
size must cover the proof-byte region. Windows page rounding may also mark part
of the preceding chain storage executable; this does not alter the intended
control flow.

For `dep2`, all helper addresses are obtained from the fixed-base DLL. For
`aslr_dep2`, the learner must calculate `stage_base`, the cached-pointer slot,
and every gadget from the current helper base plus independently recovered
RVAs.

### Structural first-stage constraint

The initial controlled stack area is specified in **DWORDs after saved EIP**.
The build must provide exactly two controlled DWORDs after saved EIP:

```text
saved EIP:       pop eax; ret
ESP + 0:         chosen staged-chain address
ESP + 4:         xchg eax, esp; ret
ESP + 8 onward:  zeroed, uncontrolled tail
```

This permits the intended pivot but cannot fit a conventional `stdcall`
`VirtualProtect` frame, which requires a target, return address, and four
arguments after saved EIP. The handler must zero the stack buffer before its
limited copy so bytes beyond the controlled prefix cannot become an accidental
continuation.

`DEP2_STAGE1_COPY_BYTES` is calibrated from the actual MSVC Win32 saved-EIP
offset: it equals the observed offset plus eight bytes. The Windows integration
test is authoritative: it sends the calibrated prefix, verifies saved-EIP
control, and inspects the two controlled DWORDs and the zeroed tail at runtime.
A compiler or flag change that shifts the frame makes that test fail rather than
silently weakening the exercise.

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
- the intended two-DWORD pivot layout after saved EIP;
- second-stage serialization and proof-region placement;
- required and forbidden DEP-2 gadget sets; and
- address derivation for fixed-base and leak-derived ASLR cases.

### Windows integration verification

Add an instructor-only debugger-driven test, run after an MSVC Win32 build,
that:

- confirms the cached API pointer is nonzero before command processing;
- proves no staging pointer is conveniently available in a volatile register at
  the overflow return point;
- demonstrates the pivot changes ESP into the private staging allocation;
- confirms the staged chain reaches `VirtualProtect` with the expected call
  frame;
- verifies proof execution occurs at an address within staged storage;
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
