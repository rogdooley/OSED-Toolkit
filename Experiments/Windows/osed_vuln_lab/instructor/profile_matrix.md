# Profile Architecture and Verification

This is instructor material. It records why each build exists and the binary
properties that must survive compilation.

## Architecture Audit

The service uses one fixed-size outer packet receiver and a profile-specific
command dispatcher. The command body grammar evolves cumulatively: easy uses
raw data, SEH adds a simple record, and DEP/ASLR share an offset-based record.
Earlier vulnerable handlers copy validated record data into smaller local
stack buffers. DEP v3 instead models an event-routing application and must be
evaluated from its compiled behavior. `osedhelper.dll` is loaded through
`event_runtime_check_compatibility` and supplies the application support APIs
or legacy training primitives appropriate to the selected profile.

Before profile isolation, every service handler and every helper primitive was
present in every build. The helper did not guarantee any useful instruction
sequence, and the ROP metadata shape did not load in `Tools.rop`. Those gaps
made easy unreliable and risked unintended shortcuts between later stages.

| Profile | Service ASLR | Service DEP | Helper ASLR | Helper DEP | Helper SafeSEH | Body grammar | Intended technique | Included primitives |
|---|---|---|---|---|---|---|---|---|
| `easy` | off | off | off, fixed | off | off | raw version 1 | saved RET overwrite | `jmp esp`, `call esp`, `push esp; ret` |
| `seh` | off | off | off, fixed | off | off | version 1 structured record | nSEH/SEH overwrite | one `pop; pop; ret` |
| `dep` | off | on | off, fixed | on | off | version 2 offset record | PUSHAD VirtualProtect ROP | register loads, arithmetic, writable slot, callable wrapper, dispatch and pivot sequences |
| `aslr_dep` | on | on | on | on | off | version 2 request and binary result | leak, base recovery, RVA-based ROP | same ROP vocabulary as `dep`, but no fixed application address |
| `dep2` | off | on | off, fixed | on | off | version 2 offset record | staged DEP bypass | constrained initial control, helper staging, cached API pointer, and pivot primitives |
| `aslr_dep2` | on | on | on | on | off | version 2 request and binary result | disclosure plus staged DEP bypass | same staged model as `dep2`, with helper-relative addresses derived at runtime |
| `dep3` | off | on | off, fixed | on | off | version 2 routed-event record | compiled-binary feasibility assessment | ordinary event-runtime APIs and naturally emitted code only |

The non-ASLR helper uses preferred base `0x62500000` with `/FIXED`; the ASLR
helper retains relocations and uses `/DYNAMICBASE`. The service compiler uses
`/Od /Ob0 /Oi- /Oy-` to preserve beginner-readable functions and vulnerable
copy calls. Legacy gadget survival does not depend on those settings: the
applicable profiles compile selected x86 MSVC naked functions from
`src/osedgadgets.c`. Those functions are not public DLL APIs, and DEP v3 does
not compile them.

## Profile Contents

- `easy`: packet receiver, ping, classic stack handler, constrained small-buffer
  handler, and direct stack-transfer helper code.
- `seh`: packet receiver, ping, structured record parser, deterministic
  exception handler, and only the pop-pop-ret helper sequence.
- `dep`: packet receiver, ping, version-2 record parser, DEP overflow handler,
  stable ROP code, writable storage, and callable VirtualProtect wrapper.
- `aslr_dep`: the DEP request grammar plus a framed binary helper-pointer
  result; the helper ROP code is randomized with the rest of the DLL.
- `dep2`: the version-2 request grammar, a constrained initial overwrite, and
  helper-managed staged data used by the legacy pivot exercise.
- `aslr_dep2`: the DEP-2 model plus a disclosure used to derive live
  helper-relative addresses.
- `dep3`: routed-event processing, normal request timestamp logging, and
  application-oriented helper APIs. It contains no dedicated staging region,
  cached protection API, protection wrapper, or synthetic gadget bank.

## Automated Binary Check

When Python 3 is available, the default MSVC build runs `verify_lab` before the
student bundle is copied. It parses the final PE files and fails the build for:

- wrong architecture, ASLR, or DEP flags
- unexpected helper base or relocation state
- a SafeSEH table in the SEH helper
- missing, altered, or out-of-profile legacy instruction sequences
- unexpected public training exports or exploit-oriented symbol names
- missing or unexpected protection-related imports for the selected profile
- service markers indicating an out-of-profile handler was compiled
- DEP v3 mitigation drift, artificial DEP-bypass infrastructure, or missing
  request-logging functionality

Run it explicitly with:

```bat
cmake --build build_easy --config Release --target verify_lab
```

The verifier reports profile properties and instruction-sequence counts without
printing useful addresses. Build-specific addresses must be discovered and
validated by the learner.

## Remaining Verification

The source and CMake graph can be checked on non-Windows hosts, but final PE
flags, instruction bytes, offsets, runtime module bases, exception behavior,
and DEP-bypass feasibility must be confirmed by an MSVC Win32 Release build. A
successful `verify_lab` run provides static evidence; WinDbg supplies runtime
evidence. For DEP v3, record the toolset, configuration, linker flags, and
binary hashes used for that assessment.
