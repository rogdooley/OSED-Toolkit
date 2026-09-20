# Profile Architecture and Verification

This is instructor material. It records why each build exists and the binary
properties that must survive compilation.

## Architecture Audit

The service uses one fixed-size packet receiver and a profile-specific command
dispatcher. Vulnerable handlers copy an attacker-declared body length into a
smaller local stack buffer. `osedhelper.dll` is loaded through `helper_probe`
in every profile and supplies only the control-flow primitives appropriate to
that profile.

Before profile isolation, every service handler and every helper primitive was
present in every build. The helper did not guarantee any useful instruction
sequence, and the ROP metadata shape did not load in `Tools.rop`. Those gaps
made easy unreliable and risked unintended shortcuts between later stages.

| Profile | Service ASLR | Service DEP | Helper ASLR | Helper DEP | Helper SafeSEH | Intended technique | Included primitives |
|---|---|---|---|---|---|---|---|
| `easy` | off | off | off, fixed | off | off | saved RET overwrite | `jmp esp`, `call esp`, `push esp; ret` |
| `seh` | off | off | off, fixed | off | off | nSEH/SEH overwrite | one `pop; pop; ret` |
| `dep` | off | on | off, fixed | on | off | PUSHAD VirtualProtect ROP | register loads, arithmetic, writable slot, callable wrapper, dispatch and pivot sequences |
| `aslr_dep` | on | on | on | on | off | leak, base recovery, RVA-based ROP | same ROP vocabulary as `dep`, but no fixed application address |

The non-ASLR helper uses preferred base `0x62500000` with `/FIXED`; the ASLR
helper retains relocations and uses `/DYNAMICBASE`. The service compiler uses
`/Od /Ob0 /Oi- /Oy-` to preserve beginner-readable functions and vulnerable
copy calls. Gadget survival does not depend on those settings: each sequence is
an exported x86 MSVC naked function in `src/osedgadgets.c`.

## Profile Contents

- `easy`: packet receiver, ping, classic stack handler, constrained small-buffer
  handler, and direct stack-transfer helper exports.
- `seh`: packet receiver, ping, deterministic exception handler, and only the
  pop-pop-ret helper export.
- `dep`: packet receiver, ping, DEP overflow handler, stable ROP exports,
  writable storage, and callable VirtualProtect wrapper.
- `aslr_dep`: DEP handler plus controlled helper pointer leak; the helper ROP
  exports are randomized with the rest of the DLL.

## Automated Binary Check

When Python 3 is available, the default MSVC build runs `verify_lab` before the
student bundle is copied. It parses the final PE files and fails the build for:

- wrong architecture, ASLR, or DEP flags
- unexpected helper base or relocation state
- a SafeSEH table in the SEH helper
- missing, altered, or out-of-profile gadget exports
- missing VirtualProtect or vulnerable-copy imports
- service markers indicating an out-of-profile handler was compiled

Run it explicitly with:

```bat
cmake --build build_easy --config Release --target verify_lab
```

The verifier reports exact exported bytes. Addresses remain build-specific and
must still be discovered and validated by the learner.

## Remaining Verification

The source and CMake graph can be checked on non-Windows hosts, but final PE
flags, exported bytes, offsets, runtime module bases, exception behavior, and
the VirtualProtect call frame must be confirmed by an MSVC Win32 build. A
successful `verify_lab` run provides the static evidence; WinDbg supplies the
runtime evidence.
