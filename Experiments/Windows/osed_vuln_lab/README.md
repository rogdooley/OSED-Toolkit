# OSED Vulnerable Service Lab - Authoring Guide (VM-Only)

This lab target is intentionally vulnerable and intended only for local Windows x86 VM training.

> **Instructor material:** this source tree contains protocol and vulnerability
> spoilers. Give learners only the generated `student_bundle` directory. The
> student brief makes protocol recovery in IDA Pro the first exercise.

## Components

- `osed_vulnsvc`: Win32 TCP service with opcode-based vulnerable handlers.
- `osedhelper.dll`: Harmless helper DLL with exported functions for module/gadget analysis.
- `student/`: spoiler-free brief and protocol-reversing worksheet.
- `instructor/protocol_reference.md`: protocol solution and build-validation commands.
- `python/exploit_scaffold.py`: instructor/post-discovery validation CLI.
- `python/protocol_smoketest.py`: instructor build smoke test.
- `gadgets/gadgets_template.json`: User-maintained gadget metadata template.
- `gadget_json_schema.md`: JSON format rules for module/gadget metadata.
- `training_path.md`: staged training sequence and expected outcomes.
- `aslr/README.md`: OSED-style leak, base recovery, and ASLR control-flow track.
- `python/aslr_scaffold.py`: transport and address-arithmetic scaffold with no target values.
- `CHANGELOG.md`: local change history for this lab target.
- `windbg_easy.txt`: WinDbg command workflow for the `easy` profile.
- `windbg_dep.txt`: WinDbg command workflow for the `dep` profile.
- `windbg_aslr_dep.txt`: WinDbg command workflow for the `aslr_dep` profile.
- `windbg_seh.txt`: WinDbg command workflow for the `seh` profile.

## Student Distribution

The student handout intentionally omits the packet format, command values,
payload limits, handler names, and protocol-aware scripts. See
`instructor/protocol_reference.md` only when validating or teaching the lab.

The target itself is not obfuscated or packed. MSVC optimization, inlining, and
frame-pointer omission are disabled so imports, receive boundaries, field
checks, dispatch logic, and vulnerable copies remain straightforward in IDA.

## Build (CMake + MSVC, x86)

Requirements:

- CMake 3.12 or newer
- An MSVC toolchain with x86 C/C++ build support

First verify the tools and source directory in `cmd.exe`:

```bat
where cmake
cmake --version
cmake --help
dir CMakeLists.txt
```

`cmake --version` must report 3.12 or newer, and `dir` must find the
`CMakeLists.txt` in the current directory. Use `dir`, not the Unix command
`ls`, in `cmd.exe`.

In the `cmake --help` output, the default generator is marked with `*`. CMake
must recognize a generator for an installed MSVC toolchain. If multiple
versions are installed, you may add `-G "<generator name from cmake --help>"`.
The generator name must match the local machine; it is intentionally not
hardcoded here.

These labs depend on the MSVC toolchain, not a specific Visual Studio IDE
release. MSVC-specific SEH syntax and mitigation linker flags are part of the
lab design.

The commands below assume CMake selected a Visual Studio generator, which
supports `-A Win32` and `--config Release`. If using Ninja or NMake instead,
open an **x86** MSVC tools prompt, omit `-A Win32`, configure with
`-DCMAKE_BUILD_TYPE=Release`, and build without `--config Release`.

A CMake build directory is tied to its original generator and architecture.
Use a new build directory after changing either one; do not reuse a directory
left by a failed configure with a different generator.

From the repository root, choose the command style matching the installed
CMake version. `-A Win32` produces 32-bit lab binaries on a 64-bit host.

### Modern CMake 3.13+

```bat
cd Experiments\Windows\osed_vuln_lab
cmake -A Win32 -S . -B build_easy -DLAB_PROFILE=easy -DHELPER_ASLR=OFF
cmake --build build_easy --config Release

cmake -A Win32 -S . -B build_dep -DLAB_PROFILE=dep -DHELPER_ASLR=OFF
cmake --build build_dep --config Release

cmake -A Win32 -S . -B build_aslr_dep -DLAB_PROFILE=aslr_dep -DHELPER_ASLR=ON
cmake --build build_aslr_dep --config Release

cmake -A Win32 -S . -B build_seh -DLAB_PROFILE=seh -DHELPER_ASLR=OFF
cmake --build build_seh --config Release
```

After building the desired profile, generate the student handout:

```bat
cmake --build build_easy --config Release --target student_bundle
```

For a different profile, replace `build_easy` with its build directory. Give
the learner only `build_easy\student_bundle` (or the corresponding profile
directory). It contains the EXE, required DLL, brief, and worksheet; it excludes
source, PDB files, headers, and protocol-aware Python clients.

### Legacy CMake 3.12

CMake 3.12 does not support `-S` and `-B`, so create and enter each build
directory explicitly:

```bat
cd Experiments\Windows\osed_vuln_lab
if not exist build_easy mkdir build_easy
pushd build_easy
cmake -A Win32 -DLAB_PROFILE=easy -DHELPER_ASLR=OFF ..
cmake --build . --config Release
popd

if not exist build_dep mkdir build_dep
pushd build_dep
cmake -A Win32 -DLAB_PROFILE=dep -DHELPER_ASLR=OFF ..
cmake --build . --config Release
popd

if not exist build_aslr_dep mkdir build_aslr_dep
pushd build_aslr_dep
cmake -A Win32 -DLAB_PROFILE=aslr_dep -DHELPER_ASLR=ON ..
cmake --build . --config Release
popd

if not exist build_seh mkdir build_seh
pushd build_seh
cmake -A Win32 -DLAB_PROFILE=seh -DHELPER_ASLR=OFF ..
cmake --build . --config Release
popd
```

## Mitigation Profiles

- `easy`: `/GS- /DYNAMICBASE:NO /NXCOMPAT:NO`
  - Goal: simplest memory corruption path with executable stack assumptions.
- `dep`: `/GS- /DYNAMICBASE:NO /NXCOMPAT`
  - Goal: DEP active, stable module base for ROP learning.
- `aslr_dep`: `/GS- /DYNAMICBASE /NXCOMPAT`
  - Goal: DEP + ASLR, practice info leak + dynamic chain construction.
- `seh`: `/GS- /SAFESEH:NO`
  - Goal: deterministic exception handling path for SEH overwrite exercises.
- `helper_no_aslr`: build with `-DHELPER_ASLR=OFF` (`/DYNAMICBASE:NO`).
- `helper_aslr`: build with `-DHELPER_ASLR=ON` (`/DYNAMICBASE`).

## Runtime

```bat
build_easy\Release\osed_vulnsvc.exe 9999
```

Use the matching build directory for the selected profile, such as
`build_aslr_dep\Release\osed_vulnsvc.exe 9999`. Keep `osedhelper.dll` in the
same `Release` directory as the executable.

Runtime output is intentionally sparse so the executable does not disclose the
dispatcher map or helper-module address before the learner recovers them.

## Instructor Validation

Protocol details and validation-client commands are isolated in
`instructor/protocol_reference.md`. Do not provide that file or `python/` to a
learner before protocol recovery is complete.

## Post-Discovery WinDbg Workflow

1. Recover and document the message envelope and dispatcher from the binary.
2. Write a minimal client from those findings and confirm a harmless command.
3. Locate the simplest vulnerable handler and send a cyclic pattern.
4. Calculate and verify the EIP or SEH overwrite offset.
5. Check bad characters directly in debugger memory.
6. Continue with module analysis and the selected mitigation profile.

Profile-specific WinDbg files:

- `windbg_easy.txt`
- `windbg_dep.txt`
- `windbg_aslr_dep.txt`
- `windbg_seh.txt`

## Training Sequence and Metadata Schema

- Follow staged progression in `training_path.md`.
- Use `gadget_json_schema.md` for exact key/field rules and validation expectations.

## Instructor Tool Notes

- No weaponized payloads are shipped.
- Payload bytes are user-supplied and should remain benign (`MessageBoxA`, `calc.exe`, proof file write).
- The protocol-aware clients are build-validation or post-discovery aids, not
  part of the student handout.

## Visual Studio Project Notes

The commands above generate the matching Visual Studio `.sln` and `.vcxproj`
files. The selected generator does not change the required Win32 target.
A manual Visual Studio folder is included for notes/templates only.
