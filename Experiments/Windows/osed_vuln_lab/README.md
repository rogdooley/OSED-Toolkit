# OSED Vulnerable Service Lab (VM-Only)

This lab target is intentionally vulnerable and intended only for local Windows x86 VM training.

## Components

- `osed_vulnsvc`: Win32 TCP service with opcode-based vulnerable handlers.
- `osedhelper.dll`: Harmless helper DLL with exported functions for module/gadget analysis.
- `python/exploit_scaffold.py`: CLI for patterns, offsets, bad characters, raw payloads, and student-supplied layouts.
- `python/protocol_smoketest.py`: Safe `OP_PING` connectivity test with no disclosure or crash.
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

## Protocol

Packet format (`little endian`):

- `uint32 magic` = `0x4F534544` (`OSED`)
- `uint16 opcode`
- `uint16 reserved` (unused)
- `uint32 length`
- `length` bytes payload

Opcodes:

- `0x1000 OP_PING`: neutral connectivity check that returns `PONG`.
- `0x1001 OP_STACK`: classic stack overflow path.
- `0x1002 OP_SEH`: SEH overwrite training path.
- `0x1003 OP_SMALLBUF`: constrained overflow for egghunter-style staging.
- `0x1004 OP_LEAK`: controlled pointer leak (`helper_get_anchor` pointer disclosure).
- `0x1005 OP_ROP`: overflow path for DEP + VirtualProtect ROP workflow.

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

Debug logs print:

- opcode
- declared length
- copied length
- handler name

## Safe Smoke Test

```bat
python python\protocol_smoketest.py --host 127.0.0.1 --port 9999
```

Expected output format:

- `PONG`

This test does not exercise the stack overflow or leak an address. `OP_LEAK`
is reserved for the `aslr_dep` stage.

## Easy Profile Workflow

Run the service under WinDbg, verify connectivity, and then send a cyclic
pattern that remains below the protocol's 8192-byte payload limit:

```bat
python python\exploit_scaffold.py ping
python python\exploit_scaffold.py pattern --opcode stack --length 800
```

After WinDbg reports the overwritten EIP value, calculate its offset:

```bat
python python\exploit_scaffold.py offset --eip 0xXXXXXXXX --length 800
```

Build a bad-character test only after independently confirming the offset and
choosing a debugger-validated return address:

```bat
python python\exploit_scaffold.py badchars --opcode stack --offset OFFSET --return-address 0xADDRESS --exclude 00,0a,0d
```

The CLI also supports `raw` payload files and a `layout` command for combining
student-supplied padding, return addresses, ROP bytes, and benign proof bytes.
Run `python python\exploit_scaffold.py --help` for the complete interface.

## WinDbg Workflow (Training)

1. Find offset:
   - send cyclic pattern via scaffold and identify EIP/SEH overwrite offset.
2. Verify badchars:
   - use scaffold badchar mode and compare memory view in debugger.
3. Identify modules:
   - map loaded modules and mitigation flags (`!mona modules` equivalent workflow).
4. Select gadgets:
   - gather gadget addresses from non-ASLR/ASLR-appropriate modules and store them in your own JSON.
5. Build ROP chain:
   - construct chain bytes in your own tooling and place them in scaffold placeholders.
6. Verify VirtualProtect call:
   - confirm stack/register layout and benign proof execution path.

Profile-specific WinDbg files:

- `windbg_easy.txt`
- `windbg_dep.txt`
- `windbg_aslr_dep.txt`
- `windbg_seh.txt`

## Training Sequence and Metadata Schema

- Follow staged progression in `training_path.md`.
- Use `gadget_json_schema.md` for exact key/field rules and validation expectations.

## Python Scaffolding Notes

- No weaponized payloads are shipped.
- Payload bytes are user-supplied and should remain benign (`MessageBoxA`, `calc.exe`, proof file write).
- Payloads larger than 8192 bytes are rejected by both the client and service before reaching a vulnerable handler.

## Visual Studio Project Notes

The commands above generate the matching Visual Studio `.sln` and `.vcxproj`
files. The selected generator does not change the required Win32 target.
A manual Visual Studio folder is included for notes/templates only.
