# OSED Vulnerable Service Lab (VM-Only)

This lab target is intentionally vulnerable and intended only for local Windows x86 VM training.

## Components

- `osed_vulnsvc`: Win32 TCP service with opcode-based vulnerable handlers.
- `osedhelper.dll`: Harmless helper DLL with exported functions for module/gadget analysis.
- `python/exploit_scaffold.py`: Benign exploit-development scaffolding.
- `python/protocol_smoketest.py`: Safe connectivity/parser test that exercises only `OP_LEAK`.
- `gadgets/gadgets_template.json`: User-maintained gadget metadata template.
- `gadget_json_schema.md`: JSON format rules for module/gadget metadata.
- `training_path.md`: staged training sequence and expected outcomes.
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

- `0x1001 OP_STACK`: classic stack overflow path.
- `0x1002 OP_SEH`: SEH overwrite training path.
- `0x1003 OP_SMALLBUF`: constrained overflow for egghunter-style staging.
- `0x1004 OP_LEAK`: controlled pointer leak (`helper_get_anchor` pointer disclosure).
- `0x1005 OP_ROP`: overflow path for DEP + VirtualProtect ROP workflow.

## Build (CMake + MSVC, x86)

From a **Developer Command Prompt for VS**:

```bat
cd Experiments\Windows\osed_vuln_lab
cmake -S . -B build_easy -A Win32 -DLAB_PROFILE=easy -DHELPER_ASLR=OFF
cmake --build build_easy --config Release

cmake -S . -B build_dep -A Win32 -DLAB_PROFILE=dep -DHELPER_ASLR=OFF
cmake --build build_dep --config Release

cmake -S . -B build_aslr_dep -A Win32 -DLAB_PROFILE=aslr_dep -DHELPER_ASLR=ON
cmake --build build_aslr_dep --config Release

cmake -S . -B build_seh -A Win32 -DLAB_PROFILE=seh -DHELPER_ASLR=OFF
cmake --build build_seh --config Release
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
osed_vulnsvc.exe 9999
```

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

- `LEAK:0x...`

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

## Visual Studio Project Notes

If preferred, generate `.sln/.vcxproj` from CMake using `-G "Visual Studio 17 2022" -A Win32`.
A manual Visual Studio folder is included for notes/templates only.
