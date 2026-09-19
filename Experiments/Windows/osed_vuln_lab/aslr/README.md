# ASLR Bypass Track

This is a local Windows x86 adaptation of the OSED leak-to-control-flow workflow. It does not reproduce the course target. It isolates the same reasoning chain in an inspectable VM lab:

```text
runtime pointer leak
        -> identify owning module
        -> leaked VA - known anchor RVA
        -> randomized module base
        -> base + target RVA
        -> benign control-flow proof
```

Do not inspect `src`, `instructor.md`, or linker map files during the first attempt. IDA and WinDbg observations are the exercise.

## Build

Choose the commands matching the installed CMake version. CMake selects an
installed compatible MSVC generator; use `cmake --help` to inspect generators.
See the parent README for Ninja/NMake and build-directory cache guidance.

Modern CMake 3.13+:

```bat
cd Experiments\Windows\osed_vuln_lab
cmake -A Win32 -S . -B build_aslr_dep -DLAB_PROFILE=aslr_dep -DHELPER_ASLR=ON
cmake --build build_aslr_dep --config Release
```

Legacy CMake 3.12:

```bat
cd Experiments\Windows\osed_vuln_lab
if not exist build_aslr_dep mkdir build_aslr_dep
pushd build_aslr_dep
cmake -A Win32 -DLAB_PROFILE=aslr_dep -DHELPER_ASLR=ON ..
cmake --build . --config Release
popd
```

Run the executable from the matching `Release` directory under WinDbg, for
example `build_aslr_dep\Release\osed_vulnsvc.exe 9999`. CMake places
`osedhelper.dll` in the same directory. Confirm both modules use ASLR and DEP.

## Exercises

1. [ASLR-01: Observe Randomization](ASLR-01-observe.md)
2. [ASLR-02: Find the Disclosure Path](ASLR-02-disclosure.md)
3. [ASLR-03: Recover the Module Base](ASLR-03-base-recovery.md)
4. [ASLR-04: Leak to Control Flow](ASLR-04-control-flow.md)

Use `hints.md` one hint at a time. `instructor.md` contains validation data and should stay closed until the exercise is complete.

## Scaffold

After completing ASLR-02, the scaffold handles transport and arithmetic but contains no target RVAs or overwrite offset:

```bat
python python\aslr_scaffold.py leak
python python\aslr_scaffold.py calculate --leak 0xAAAAAAAA --anchor-rva 0xBBBB --target-rva 0xCCCC
python python\aslr_scaffold.py trigger --offset 0xDD --target 0xEEEEEEEE
```

Every placeholder must come from your own IDA or WinDbg evidence. Restart the service before the final attempt and obtain a fresh leak.
