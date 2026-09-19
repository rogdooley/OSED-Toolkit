# Windows x86 Format-String Labs

Intentionally vulnerable, local-only programs for OSED-style format-string practice. Use only in a disposable Windows VM. The success paths print benign proof messages and perform no external action.

## Build

Open a **Developer Command Prompt for Visual Studio 2017** and choose the
command style matching the installed CMake version.

Modern CMake 3.13+ (including 3.29):

```bat
cd Experiments\Windows\format_string_labs
cmake -G "Visual Studio 15 2017" -A Win32 -S . -B build
cmake --build build --config Release
```

Legacy CMake 3.12:

```bat
cd Experiments\Windows\format_string_labs
if not exist build mkdir build
pushd build
cmake -G "Visual Studio 15 2017" -A Win32 ..
cmake --build . --config Release
popd
```

Binaries and PDBs are written under `build\Release`. The build deliberately uses x86, `/Od`, `/Oy-`, `/GS-`, DEP, and no ASLR. This first level isolates format-string behavior; later levels should add binary-only analysis and ASLR.

`fmt05_service.exe` is the integrated exception: it enables ASLR and DEP and listens only on `127.0.0.1:31337`.

## Run

Each program accepts a format string interactively or reads its first line from a file:

```bat
build\Release\fmt01_stack_leak.exe
build\Release\fmt01_stack_leak.exe input.txt
```

Literal percent signs in `cmd.exe` are awkward, so input files are recommended. Attach WinDbg before testing `%s` or a write conversion: an invalid consumed value can cause an expected access violation.

## Training Contract

- Do not inspect `src` or `instructor` during the first attempt.
- Begin with the matching file under `exercises`.
- Record facts separately from hypotheses.
- Request hints one at a time.
- Stop after meeting the success condition and write the debrief before continuing.

The programs pass explicit values through variadic argument slots. This makes argument consumption reproducible and visible at the `printf` call while preserving the core vulnerability: untrusted data is used as the format string. Labs 3 and 4 explicitly enable the Microsoft CRT's normally disabled `%n` conversion.

## Sequence

1. `FMT-01`: stack leaks and argument consumption.
2. `FMT-02`: pointer recognition and `%s` disclosure.
3. `FMT-03`: `%n` and exact character-count writes.
4. `FMT-04`: function-pointer overwrite using debugger-derived addresses.
5. `FMT-05`: binary-driven discovery and argument mapping.
6. `FMT-06`: arbitrary read and ASLR base recovery.
7. `FMT-07`: bounded byte-wise arbitrary writes.
8. `FMT-08`: leak, write, and benign control-flow redirection.

Solutions are intentionally separated in `instructor/solutions.md`.
