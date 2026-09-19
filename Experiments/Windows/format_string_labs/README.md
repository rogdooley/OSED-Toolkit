# Windows x86 Format-String Labs

Intentionally vulnerable, local-only programs for OSED-style format-string practice. Use only in a disposable Windows VM. The success paths print benign proof messages and perform no external action.

## Build

Choose the commands matching the installed CMake version. CMake selects an
installed compatible MSVC generator; `cmake --help` lists the available
generators and marks the default with `*`. Both paths produce Win32/x86
binaries and do not assume a Visual Studio release.

The examples assume a Visual Studio generator. For Ninja or NMake, open an
**x86** MSVC tools prompt, omit `-A Win32`, add
`-DCMAKE_BUILD_TYPE=Release` while configuring, and omit `--config Release`
while building. Always use a fresh build directory when changing generator or
architecture.

Modern CMake 3.13+:

```bat
cd Experiments\Windows\format_string_labs
cmake -A Win32 -S . -B build
cmake --build build --config Release
```

Legacy CMake 3.12:

```bat
cd Experiments\Windows\format_string_labs
if not exist build mkdir build
pushd build
cmake -A Win32 ..
cmake --build . --config Release
popd
```

Binaries and PDBs are written under the selected build directory's `Release`
folder. The build deliberately uses x86, `/Od`, `/Oy-`, `/GS-`, DEP, and no
ASLR. This first level isolates format-string behavior.

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
