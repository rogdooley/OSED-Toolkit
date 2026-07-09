# Build Settings

The build needs to look like a real Release deployment, not a classroom demo.

## Baseline

- Target: Windows x86
- Toolchain: Visual Studio
- Configuration: Release with symbols
- Debugger: WinDbg
- RE tools: IDA Free or Ghidra

## Recommended compiler posture

- optimize the service and DLLs
- keep PDBs available
- avoid whole-program transforms that erase function boundaries too early
- preserve separate translation units so the student can see real call flow

## Suggested profiles

### Analysis-friendly

- service: `/O2 /GS /Zi`
- helper: `/O2 /Zi`
- gadgetlib: `/O2 /Zi`
- link: `/DEBUG /INCREMENTAL:NO`

This is the first teaching profile. It should be reproducible and easy to step
through while still looking like a Release build.

### DEP-oriented

- service: `/O2 /GS /NXCOMPAT /Zi`
- helper: fixed base in early stages
- gadgetlib: fixed base or ASLR depending on lesson stage

This is the profile that prepares the student for ROP reasoning later.

### ASLR-oriented

- service: `/O2 /GS /NXCOMPAT /DYNAMICBASE /Zi`
- helper and gadgetlib: ASLR enabled

This profile is for the later phase when address discovery matters.

## Import-table choices

The import tables should be intentional:

- `ws2_32.dll` for network handling
- `kernel32.dll` for process and memory primitives
- `advapi32.dll` or `bcrypt.dll` for auth or token verification
- a small custom `helper.dll` for cross-module tracing

Those imports give the student real work to do in IDA and WinDbg without
depending on contrived APIs.
