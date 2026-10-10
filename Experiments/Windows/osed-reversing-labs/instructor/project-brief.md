# Implementation Brief

This directory implements the supplied OSED reverse-engineering practice-lab request as three independent x86 C executables. The root README and `student/` materials intentionally omit solutions. This document set records the instructor-only implementation facts, validation boundaries, and teaching guidance.

## Build configuration

The primary Windows build uses Visual Studio 2022's x86 `cl.exe`, `/Od`, `/Oy-`, and `/GS-`; distributed executables omit debug symbols. Linux cross-compilation remains available through `i686-w64-mingw32-gcc` and the Makefile. Targets 01 and 03 disable ASLR while retaining NX compatibility. Target 02 enables ASLR and NX compatibility. SafeSEH is not claimed or configured.

## Validation contract

`make validate` verifies PE32 architecture, the selected ASLR/NX flags, and Winsock imports after an actual build. Runtime behavior must be checked on a Windows VM. Record compiler and linker versions plus SHA-256 hashes there before distributing a student bundle.
