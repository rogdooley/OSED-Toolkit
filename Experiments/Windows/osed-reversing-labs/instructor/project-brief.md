# Implementation Brief

This directory implements the supplied OSED reverse-engineering practice-lab request as three independent x86 C executables. The root README and `student/` materials intentionally omit solutions. This document set records the instructor-only implementation facts, validation boundaries, and teaching guidance.

## Build configuration

All targets require `i686-w64-mingw32-gcc`, compile with `-O0`, preserve frame pointers, omit debug symbols from the distributed executables, and disable stack cookies. Targets 01 and 03 disable ASLR while retaining NX compatibility. Target 02 enables ASLR and NX compatibility. MinGW-w64 does not provide an equivalent SafeSEH workflow; SafeSEH is therefore not claimed or configured.

## Validation contract

`make validate` verifies PE32 architecture, the selected ASLR/NX flags, and Winsock imports after an actual build. Runtime behavior must be checked on a Windows VM. Record compiler and linker versions plus SHA-256 hashes there before distributing a student bundle.
