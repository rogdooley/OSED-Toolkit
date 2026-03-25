# 02 - Fuzzing (Minimal, Practical)

Goal: automate the boring part:

- send progressively larger inputs
- detect crash by process exit / hang
- save the last payload that likely caused the crash

This is deliberately minimal so you understand every line.

## Build Target (Windows, x86)

Reuse the target from lesson 01 or build a new copy:

```bat
cd lessons\win32_x86\01_crash_basics\src
cl /nologo /W3 /Od /Zi /MT vuln_strcpy.c /link /OUT:..\..\02_fuzzing\src\vuln_strcpy_x86.exe
```

## Run Fuzzer (Windows)

From `lessons\win32_x86\02_fuzzing\src`:

```bat
py -3 fuzz_len.py --exe vuln_strcpy_x86.exe --max 2000 --step 50
```

Artifacts are written to `lessons\win32_x86\02_fuzzing\artifacts\`.

## Next Exercise

1. Change the fuzzer to use a cyclic pattern once you find a crashing length.
2. Capture the WinDbg crash output and run `Tools.crashtriage` on it.

