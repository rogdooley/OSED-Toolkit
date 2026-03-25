# 05 - Mitigations (Observe, Don’t Guess)

Goal: compile the same vulnerable logic with different mitigations and observe:

- does it crash sooner/later?
- does the exception context change?
- do you see stack cookie failures?
- do PE flags indicate NX/ASLR compatibility?

Use the same source as lesson 01 to keep variables controlled.

## Build Variants (Windows, x86)

From:

```bat
cd lessons\win32_x86\05_mitigations\src
```

### Variant A: Minimal (closest to lesson 01)

```bat
cl /nologo /W3 /Od /Zi /MT vuln_variants.c /link /OUT:vuln_A.exe
```

### Variant B: Stack cookies on (/GS)

```bat
cl /nologo /W3 /Od /Zi /MT /GS vuln_variants.c /link /OUT:vuln_B_GS.exe
```

### Variant C: Stack cookies off (/GS-)

```bat
cl /nologo /W3 /Od /Zi /MT /GS- vuln_variants.c /link /OUT:vuln_C_GSoff.exe
```

### Variant D: Make ASLR/NX intent explicit

```bat
cl /nologo /W3 /Od /Zi /MT vuln_variants.c /link /OUT:vuln_D_nx_aslr.exe /DYNAMICBASE /NXCOMPAT
```

## Inspect PE Flags

```bat
dumpbin /headers vuln_D_nx_aslr.exe | findstr /i "dynamicbase nxcompat"
```

## WinDbg Exercises

Crash each variant the same way (same input length/pattern) and compare:

- `!analyze -v` output
- whether you see indications of stack cookie failure (common symptom: crash in runtime checks)
- how consistent the crash is across runs

Keep notes in a table:

- binary name
- compile flags
- exception summary
- top-ranked register candidate per `Tools.crashtriage`

