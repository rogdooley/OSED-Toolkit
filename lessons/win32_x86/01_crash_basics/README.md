# 01 - Crash Basics (Win32/x86)

Goal: produce a deterministic crash, then extract the few fields you always need:

- exception type/code
- instruction pointer register (EIP) at time of crash
- stack pointer (ESP) and a small stack dump
- the input that caused the crash

This lesson uses a deliberately unsafe copy into a fixed-size stack buffer.

## Build (Windows, x86)

```bat
cd lessons\win32_x86\01_crash_basics\src
cl /nologo /W3 /Od /Zi /MT vuln_strcpy.c /link /OUT:vuln_strcpy_x86.exe
```

Optional (file-driven target, easier for long/binary payloads):

```bat
cl /nologo /W3 /Od /Zi /MT vuln_file_read.c /link /OUT:vuln_file_read_x86.exe
```

## Run (Normal)

```bat
vuln_strcpy_x86.exe AAAA
```

## Crash It (Length-Based)

```bat
vuln_strcpy_x86.exe AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

If it does not crash, increase length.

## Crash It (Pattern-Based)

On your Windows host (or Kali), generate a pattern and pass it:

```bash
python -m Tools.pattern.cli.pattern_create -l 600 > pattern.txt
```

Then run:

```bat
vuln_strcpy_x86.exe <contents_of_pattern.txt>
```

For the file-driven target, write a binary payload and pass the filename:

```bash
python lessons/win32_x86/tools/make_pattern_payload.py --length 600 --out payload.bin
```

```bat
vuln_file_read_x86.exe payload.bin
```

## WinDbg Exercise

Launch under WinDbg and feed the same input.

Commands to run after crash:

```
r
!analyze -v
k
dds esp L40
```

Copy the WinDbg output to `crash.txt`, then run triage:

```bash
python -m Tools.crashtriage.cli.triage_crash -l 600 --input crash.txt
```

Expected outcome:

- it identifies `x86`
- it ranks `EIP` as the top candidate (when present)
- it emits `pattern_offset` commands for the values it found

## IDA Exercise

Open `vuln_strcpy_x86.exe` in IDA Free.

Find the vulnerable function and answer:

1. What is the local buffer size?
2. Which copy API is used?
3. Where does the input originate (argv, stdin, file)?

Write these answers in a short note next to the lesson.
