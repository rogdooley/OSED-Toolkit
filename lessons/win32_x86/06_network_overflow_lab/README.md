# 06 - Network Overflow Lab (Win32/x86)

Goal: practice the *repeatable* parts of stack overflow work in a network-shaped target:

- reproduce a crash via a single request
- use a cyclic pattern to recover exact offset to EIP (when applicable)
- confirm the vulnerable code path in IDA
- learn the WinDbg “first response” muscle memory

This lesson intentionally stops at **crash + offset + root cause**.

## Target Summary

- Binary: `labsrv_overflow_x86.exe` (you build it)
- Protocol: one-line commands over TCP
- Vulnerable command: `OVER <bytes>\r\n`
- Vulnerability: unsafe copy into fixed-size stack buffer

## Build (Windows, x86)

From a VS Developer Command Prompt:

```bat
cd lessons\win32_x86\06_network_overflow_lab\src
cl /nologo /W3 /Od /Zi /MT labsrv_overflow.c ws2_32.lib /link /OUT:labsrv_overflow_x86.exe
```

Optional: build a “more realistic” variant with security features:

```bat
cl /nologo /W3 /Od /Zi /MT /GS labsrv_overflow.c ws2_32.lib /link /OUT:labsrv_overflow_x86_GS.exe /DYNAMICBASE /NXCOMPAT
```

## Run (Windows)

In one console:

```bat
labsrv_overflow_x86.exe
```

It listens on `127.0.0.1:9001`.

## Send Requests

From another console:

```bat
py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd PING
```

Crash attempt (length-based):

```bat
py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd OVER --len 600
```

Pattern-based:

1) Generate a cyclic pattern on your host:

```bash
python -m Tools.pattern.cli.pattern_create -l 800 > pattern.txt
```

2) Send it:

```bat
py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd OVER --pattern-file pattern.txt
```

## WinDbg Workflow (x86)

Launch the server under WinDbg and send the same crashing request.

After crash, run:

```
!analyze -v
r
r eip
k
dds esp L40
```

Copy the crash text into `crash.txt` and triage:

```bash
python -m Tools.crashtriage.cli.triage_crash -l 800 --input crash.txt
```

Then compute the offset using the crashed EIP value:

```bash
python -m Tools.pattern.cli.pattern_offset -l 800 -q <EIP_HEX>
```

## IDA Exercise

Open the EXE in IDA Free and find:

- `handle_client`
- the handler for `OVER`
- the local stack buffer size
- the unsafe copy site

Write a short note using:

`lessons/win32_x86/shared/notes_template.md`

## Safety

- Use only in your isolated lab VM.
- This code is intentionally unsafe by design.
