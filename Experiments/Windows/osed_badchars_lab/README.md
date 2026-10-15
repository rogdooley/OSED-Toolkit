# OSED Bad-Character Discovery Lab

Windows x86 exercises for tracing candidate byte arrays through realistic input-processing paths with IDA Free and WinDbg.

The lab contains three loopback-only TCP targets (NET-01 through NET-03) and
three binary-file targets (FILE-01 through FILE-03). The TCP harness supports
`--probe` and `--overflow-context`; they retain the same challenge-specific
processing functions. `generate_file.py` constructs length-framed file records
without altering candidate bytes.

## Targets and default endpoints

| Target | Input | Default endpoint / invocation |
| --- | --- | --- |
| `net01.exe` | TCP | `127.0.0.1:32101` (`net01.exe [port]`) |
| `net02.exe` | TCP | `127.0.0.1:32102` (`net02.exe [port]`) |
| `net03.exe` | TCP | `127.0.0.1:32103` (`net03.exe [port]`) |
| `file01.exe` | file record | `file01.exe <record-file>` |
| `file02.exe` | file record | `file02.exe <record-file>` |
| `file03.exe` | file record | `file03.exe <record-file>` |

All TCP services bind to loopback only. Match the harness target and port, for
example: `python tools\\send_tcp.py --challenge net02 --mode probe --candidate-file candidate.bin --port 32102`.

## Byte-behavior progression

The targets intentionally do not repeat one C-string lesson. NET-01 is the
baseline C-string exercise. The remaining targets cover, respectively, a
protocol field delimiter, conditional deletion/substitution, a legacy record
terminator, whole-record decoding, and context-dependent escaping. Student
material describes observation strategy, not the values or rules to discover.

Build from a Visual Studio 2017, 2019, or 2022 Developer Command Prompt:

```bat
build\build.bat Release
```

The solution is Win32-only. Binaries are emitted to
`dist\\instructor\\Release\\` (or `Debug`). Host-side tests validate project
metadata and Python tooling; compilation, PE inspection, and WinDbg observations
require a Windows MSVC environment and are not claimed by this repository until
recorded in instructor material.
