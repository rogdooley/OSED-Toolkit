# OSED Bad-Character Discovery Lab

Windows x86 exercises for tracing candidate byte arrays through realistic input-processing paths with IDA Free and WinDbg.

The current pre-weekend gate implements NET-01 and NET-02. Each target is a loopback-only service with a supplied Python harness. `--probe` is for observing candidate bytes without relying on corruption; `--overflow-context` uses the documented setup while retaining the same processing functions.

Build from a Visual Studio 2017, 2019, or 2022 Developer Command Prompt:

```bat
build\build.bat Release
```

The solution is Win32-only. Host-side tests validate project metadata and Python tooling; compilation, PE inspection, and WinDbg observations require a Windows MSVC environment and are not claimed by this repository until recorded in instructor material.
