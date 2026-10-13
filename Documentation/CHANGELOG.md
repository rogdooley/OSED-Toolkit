# Emitter Changelog

## Unreleased

### Templates
- **registry_persist** -- Write a Run value under HKCU via
  RegOpenKeyExA/RegSetValueExA so the binary auto-starts on user logon.
- **dll_inject** -- Classic DLL injection via CreateRemoteThread +
  LoadLibraryA. Finds target by name (Toolhelp32), opens with
  PROCESS_ALL_ACCESS, allocates remote buffer, writes DLL path,
  resolves LoadLibraryA via GetModuleHandleA/GetProcAddress.
- **service_persist** -- Install a Windows service via SCM APIs
  (OpenSCManagerA, CreateServiceA, StartServiceA) that auto-starts on
  boot. Badchar-safe SERVICE_ALL_ACCESS encoding.
- **process_replace** -- Kill a running process by name (Toolhelp32
  snapshot enumeration), copy a replacement binary, restart it via
  WinExec. Case-insensitive process name matching.

### APIs and structures
- RegOpenKeyExA, RegSetValueExA, RegCloseKey added to api_database.py
  (advapi32.dll)
- VirtualAllocEx, WriteProcessMemory, CreateRemoteThread added to
  api_database.py (kernel32.dll)
- OpenSCManagerA, CreateServiceA, StartServiceA, CloseServiceHandle
  added to api_database.py (advapi32.dll)
- advapi32.dll added to MODULE_LOAD_ORDER (load_via=LoadLibraryA)
- CreateToolhelp32Snapshot, Process32First, Process32Next, OpenProcess,
  TerminateProcess added to api_database.py
- PROCESSENTRY32 struct (0x128 bytes) added to struct database

### CLI
- `--service-name` flag for service_persist template
- `--process-name` flag for process_replace template

### Bug fixes
- **process_replace TerminateProcess race**: Added
  WaitForSingleObject(hProcess, INFINITE) after TerminateProcess to
  ensure the old binary's file handle is released before CopyFileA.
- **process_replace CopyFileA unchecked**: WinExec now only runs if
  CopyFileA succeeds (test eax, eax / jz skip).
- **process_replace snapshot handle leak**: Not-found path now calls
  CloseHandle(hSnapshot) before jumping to copy.
- **Register clobber in safe_*_mem helpers**: `_pick_tmp()` now avoids
  both the destination and base registers when selecting scratch storage.
  Previously, `safe_sub_from_mem("ecx", "edx", ...)` could generate
  `add edx, edx` after overwriting edx with the encoded displacement.
- **Stack frame overflow**: Frame size is now computed dynamically from
  the layout high-water mark (rounded to 0x100), replacing the fixed
  0x500. Guard rejects frames > 4096 bytes (no stack probing yet).
- **Missing LoadLibraryA**: Manifests that use APIs from secondary DLLs
  without declaring LoadLibraryA now raise ValueError instead of
  silently skipping that DLL's resolution.
- **CLI exit code**: Assembly failures, unresolved badchar violations
  (without --encode), and missing assembler now exit non-zero.
- **Stale output cleanup**: Encoded files (shellcode_encoded.*) and
  encoder_report.txt are removed on rebuilds that don't produce them.
- **Test format mismatch**: Fixed py_bytes expected format in
  test_build_rejects_assembled_badchars.

### Documentation
- emitter-internals.md accuracy fixes: string badchar scope, probe_slots
  auto-adds APIs only (not variables/strings), fnstenv stub context,
  push method builds at ESP not frame offset, structure zone in frame
  diagram, PEB walk case assumption, dynamic frame sizing throughout.
- emitter.md and doc_gen.py updated for dynamic frame sizing.

## 2026-10-11

### Templates
- **http_exfil** -- Read a file from the target into a VirtualAlloc
  buffer, POST contents to attacker's HTTP server via WinInet. 913 bytes.
- **http_download** -- `--payload-file` flag auto-sizes VirtualAlloc
  from the served file.

### APIs
- InternetConnectA, HttpOpenRequestA, HttpSendRequestA added to
  api_database.py (wininet.dll).

### CLI
- `--url` auto-extracts `--lhost`/`--lport` when they aren't explicit.
- `--lhost`/`--lport` now optional (default to 127.0.0.1:4444 only as
  fallback).
- `--payload-file` flag for http_download VirtualAlloc sizing.

### Tools
- http_exfil_server.py -- Minimal HTTP POST catcher that saves request
  bodies as timestamped .bin files.

### Documentation
- emitter.md -- Full usage docs with CLI reference, all templates,
  XOR encoder, exfil server.
- emitter-internals.md -- Technical reference for shellcode internals.
