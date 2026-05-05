# OSED WinDbg Toolkit

TypeScript-based WinDbg Preview data-model script for exploit-development helpers.

## Prerequisites

- WinDbg Preview (modern JavaScript provider)
- Node.js 20+

## Install and Build

1. Clone this repository.
2. Change into the project directory:
   - `cd osed-windbg`
3. Install dev dependencies:
   - `npm install`
4. Build bundle:
   - `npm run build`
5. In WinDbg Preview:
   - `.scriptload <full path>\\osed-windbg\\dist\\osed.js`

## Quickstart

- `dx @$osed().help()`
- `dx @$osed().pattern_create(300, "msf")`
- `dx @$osed().exploit("offset")`
- `dx @$osed().seh()`
- `dx @$osed().sc.peb()`
- `dx @$osed().sc.modules()`
- `dx @$osed().sc.base("kernel")`
- `dx @$osed().sc.hashes("kernel32", "crc32")`
- `dx @$osed().sc.hash("WinExec", "ROR13")`
- `dx @$osed().sc.algorithms()`
- `dx @$osed().sc.iat()`
- `dx @$osed().sc.iat("app.exe")`
- `dx @$osed().sc.iat_find("VirtualAlloc")`
- `dx @$osed().sc.iat_ptr("app.exe", "VirtualAlloc")`

## Troubleshooting

- Script fails to load:
  - Confirm `dist/osed.js` exists and path is correct.
- `@$osed` is missing:
  - Re-run `.scriptload` and confirm `initializeScript()` executed.
- Command returns validation errors:
  - Use `dx @$osed().help("<name>")` and match schema exactly.
- Memory read failures:
  - Ensure target process is active and addresses are valid in current context.
- `dx` result output is noisy:
  - Command calls return `true/false`; inspect full structured output with `dx @$osed().last_result()`.
