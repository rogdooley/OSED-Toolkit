# OSED Lab Training Path (VM-Only)

This path sequences profile usage from lowest complexity to highest constraints.

## Stage 1: easy

Profile
- Build: `LAB_PROFILE=easy`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /DYNAMICBASE:NO /NXCOMPAT:NO`

Primary goals
- Confirm protocol handling and deterministic crashes.
- Find `OP_STACK` EIP offset with cyclic pattern.
- Establish badchar process with controlled memory checks.

Expected outcomes
- Reliable EIP control on `OP_STACK`.
- Documented badchar set for your VM/debugger/toolchain.

Reference
- `windbg_easy.txt`

## Stage 2: seh

Profile
- Build: `LAB_PROFILE=seh`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /SAFESEH:NO`

Primary goals
- Understand exception-path control and SEH overwrite behavior via `OP_SEH`.
- Correlate deterministic AV path with exception context inspection.

Expected outcomes
- Reproducible SEH overwrite offset and structured exception analysis notes.

Reference
- `windbg_seh.txt`

## Stage 3: dep

Profile
- Build: `LAB_PROFILE=dep`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /DYNAMICBASE:NO /NXCOMPAT`

Primary goals
- Transition from direct code execution assumptions to DEP-aware control flow.
- Plan benign `VirtualProtect`-style call setup for `OP_ROP`.

Expected outcomes
- Stable module inventory.
- User-maintained gadget metadata JSON with validated addresses.
- Verified debugger break on `kernel32!VirtualProtect` during training flow.

Reference
- `windbg_dep.txt`

## Stage 4: aslr_dep

Profile
- Build: `LAB_PROFILE=aslr_dep`, `HELPER_ASLR=ON`
- Mitigations: `/GS- /DYNAMICBASE /NXCOMPAT`

Primary goals
- Use `OP_LEAK` to recover runtime pointer context.
- Recompute address-dependent values each process start.
- Re-validate DEP-aware benign control flow under ASLR.

Expected outcomes
- Repeatable leak-to-module mapping process.
- Documented per-run address recalculation workflow.

Reference
- `windbg_aslr_dep.txt`

## Supporting Workflow

1. Start service: `osed_vulnsvc.exe 9999`
2. Confirm connectivity: `python python\\protocol_smoketest.py`
3. Use `python\\exploit_scaffold.py` with benign, user-supplied bytes.
4. Keep module/gadget metadata in `gadgets/gadgets_template.json` format.
5. Follow profile-specific WinDbg command file.

## Guardrails

- Local isolated VM only.
- No persistence, credential theft, stealth, or destructive payload behavior.
- Keep proof behavior benign (`MessageBoxA`, `calc.exe`, proof file write).
