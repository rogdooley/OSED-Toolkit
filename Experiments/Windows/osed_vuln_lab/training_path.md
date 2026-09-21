# OSED Lab Training Path (VM-Only)

This path sequences profile usage from lowest complexity to highest constraints.

Begin every stage from the generated `student_bundle`. The source tree,
`instructor/`, and `python/` are instructor material until the learner has
recovered the protocol and written a working client.

## Stage 1: easy

Profile
- Build: `LAB_PROFILE=easy`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /DYNAMICBASE:NO /NXCOMPAT:NO`

Primary goals
- Recover the message envelope, validation logic, and dispatcher from the
  binary without using source or PDB files.
- Write a minimal client based on documented evidence.
- Identify the simplest vulnerable command and find its EIP offset with a
  cyclic pattern.
- Establish badchar process with controlled memory checks.

Expected outcomes
- Completed protocol worksheet with static and dynamic evidence.
- Reliable EIP control on the identified stack-overflow command.
- Documented badchar set for your VM/debugger/toolchain.
- Verified direct stack redirect from a supplied non-ASLR module.

Reference
- `windbg_easy.txt`

## Stage 2: seh

Profile
- Build: `LAB_PROFILE=seh`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /SAFESEH:NO`

Primary goals
- Understand exception-path control and SEH overwrite behavior via `OP_SEH`.
- Recover the command-specific record layered inside the familiar envelope.
- Correlate deterministic AV path with exception context inspection.

Expected outcomes
- Reproducible SEH overwrite offset and structured exception analysis notes.
- Debugger-verified pop-pop-ret candidate from a module with SafeSEH disabled.

Reference
- `windbg_seh.txt`

## Stage 3: dep

Profile
- Build: `LAB_PROFILE=dep`, `HELPER_ASLR=OFF`
- Mitigations: `/GS- /DYNAMICBASE:NO /NXCOMPAT`

Primary goals
- Transition from direct code execution assumptions to DEP-aware control flow.
- Recover the evolved offset-based command body and identify which bytes reach
  the vulnerable copy.
- Plan benign `VirtualProtect`-style call setup for `OP_ROP`.

Expected outcomes
- Stable module inventory.
- User-maintained gadget metadata JSON containing every primitive required by
  `Tools.rop.VirtualProtectChain`.
- Verified debugger break on `kernel32!VirtualProtect` during training flow.
- Benign proof bytes reached after VirtualProtect returns through `jmp esp`.

Reference
- `windbg_dep.txt`

## Stage 4: aslr_dep

Profile
- Build: `LAB_PROFILE=aslr_dep`, `HELPER_ASLR=ON`
- Mitigations: `/GS- /DYNAMICBASE /NXCOMPAT`

Primary goals
- Use `OP_LEAK` to recover runtime pointer context.
- Parse and validate the binary response rather than relying on a textual label.
- Recompute address-dependent values each process start.
- Re-validate DEP-aware benign control flow under ASLR.

Expected outcomes
- Repeatable leak-to-module mapping process.
- Documented per-run address recalculation workflow.
- Working DEP chain built from leaked base plus verified gadget RVAs.

Reference
- `windbg_aslr_dep.txt`
- `aslr/README.md` for the complete four-exercise leak-to-control-flow track.

## Supporting Workflow

1. Build the chosen profile and its `student_bundle` target.
2. Move only the generated bundle into the isolated training VM.
3. Start `osed_vulnsvc.exe 9999` and reverse the receive path in IDA Pro.
4. Create a client from the recovered envelope, command-body parser, and
   dispatcher behavior.
5. Continue with the profile-specific WinDbg workflow after reaching the
   intended handler.

Instructor validation clients under `python/` may be introduced after the
learner submits the protocol worksheet. They are not starting solutions.

## Guardrails

- Local isolated VM only.
- No persistence, credential theft, stealth, or destructive payload behavior.
- Keep proof behavior benign (`MessageBoxA`, `calc.exe`, proof file write).
