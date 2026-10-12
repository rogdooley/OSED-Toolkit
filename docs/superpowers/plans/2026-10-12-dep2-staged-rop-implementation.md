# DEP-2 Staged ROP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `dep2` and `aslr_dep2` Windows x86 training profiles that preserve `OP_ROP` framing while requiring a first-stage stack pivot into a staged, `PUSHAD`-driven `VirtualProtect` ROP chain.

**Architecture:** The service validates the existing version-2 `OP_ROP` record, copies its data region into private helper static storage, then copies exactly through saved EIP plus two DWORDs into a local overflow buffer. The helper initializes a private cached `VirtualProtect` pointer at startup; the second-stage chain dereferences that slot, builds the documented `PUSHAD` frame, marks staged proof bytes executable, and returns into a local proof sequence that changes a private status DWORD. `aslr_dep2` reuses this architecture with helper ASLR and the existing leak/RVA workflow.

**Tech Stack:** C11, MSVC x86 intrinsics and inline assembly, CMake 3.12+, Python 3 standard library, `unittest`, `pytest`, WinDbg/CDB on Windows, and the existing `Tools.rop` planner.

**Spec:** `docs/superpowers/specs/2026-10-12-dep2-staged-rop-design.md`

## Global Constraints

- Preserve the existing `OP_ROP` (`0x1005`) version-2 record and do not add a second receive or a new opcode.
- Build Win32/x86 only; retain `/GS- /Od /Ob0 /Oi- /Oy-` and use `__declspec(noinline)` around the vulnerable DEP-2 handler.
- `dep2` uses fixed service/helper bases with DEP enabled; `aslr_dep2` enables service/helper ASLR and DEP.
- Stage the full validated ROP data region in a private 8192-byte static helper buffer; never export or return its address.
- Initialize the private cached `VirtualProtect` pointer during service startup; fail startup if it cannot be resolved.
- The DEP-2 helper must not import `VirtualProtect`, export `helper_memory_protect`, or expose `helper_sequence_19`/`helper_sequence_20`.
- Compute the first-stage copy boundary with `_AddressOfReturnAddress()` as the local-buffer-to-return-address distance plus `3 * sizeof(uint32_t)`.
- The first stage contains saved EIP, staged-chain address, and pivot gadget only; later request bytes must not reach caller-stack positions after that boundary.
- The proof is local and benign: staged instructions update a private helper status DWORD; no process launch, file write, network action, or persistence.
- Keep instructor solutions, layout tools, PDB-driven runtime tests, and generated manifests out of `student_bundle`.

## Review Focus

- **Oversized records:** `helper_stage_record` must reject data larger than 8192 bytes without modifying the previous stage; cover this in Task 2 unit tests.
- **Short first-stage inputs:** a record shorter than the dynamically computed three-DWORD boundary must not reach the overflow copy; cover this in Task 4 runtime negative test.
- **Post-EIP contamination:** sent sentinel DWORDs after the pivot gadget must not appear in caller-stack positions after the controlled boundary; cover this in Task 4 CDB test.
- **API-resolution failure:** startup must fail cleanly if the cached pointer is unavailable; cover this in Task 2 helper-unit/Windows startup test.
- **ASLR reuse:** a payload calculated from a previous helper base must fail or be rejected after restart, while a fresh leak-plus-RVA payload succeeds; cover this in Task 5 two-launch test.
- **`PUSHAD` feasibility:** before completing the instructor chain, a Release Win32 CDB run must prove the pivot reaches staging and that ESP equals the proof address immediately before `PUSHAD`; cover this in Task 0.
- **Student-artifact isolation:** bundle checks must reject PDBs, map files, build logs, generated manifests, and source archives in addition to instructor scripts; cover this in Task 6.

---

### Task 0: Establish the Release Win32 Pivot Feasibility Gate

**Files:**
- Create: `Experiments/Windows/osed_vuln_lab/python/verify_dep2_feasibility.py`
- Create: `Experiments/Windows/osed_vuln_lab/python/test_verify_dep2_feasibility.py`
- Modify: `Experiments/Windows/osed_vuln_lab/CMakeLists.txt`

**Interfaces:**
- Produces: `verify_dep2_feasibility.py --service PATH --helper PATH --cdb PATH`, which accepts an explicitly supplied first-stage request and expected stage/proof addresses and returns nonzero on any failed breakpoint assertion.
- Consumes later: the same PDB symbol resolution and structured CDB transcript format used by the full Task 4 verifier.
- Constraint: this is an instructor-only Release Win32 gate. It proves control-flow feasibility, not a complete DEP bypass, and it never enters `student_bundle`.

- [ ] **Step 1: Write failing feasibility transcript tests**

Create `test_verify_dep2_feasibility.py` cases that reject a transcript when the saved-EIP sequence is wrong, the pivot does not execute, post-pivot ESP is outside staging, the first second-stage `ret` target is wrong, or ESP immediately before `PUSHAD` differs from the proof address.

- [ ] **Step 2: Run the test and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_verify_dep2_feasibility.py'`

Expected: FAIL because the feasibility verifier does not exist.

- [ ] **Step 3: Implement the feasibility parser and CMake target**

Implement a structured CDB-command generator/transcript parser and a non-default `verify_dep2_feasibility` CMake target. The target must require the Release Win32 service/helper and matching PDBs, fail clearly when they are absent, and record the selected build configuration.

- [ ] **Step 4: Run the Release Win32 gate before full chain work**

On the Windows build host, configure and build `dep2` as Release Win32, then run the feasibility target with an instructor-only controlled staged request. Capture evidence that the exact final pivot path reaches the selected `PUSHAD` instruction with ESP equal to proof-start. If this fails, resolve the actual gadget/stack layout before continuing; do not proceed on a register-table assumption.

- [ ] **Step 5: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/python/verify_dep2_feasibility.py Experiments/Windows/osed_vuln_lab/python/test_verify_dep2_feasibility.py Experiments/Windows/osed_vuln_lab/CMakeLists.txt
rtk git commit -m "Gate DEP-2 on Release pivot feasibility"
```

---

### Task 1: Add Instructor Chain and Proof Builders

**Files:**
- Create: `Experiments/Windows/osed_vuln_lab/python/dep2_layout.py`
- Create: `Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py`
- Create: `Experiments/Windows/osed_vuln_lab/python/dep2_solution.py`
- Modify: `Tools/rop/chain.py`
- Modify: `Tools/rop/__init__.py`
- Modify: `Tools/rop/tests/test_rop.py`

**Interfaces:**
- Produces: `dep2_layout.first_stage_prefix_length(saved_eip_offset: int) -> int`, returning `saved_eip_offset + 12`.
- Produces: `dep2_layout.build_status_proof(status_address: int, success_value: int) -> bytes`, emitting a local x86 status-store-and-return proof sequence.
- Produces: `dep2_layout.build_staged_payload(saved_eip_offset: int, pop_eax_ret: int, stage2_address: int, pivot: int, stage2_offset: int, stage2: bytes, proof: bytes) -> bytes`.
- Produces: `Tools.rop.CachedVirtualProtectChain`, a `VirtualProtectChain` variant that loads `ESI` by dereferencing a supplied cached-pointer-slot address before the existing `PUSHAD` dispatch.
- Consumes later: the runtime layout and gadget addresses supplied by instructor-only tooling; it embeds no lab-specific addresses.

- [ ] **Step 1: Write failing Python layout tests**

Add `test_dep2_layout.py` cases that assert a 268-byte saved-EIP offset yields a 280-byte first-stage prefix, that the three DWORDs are exactly `[pop_eax_ret, stage2_address, pivot]`, that later payload bytes begin at `stage2_offset` only in the staged copy, and that a status proof contains the supplied status address and success value in little-endian form.

- [ ] **Step 2: Run the new layout tests and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_dep2_layout.py'`

Expected: FAIL because `dep2_layout` does not exist.

- [ ] **Step 3: Implement the pure instructor layout builder**

Implement the four declared functions in `dep2_layout.py`. Reject negative offsets, stage-two offsets smaller than the first-stage prefix, non-DWORD addresses, and payloads above 8192 bytes. Keep the proof builder local-only and do not include host, port, or protocol code.

- [ ] **Step 4: Write failing cached-pointer planner tests**

In `Tools/rop/tests/test_rop.py`, add tests asserting `CachedVirtualProtectChain.plan()` contains, in order, `pop_eax_ret`, `cached_virtualprotect_slot`, `mov_eax_ptr_eax_ret`, `xchg_eax_esi_ret`, and then the existing `PUSHAD` setup. Assert its serialized plan does not contain `call_eax_ret` or `jmp_eax`.

- [ ] **Step 5: Implement `CachedVirtualProtectChain`**

Add `class CachedVirtualProtectChain(VirtualProtectChain)` in `Tools/rop/chain.py`. Its constructor accepts `cached_pointer_slot: int` and uses that value only through a `RawDword` following `pop_eax_ret`; replace the direct `virtualprotect_ptr` load with dereference and `EAX`-to-`ESI` transfer. Export it from `Tools/rop/__init__.py`.

- [ ] **Step 6: Implement the instructor CLI**

Implement `dep2_solution.py` with `build` and `send` subcommands. It accepts all saved-EIP offsets, stage offsets, helper RVAs/VAs, and gadget addresses explicitly; it uses `build_request(OP_ROP, payload)` from `exploit_scaffold.py` and never hardcodes a target address.

- [ ] **Step 7: Run focused tests**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_*.py'`

Run: `rtk uv run pytest Tools/rop/tests/test_rop.py -q`

Expected: all existing tests and the new layout/planner tests pass.

- [ ] **Step 8: Commit**

```bash
rtk git add Tools/rop/chain.py Tools/rop/__init__.py Tools/rop/tests/test_rop.py Experiments/Windows/osed_vuln_lab/python/dep2_layout.py Experiments/Windows/osed_vuln_lab/python/dep2_solution.py Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py
rtk git commit -m "Add instructor staged ROP chain builders"
```

### Task 2: Add DEP-2 Helper Runtime and Gadget Isolation

**Files:**
- Modify: `Experiments/Windows/osed_vuln_lab/include/osedhelper.h`
- Modify: `Experiments/Windows/osed_vuln_lab/src/osedhelper.c`
- Modify: `Experiments/Windows/osed_vuln_lab/src/osedgadgets.c`
- Modify: `Experiments/Windows/osed_vuln_lab/CMakeLists.txt`
- Modify: `Experiments/Windows/osed_vuln_lab/python/verify_binaries.py`
- Create: `Experiments/Windows/osed_vuln_lab/python/test_verify_binaries.py`

**Interfaces:**
- Produces: `int __stdcall helper_prepare_rop_runtime(void)`; resolves and caches `VirtualProtect`, returns nonzero only when initialized.
- Produces: `int __stdcall helper_stage_record(const uint8_t *data, uint32_t length)`; clears the private stage/status objects and copies one validated ROP data region, returning nonzero on success.
- Produces: PE parser method `PEFile.imports() -> dict[str, set[str]]` for import-directory assertions.
- Consumes: `OSED_STAGE_BYTES == 8192`; DEP-2 service code calls both helper APIs without receiving a stage pointer.

- [ ] **Step 1: Write failing PE import-parser tests**

Create `test_verify_binaries.py` with a minimal PE32 fixture containing one import descriptor and thunk table. Assert `PEFile.imports()` finds `KERNEL32.dll!GetProcAddress`, and a fixture containing `VirtualProtect` is distinguishable from a plain string occurrence in another section.

- [ ] **Step 2: Run import-parser tests and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_verify_binaries.py'`

Expected: FAIL because `PEFile.imports()` is absent.

- [ ] **Step 3: Implement PE import parsing and DEP-2 verification expectations**

Add `PEFile.imports()` using data-directory index 1, import descriptors, and import-by-name thunks. Add `dep2` and `aslr_dep2` expectations: require sequences 01-18 except no direct sequences 19/20; forbid `helper_memory_protect`; require `GetModuleHandleA` and `GetProcAddress` imports; reject a `VirtualProtect` import; and keep fixed versus ASLR mitigation expectations distinct.

- [ ] **Step 4: Write failing helper-runtime tests or a Windows-only probe target**

Add a Windows-only `helper_runtime_probe` target in CMake or a Python/CDB probe fixture that calls `helper_prepare_rop_runtime()` followed by `helper_stage_record()`. Assert initialization succeeds and an 8193-byte record is rejected without replacing the prior stage. Reserve proof-status reset evidence for the PDB-driven CDB verifier in Task 4, because no student-visible status getter is permitted. Mark the probe Windows-only; it is not part of `student_bundle`.

- [ ] **Step 5: Implement private stage/runtime state**

In `osedhelper.c`, add private static `uint8_t` staging storage of exactly 8192 bytes, a private cached API pointer, and a private volatile status DWORD. Implement the declared helper APIs with `GetModuleHandleA`/`GetProcAddress`, `memset`, and `memcpy`. Do not export a location getter, status getter, memory-protection wrapper, or `VirtualProtect` import.

- [ ] **Step 6: Isolate the DEP-2 gadget set**

In `osedgadgets.c`, add `OSED_PROFILE_DEP2` and `OSED_PROFILE_ASLR_DEP2` conditionals. Provide the pivot, register loads, dereference, `EAX`/`ESI` transfer, `PUSHAD`, return, `jmp esp`, and writable-slot vocabulary. Restrict `helper_sequence_19` and `helper_sequence_20` to the original `dep` and `aslr_dep` profiles only.

- [ ] **Step 7: Run Python tests and configure checks**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_*.py'`

Run: `rtk cmake -S Experiments/Windows/osed_vuln_lab -B /tmp/osed-dep2-config -DLAB_PROFILE=dep2 -DHELPER_ASLR=OFF`

Expected: import-parser tests pass; DEP-2 configuration succeeds on a non-Windows host without claiming PE/runtime validation.

- [ ] **Step 8: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/include/osedhelper.h Experiments/Windows/osed_vuln_lab/src/osedhelper.c Experiments/Windows/osed_vuln_lab/src/osedgadgets.c Experiments/Windows/osed_vuln_lab/python/verify_binaries.py Experiments/Windows/osed_vuln_lab/python/test_verify_binaries.py Experiments/Windows/osed_vuln_lab/CMakeLists.txt
rtk git commit -m "Add DEP-2 helper staging primitives"
```

### Task 3: Implement the Structural DEP-2 First Stage

**Files:**
- Modify: `Experiments/Windows/osed_vuln_lab/src/osed_vulnsvc.c`
- Modify: `Experiments/Windows/osed_vuln_lab/CMakeLists.txt`
- Modify: `Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py`

**Interfaces:**
- Produces: a `handler_rop_staged(const uint8_t *data, uint32_t length)` compiled only for `OSED_PROFILE_DEP2` and `OSED_PROFILE_ASLR_DEP2`.
- Consumes: `helper_prepare_rop_runtime()` at service startup and `helper_stage_record()` before the overflowing copy.
- Preserves: `parse_v2_record()` and `OP_ROP` dispatch unchanged.

- [ ] **Step 1: Extend layout tests for structural capacity**

Add tests that assert the source-level boundary formula is `distance_to_saved_eip + 3 * 4` and that a conventional six-DWORD `VirtualProtect` frame cannot fit in the initial controlled window. Put short-record rejection in the Windows runtime cases in Task 4, where the actual return-address distance is available.

- [ ] **Step 2: Run the extended layout tests and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_dep2_layout.py'`

Expected: FAIL until the corresponding handler constants/metadata exist.

- [ ] **Step 3: Implement profile selection and startup initialization**

Add `dep2` and `aslr_dep2` to the CMake profile list, definitions, linker flag selection, and helper-ASLR validation. In `main`, call `helper_prepare_rop_runtime()` for those profiles after `helper_probe`; return failure before listening if preparation fails.

- [ ] **Step 4: Implement `handler_rop_staged`**

Use a local `pivotbuf`, `_AddressOfReturnAddress()`, and `uintptr_t` to derive `copy_length = saved_eip_address - pivotbuf_address + 3 * sizeof(uint32_t)`. Reject `length < copy_length`, call `helper_stage_record(data, length)`, then copy exactly `copy_length` bytes into `pivotbuf`. Keep it `__declspec(noinline)`. Route only the new profiles' `OP_ROP` dispatch to this handler; preserve original `handler_rop` for `dep` and `aslr_dep`.

- [ ] **Step 5: Run source-level tests and all profile configure checks**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_*.py'`

Run configurations for `easy`, `seh`, `dep`, `dep2`, `aslr_dep`, and `aslr_dep2` in separate `/tmp` directories.

Expected: all Python tests pass; CMake generation succeeds; no non-Windows result is described as a compiled PE or runtime result.

- [ ] **Step 6: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/src/osed_vulnsvc.c Experiments/Windows/osed_vuln_lab/CMakeLists.txt Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py
rtk git commit -m "Add structural DEP-2 pivot handler"
```

### Task 4: Build the DEP-2 Windows Integration Verifier

**Files:**
- Create: `Experiments/Windows/osed_vuln_lab/python/verify_dep2_runtime.py`
- Create: `Experiments/Windows/osed_vuln_lab/python/test_verify_dep2_runtime.py`
- Create: `Experiments/Windows/osed_vuln_lab/windbg_dep2.txt`
- Create: `Experiments/Windows/osed_vuln_lab/instructor/validation/dep2-release.json`
- Modify: `Experiments/Windows/osed_vuln_lab/CMakeLists.txt`
- Modify: `Experiments/Windows/osed_vuln_lab/python/dep2_solution.py`

**Interfaces:**
- Produces: `verify_dep2_runtime.py --profile dep2 --service PATH --helper PATH --cdb PATH`, exit zero only for the intended staged path.
- Consumes: private symbols from the MSVC build PDB; it must fail clearly when CDB/PDBs are absent rather than silently skipping an explicit verification command.
- Produces: a `verify_dep2_runtime` CMake target outside the default student bundle copy.
- Produces: an instructor-only validation manifest with CMake generator/profile, MSVC toolset, architecture, compile/link flags, and SHA-256 hashes of the validated service and helper binaries.

- [ ] **Step 1: Write failing transcript-parser tests**

Create `test_verify_dep2_runtime.py` with representative CDB output. Assert the parser rejects: a missing cached pointer, a pivot whose ESP is outside `[stage_base + stage2_offset, stage_base + OSED_STAGE_BYTES)`, a first post-pivot `ret` target different from the staged chain's first DWORD, an incorrect pre-`PUSHAD` ESP, a non-executable proof page after `VirtualProtect`, and an unchanged status word.

- [ ] **Step 2: Run transcript-parser tests and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_verify_dep2_runtime.py'`

Expected: FAIL because the parser does not exist.

- [ ] **Step 3: Implement CDB transcript verification**

Implement a CDB command-file generator and parser in `verify_dep2_runtime.py`. Resolve private stage/status symbols from the local PDB, start the service, send the instructor-built request, and assert in order: cached pointer nonzero; saved-EIP/pivot values; pivot gadget reached; ESP enters the designated second-stage offset; the following `ret` consumes the expected DWORD; pre-`PUSHAD` ESP equals proof address; the API frame follows the spec; page protection changes; EIP enters the proof bytes; and status changes to the expected success value. On a passing Release Win32 run, emit the validation manifest with exact toolchain/configuration values and binary hashes.

- [ ] **Step 4: Add negative runtime cases**

Add requests for a short prefix, invalid stage address, wrong pivot register setup, malformed `PUSHAD` frame, and a direct conventional frame placed after the permitted prefix. Assert each ends in a controlled failure and no success-status transition. Send unique sentinels after the third initial DWORD and assert they never become post-EIP controlled stack data.

- [ ] **Step 5: Write the learner-facing WinDbg guide**

Create `windbg_dep2.txt` that guides breakpoint placement and evidence collection without giving offsets, RVAs, or the solution chain. Cover helper initialization, stage-copy xrefs, the first-stage return, pivot ESP transition, `VirtualProtect` arguments, and proof-status observation.

- [ ] **Step 6: Run Windows verification**

Run on the Windows x86 build host:

```bat
cmake -A Win32 -S . -B build_dep2 -DLAB_PROFILE=dep2 -DHELPER_ASLR=OFF
cmake --build build_dep2 --config Release --target verify_lab verify_dep2_runtime
```

Expected: `verify_lab` and `verify_dep2_runtime` both pass. Record the exact CDB version and build directory in the instructor verification output.

- [ ] **Step 7: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/python/verify_dep2_runtime.py Experiments/Windows/osed_vuln_lab/python/test_verify_dep2_runtime.py Experiments/Windows/osed_vuln_lab/python/dep2_solution.py Experiments/Windows/osed_vuln_lab/windbg_dep2.txt Experiments/Windows/osed_vuln_lab/instructor/validation/dep2-release.json Experiments/Windows/osed_vuln_lab/CMakeLists.txt
rtk git commit -m "Verify DEP-2 staged pivot runtime"
```

### Task 5: Derive and Verify ASLR DEP-2

**Files:**
- Modify: `Experiments/Windows/osed_vuln_lab/python/aslr_scaffold.py`
- Modify: `Experiments/Windows/osed_vuln_lab/python/dep2_solution.py`
- Modify: `Experiments/Windows/osed_vuln_lab/python/verify_dep2_runtime.py`
- Modify: `Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py`
- Modify: `Experiments/Windows/osed_vuln_lab/aslr/README.md`
- Create: `Experiments/Windows/osed_vuln_lab/windbg_aslr_dep2.txt`

**Interfaces:**
- Produces: `dep2_solution.derive_runtime_layout(leak: int, anchor_rva: int, layout_rvas: dict[str, int]) -> Dep2RuntimeLayout`.
- Consumes: existing binary leak parser in `aslr_scaffold.py`; no extra network command.
- Preserves: the same staged-handler code path and the same v2 `OP_ROP` data layout as `dep2`.

- [ ] **Step 1: Write failing ASLR layout tests**

Add tests for `derive_runtime_layout` that use two distinct helper bases and one common RVA map. Assert every derived stage, cached-slot, status, and gadget VA differs by the base delta, while the serialized chain shape remains identical. Add a provenance test that starts from the encoded existing-leak response, subtracts the independently recovered anchor RVA, and rejects a serialized chain derived from a hardcoded or prior-run base.

- [ ] **Step 2: Run the tests and verify failure**

Run: `rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_dep2_layout.py'`

Expected: FAIL because `derive_runtime_layout` is absent.

- [ ] **Step 3: Implement ASLR layout derivation and scaffolding**

Implement `Dep2RuntimeLayout` and `derive_runtime_layout`; extend the instructor scaffold only with post-discovery address arithmetic and no RVAs. Do not change the leak request or `OP_ROP` wire grammar.

- [ ] **Step 4: Extend the runtime verifier for two launches**

For `--profile aslr_dep2`, launch the service twice, obtain a fresh leak each time, assert the leaked address equals that process's helper base plus the known anchor RVA, derive the current base from the leak, rebuild the staged request from current RVAs, and require both successful proof-status transitions. Add a stale-base and hardcoded-base negative request and assert neither can produce the success status.

- [ ] **Step 5: Add ASLR DEP-2 WinDbg guidance**

Create `windbg_aslr_dep2.txt` covering fresh leaks, module-base/RVA equations, staged address derivation, pivot observations, and the same `PUSHAD` evidence as DEP-2. Exclude concrete current-build addresses.

- [ ] **Step 6: Run Windows verification**

Run on the Windows x86 build host:

```bat
cmake -A Win32 -S . -B build_aslr_dep2 -DLAB_PROFILE=aslr_dep2 -DHELPER_ASLR=ON
cmake --build build_aslr_dep2 --config Release --target verify_lab verify_dep2_runtime
```

Expected: both fresh-launch runs pass with distinct helper bases; the stale-base negative case fails without a proof-status transition.

- [ ] **Step 7: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/python/aslr_scaffold.py Experiments/Windows/osed_vuln_lab/python/dep2_solution.py Experiments/Windows/osed_vuln_lab/python/verify_dep2_runtime.py Experiments/Windows/osed_vuln_lab/python/test_dep2_layout.py Experiments/Windows/osed_vuln_lab/aslr/README.md Experiments/Windows/osed_vuln_lab/windbg_aslr_dep2.txt
rtk git commit -m "Add ASLR DEP-2 staged ROP lab"
```

### Task 6: Document the Staged DEP Progression and Final Gate

**Files:**
- Modify: `Experiments/Windows/osed_vuln_lab/README.md`
- Modify: `Experiments/Windows/osed_vuln_lab/training_path.md`
- Modify: `Experiments/Windows/osed_vuln_lab/instructor/profile_matrix.md`
- Modify: `Experiments/Windows/osed_vuln_lab/instructor/protocol_reference.md`
- Modify: `Experiments/Windows/osed_vuln_lab/CHANGELOG.md`
- Modify: `Experiments/Windows/osed_vuln_lab/student/START_HERE.md`
- Create: `Experiments/Windows/osed_vuln_lab/python/test_student_bundle.py`

**Interfaces:**
- Produces: profile/build documentation that names `dep2` and `aslr_dep2` while preserving the student/instructor boundary.
- Preserves: student materials reveal no target-specific RVA, saved-EIP offset, staging location, chain order, or instructor test artifact.

- [ ] **Step 1: Write documentation-boundary tests**

Add `test_student_bundle.py`, a Windows-only Python test that builds `student_bundle` and asserts it contains only the service, helper, `START_HERE.md`, and `protocol_notes.md`, and excludes `dep2_solution.py`, runtime verifier files, PDBs, map files, build logs, generated manifests, and packaged source artifacts. The test must report a clear skip only on hosts that cannot run the configured Win32 MSVC toolchain.

- [ ] **Step 2: Update instructor and student documentation**

Add the DEP-2 progression to the README, profile matrix, training path, changelog, and instructor reference. Update the student brief only to state that later profiles may require staged control flow and independent evidence for a pivot; do not document chain structure or addresses.

- [ ] **Step 3: Run final verification**

Run:

```bash
rtk python3 -m unittest discover -s Experiments/Windows/osed_vuln_lab/python -p 'test_*.py'
rtk uv run pytest Tools/rop/tests/test_rop.py -q
rtk git diff --check
```

Run all six CMake configure checks on the development host. On the Windows x86 host, run `verify_lab` plus `verify_dep2_runtime` for `dep2` and `aslr_dep2`.

Expected: all local/static checks pass; Windows runtime verification is explicitly reported as pass or not run, never inferred from macOS configuration.

- [ ] **Step 4: Commit**

```bash
rtk git add Experiments/Windows/osed_vuln_lab/README.md Experiments/Windows/osed_vuln_lab/training_path.md Experiments/Windows/osed_vuln_lab/instructor/profile_matrix.md Experiments/Windows/osed_vuln_lab/instructor/protocol_reference.md Experiments/Windows/osed_vuln_lab/CHANGELOG.md Experiments/Windows/osed_vuln_lab/student/START_HERE.md Experiments/Windows/osed_vuln_lab/python/test_student_bundle.py
rtk git commit -m "Document DEP-2 lab progression"
```
