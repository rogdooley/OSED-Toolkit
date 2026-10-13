# Future Directions

Ideas for post-exam development. None of these are needed for OSED prep;
the current x86 template set covers the exam payload surface.

## Primitive + Profile Architecture

Two-layer emitter expansion:

- **Primitives**: small, inspectable building blocks wrapping one or two
  Windows API calls with explicit precondition/postcondition contracts.
  Examples: `check_path` (GetFileAttributesA), `resolve_api`
  (GetProcAddress), `alloc_rwx` (VirtualAlloc), `write_file`
  (CreateFileA + WriteFile), `connect_tcp` (WSASocketA + connect),
  `read_registry` (RegOpenKeyExA + RegQueryValueExA).
- **Profiles**: sequences of primitives with explicit inputs, expected
  results, and verification points at each step. Enable composed
  payloads that can be debugged stage-by-stage in WinDbg.

First primitive to prototype the pattern: `check_path` built around
`GetFileAttributesA`, returning deterministic status for present,
missing, or error paths. Non-destructive, establishes the observable
contract that composed profiles would need.

## PE Loader

Reflective PE loader in shellcode -- load a full PE from memory without
touching disk. Steps: parse PE headers, allocate image, copy sections,
process relocations, resolve imports, call entry point. Significantly
more complex than current templates; would benefit from the primitive
architecture (each step is its own testable unit).

## COFF Loader

Load and execute COFF (Common Object File Format) objects in memory.
Used by C2 frameworks for running Beacon Object Files (BOFs). Parse
COFF headers, resolve relocations, handle external symbol resolution
against the Win32 API. Lighter weight than full PE loading.

## Multi-Architecture Support

### Architecture layer design

The Arch abstraction owns full ABI state, not just instruction emission:

- **Calling convention**: argument register assignment (x86 stdcall
  pushes; x64 uses rcx/rdx/r8/r9 + 32-byte shadow space; ARM64 uses
  x0-x7), stack vs register boundary, return value register.
- **Frame discipline**: 16-byte call-site alignment on x64, volatile vs
  nonvolatile register sets, pointer-width slot sizing for the stack
  allocator. `ptr_size` alone is insufficient.
- **PEB resolver**: arch-specific PEB walk (FS:[0x30] vs GS:[0x60] vs
  TEB via x18) and structure offsets. ROR-13 hash values do NOT change
  across architectures -- the algorithm hashes the same ASCII export
  names the same way. Only the resolver implementation and PEB offsets
  change.
- **Badchar encoding**: pointer-width encoding (dword vs qword), but
  the encoding strategy (complement/add, sub/neg, etc.) is shared.

The template-facing interface is a **call/argument IR**, not generic
register operations. Templates describe intent:

    arch.call(slot("OpenProcess"), [
        Arg.slot("target_pid"),
        Arg.zero(),
        Arg.imm(0x001F0FFF),
    ], badchars)
    arch.test_result()
    arch.branch_zero("done")
    arch.store_result(slot("proc_handle"), badchars)

The Arch backend lowers this to architecture-specific assembly.
Templates must not gradually become x64-aware through exposed register
operations -- the IR is the boundary.

Shared across architectures:
- Manifests (YAML schema)
- API database (names, argument semantics; add per-arch availability
  and pointer-sized type metadata where implementations differ)
- Build pipeline orchestration
- CLI
- Badchar encoding strategy

### Implementation roadmap

**Phase 1: x64 proof-of-concept**

Build one deliberately small Windows x64 PoC (e.g. WinExec("calc.exe"))
end-to-end before migrating any template. This proves:
- x64 PEB walk and API resolver
- ms64 calling convention emission
- Call-frame alignment correctness
- Encoded-byte validation on x64 instruction stream
- Runtime debugging workflow on x64 Windows

**Phase 2: shared call/argument IR**

Define the Arch base class and implement X86Arch that produces
byte-identical output to the current code. "Byte-identical assembled
output" for a migrated x86 template is the gate -- followed by
assembled-byte comparison and Windows runtime checks. Current x86
output must be preserved exactly; the IR is additive.

**Phase 3: incremental template ports**

Migrate templates one at a time against the IR, starting with the
simplest (registry_persist). Each migration: verify x86 byte-identical
output, then verify x64 output assembles and runs on x64 Windows.

**Phase 4: ARM64**

Port to AArch64 / Windows on ARM after x64 proves the abstraction:
- ARM64 calling convention (x0-x7 args, x8 indirect result)
- Fixed 4-byte instruction encoding
- PEB access via TEB (x18 register)
- Growing target surface with Snapdragon X laptops

### Non-goals during exam prep

Do not migrate any x86 templates or introduce the Arch layer before the
exam. The current x86 workflow is stable and tested; the architecture
work starts afterward.
