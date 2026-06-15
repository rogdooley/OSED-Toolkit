"""API resolution stub emitter for the shellcode emitter toolkit.

Generates the three-instruction per-function block that resolves Win32 API
addresses by ROR13 export hash and stores each pointer to its stack slot.
"""
from __future__ import annotations

from .api_database import API_DATABASE, MODULE_LOAD_ORDER
from .hash_gen import ror13
from .schema import Manifest
from .stack_alloc import StackLayout

_TOTAL_COLS = 68
_HEADER_PREFIX = "; ── "  # '; ── '


def _module_header(dll: str, load_via: str) -> str:
    """Return the section comment header line for a module, filled to _TOTAL_COLS."""
    body = f"{_HEADER_PREFIX}{dll} ({load_via}) "
    fill = _TOTAL_COLS - len(body)
    if fill < 0:
        fill = 0
    return body + "─" * fill


def emit_api_resolution(manifest: Manifest, layout: StackLayout) -> str:
    """Generate API resolution stubs for every function in the manifest.

    Output is grouped by module in MODULE_LOAD_ORDER sequence.
    Per function, emits exactly three instructions preceded by a comment.
    Returns a single string of assembly text.
    """
    # Build a lookup: dll -> list of function names in manifest declaration order
    module_funcs: dict[str, list[str]] = {}
    for name in manifest.functions:
        dll = API_DATABASE[name].module
        module_funcs.setdefault(dll, []).append(name)

    lines: list[str] = []

    for mi in MODULE_LOAD_ORDER:
        dll = mi.dll
        if dll not in module_funcs:
            continue

        # Section header
        lines.append(_module_header(dll, mi.load_via))
        lines.append("")

        funcs = module_funcs[dll]
        for name in funcs:
            slot = layout.slot(name)
            hash_val = ror13(name)
            ebp_ref = slot.ebp_ref  # e.g. '[ebp-0x28]'

            lines.append(f"    ; {name}  {ebp_ref}")
            lines.append(f"    mov  eax, 0x{hash_val:08x}")
            lines.append(f"    call resolve_export_by_hash")
            lines.append(f"    mov  {ebp_ref}, eax")
            lines.append("")

    # Ensure exactly one trailing newline at end
    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")

    return "\n".join(lines)


def emit_module_resolution(manifest: Manifest, layout: StackLayout, dll: str) -> str:
    """Emit resolution stubs for functions belonging to `dll` only.

    Returns empty string if no manifest functions belong to this dll.
    Used by build.py to interleave module-loading code between resolution blocks.
    """
    module_funcs = [n for n in manifest.functions if API_DATABASE[n].module == dll]
    if not module_funcs:
        return ""

    mi = next(m for m in MODULE_LOAD_ORDER if m.dll == dll)
    lines: list[str] = []
    lines.append(_module_header(dll, mi.load_via))
    lines.append("")

    for name in module_funcs:
        slot = layout.slot(name)
        hash_val = ror13(name)
        ebp_ref = slot.ebp_ref
        lines.append(f"    ; {name}  {ebp_ref}")
        lines.append(f"    mov  eax, 0x{hash_val:08x}")
        lines.append(f"    call resolve_export_by_hash")
        lines.append(f"    mov  {ebp_ref}, eax")
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")

    return "\n".join(lines)
