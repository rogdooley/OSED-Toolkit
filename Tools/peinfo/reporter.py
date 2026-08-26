"""
Terminal reporter for PE analysis results.

Uses rich for formatted output, with a plain-text fallback.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import PEReport

YES = "[green]Yes[/green]"
NO = "[red]No[/red]"
UNKNOWN = "[yellow]Unknown[/yellow]"


def bool_indicator(val: Optional[bool], invert: bool = False) -> str:
    if val is None:
        return UNKNOWN
    if invert:
        val = not val
    return YES if val else NO


def format_report(report: PEReport, console: Optional[Console] = None) -> None:
    if console is None:
        console = Console()

    _print_header(console, report)
    _print_mitigations(console, report)
    _print_memory_layout(console, report)
    _print_sections(console, report)
    _print_imports(console, report)
    _print_categorized_imports(console, report)
    _print_interesting_strings(console, report)
    _print_version_info(console, report)
    _print_gadgets(console, report)
    _print_exploitability(console, report)


def _print_header(console: Console, report: PEReport) -> None:
    fi = report.file_info
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=22)
    table.add_column()

    table.add_row("File", fi.path)
    table.add_row("Size", f"{fi.size:,} bytes")
    table.add_row("Machine", fi.machine)
    table.add_row("Subsystem", fi.subsystem)
    table.add_row("Compiler Timestamp", fi.timestamp)
    table.add_row("Linker Version", fi.linker_version)
    table.add_row("Checksum", f"0x{fi.checksum:08X}")
    table.add_row("Characteristics", f"0x{fi.characteristics:04X}")

    console.print(Panel(table, title="[bold]PE Information[/bold]",
                        border_style="blue"))


def _print_mitigations(console: Console, report: PEReport) -> None:
    mit = report.mitigations
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=22)
    table.add_column()

    dc_val = (
        (0x0100 if mit.nx_compat else 0)
        | (0x0040 if mit.dynamic_base else 0)
        | (0x0020 if mit.high_entropy_va else 0)
        | (0x0080 if mit.force_integrity else 0)
        | (0x0400 if mit.no_seh else 0)
        | (0x0800 if mit.no_bind else 0)
        | (0x1000 if mit.app_container else 0)
        | (0x4000 if mit.guard_cf else 0)
        | (0x8000 if mit.terminal_server_aware else 0)
        | (0x0200 if mit.no_isolation else 0)
    )
    table.add_row("DllCharacteristics", f"0x{dc_val:04X}")
    table.add_row("")
    table.add_row("NX_COMPAT", bool_indicator(mit.nx_compat))
    table.add_row("DYNAMIC_BASE (ASLR)", bool_indicator(mit.dynamic_base))
    table.add_row("HIGH_ENTROPY_VA", bool_indicator(mit.high_entropy_va))
    table.add_row("FORCE_INTEGRITY", bool_indicator(mit.force_integrity))
    table.add_row("NO_SEH", bool_indicator(mit.no_seh))
    table.add_row("GUARD_CF (CFG)", bool_indicator(mit.guard_cf))
    table.add_row("TERMINAL_SERVER_AWARE",
                  bool_indicator(mit.terminal_server_aware))
    table.add_row("APP_CONTAINER", bool_indicator(mit.app_container))
    table.add_row("NO_BIND", bool_indicator(mit.no_bind))
    table.add_row("NO_ISOLATION", bool_indicator(mit.no_isolation))
    table.add_row("")
    table.add_row("Relocations Present", bool_indicator(mit.relocations_present))
    table.add_row("GS Security Cookie", bool_indicator(mit.gs_cookie))

    if mit.no_seh:
        table.add_row("SafeSEH", "[dim]N/A (NO_SEH set)[/dim]")
    else:
        table.add_row("SafeSEH", bool_indicator(mit.safeseh))

    console.print(Panel(table, title="[bold]PE Mitigations[/bold]",
                        subtitle="[dim]compile-time / static only[/dim]",
                        border_style="blue"))


def _print_memory_layout(console: Console, report: PEReport) -> None:
    ml = report.memory_layout
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=22)
    table.add_column()

    table.add_row("Image Base", f"0x{ml['image_base']:08X}")
    table.add_row("Entry Point", f"0x{ml['entry_point']:08X}")
    table.add_row("Image Size", f"0x{ml['image_size']:X}")
    table.add_row("Section Alignment", f"0x{ml['section_alignment']:X}")
    table.add_row("File Alignment", f"0x{ml['file_alignment']:X}")
    table.add_row("Stack Reserve", f"0x{ml['stack_reserve']:X}")
    table.add_row("Stack Commit", f"0x{ml['stack_commit']:X}")
    table.add_row("Heap Reserve", f"0x{ml['heap_reserve']:X}")
    table.add_row("Heap Commit", f"0x{ml['heap_commit']:X}")

    console.print(Panel(table, title="[bold]Memory Layout[/bold]",
                        border_style="blue"))


def _print_sections(console: Console, report: PEReport) -> None:
    table = Table(box=None, padding=(0, 1))
    table.add_column("Name", style="bold")
    table.add_column("VirtAddr", justify="right")
    table.add_column("VirtSize", justify="right")
    table.add_column("RawOff", justify="right")
    table.add_column("RawSize", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Perms")

    for s in report.sections:
        perms = ""
        perms += "R" if s.readable else "-"
        perms += "W" if s.writable else "-"
        perms += "X" if s.executable else "-"

        entropy_style = ""
        if s.entropy > 7.0:
            entropy_style = "bold red"
        elif s.entropy > 6.5:
            entropy_style = "yellow"

        table.add_row(
            s.name,
            f"0x{s.virtual_address:08X}",
            f"0x{s.virtual_size:X}",
            f"0x{s.raw_offset:08X}",
            f"0x{s.raw_size:X}",
            Text(f"{s.entropy:.2f}", style=entropy_style),
            perms,
        )

    has_reloc = any(s.name == ".reloc" for s in report.sections)
    subtitle = None
    if not has_reloc:
        subtitle = "[bold red].reloc section missing[/bold red]"

    console.print(Panel(table, title="[bold]Sections[/bold]",
                        subtitle=subtitle, border_style="blue"))


def _print_imports(console: Console, report: PEReport) -> None:
    if not report.imports:
        return

    dll_names = [e.dll for e in report.imports]
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column(justify="right", style="dim")

    for entry in report.imports:
        table.add_row(entry.dll, f"{len(entry.functions)} functions")

    console.print(Panel(table, title="[bold]Imported DLLs[/bold]",
                        border_style="blue"))


def _print_categorized_imports(console: Console, report: PEReport) -> None:
    cat = report.categorized_imports
    categories = [
        ("Exploitation APIs", cat.exploitation),
        ("Dangerous CRT", cat.dangerous_crt),
        ("Networking", cat.networking),
        ("Registry", cat.registry),
        ("Process", cat.process),
        ("Crypto", cat.crypto),
        ("File I/O", cat.file_io),
    ]

    has_any = any(funcs for _, funcs in categories)
    if not has_any:
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=18)
    table.add_column()

    for label, funcs in categories:
        if funcs:
            table.add_row(label, ", ".join(funcs))

    console.print(Panel(table, title="[bold]Interesting APIs[/bold]",
                        border_style="blue"))


def _print_interesting_strings(console: Console, report: PEReport) -> None:
    if not report.interesting_strings:
        return

    lines = "\n".join(f"  {s}" for s in report.interesting_strings[:50])
    if len(report.interesting_strings) > 50:
        lines += f"\n  ... and {len(report.interesting_strings) - 50} more"

    console.print(Panel(lines,
                        title="[bold]Interesting Strings[/bold]",
                        border_style="blue"))


def _print_version_info(console: Console, report: PEReport) -> None:
    vi = report.version_info
    if vi is None:
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=22)
    table.add_column()

    if vi.company:
        table.add_row("Company", vi.company)
    if vi.product:
        table.add_row("Product", vi.product)
    if vi.version:
        table.add_row("Version", vi.version)
    if vi.description:
        table.add_row("Description", vi.description)
    if vi.copyright:
        table.add_row("Copyright", vi.copyright)
    if vi.original_filename:
        table.add_row("Original Filename", vi.original_filename)

    console.print(Panel(table, title="[bold]Version Resources[/bold]",
                        border_style="blue"))


def _print_gadgets(console: Console, report: PEReport) -> None:
    gc = report.gadget_counts
    if gc.ret == 0 and gc.jmp_esp == 0:
        console.print(Panel("[dim]No gadget data (non-x86 or no executable sections)[/dim]",
                            title="[bold]Gadget Pre-Enumeration[/bold]",
                            border_style="blue"))
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", min_width=22)
    table.add_column(justify="right")

    gadget_rows = [
        ("RET", gc.ret),
        ("POP r32; RET", gc.pop_ret),
        ("POP r32; POP r32; RET", gc.pop_pop_ret),
        ("JMP ESP", gc.jmp_esp),
        ("CALL ESP", gc.call_esp),
        ("CALL EAX", gc.call_eax),
        ("CALL ECX", gc.call_ecx),
        ("CALL EDX", gc.call_edx),
        ("CALL EBX", gc.call_ebx),
        ("CALL ESI", gc.call_esi),
        ("CALL EDI", gc.call_edi),
        ("CALL EBP", gc.call_ebp),
        ("PUSH ESP; RET", gc.push_esp_ret),
        ("PUSHAD; RET", gc.pushad_ret),
        ("XCHG EAX, ESP; RET", gc.xchg_eax_esp_ret),
        ("ADD ESP, imm; RET", gc.add_esp_ret),
    ]

    for label, count in gadget_rows:
        style = ""
        if count > 0 and label in ("JMP ESP", "CALL ESP", "PUSH ESP; RET"):
            style = "bold green"
        table.add_row(label, Text(str(count), style=style))

    console.print(Panel(table, title="[bold]Gadget Pre-Enumeration[/bold]",
                        subtitle="[dim]byte-pattern matches in executable sections[/dim]",
                        border_style="blue"))


def _print_exploitability(console: Console, report: PEReport) -> None:
    ex = report.exploitability
    if ex.rop_candidate:
        verdict = "[bold green]YES[/bold green]"
    else:
        verdict = "[bold red]NO[/bold red]"

    lines: list[str] = []
    lines.append(f"  Excellent ROP Candidate: {verdict}")
    lines.append("")

    if ex.reasons:
        lines.append("  [bold]Favorable:[/bold]")
        for r in ex.reasons:
            lines.append(f"    [green]*[/green] {r}")

    if ex.warnings:
        lines.append("")
        lines.append("  [bold]Obstacles:[/bold]")
        for w in ex.warnings:
            lines.append(f"    [red]*[/red] {w}")

    console.print(Panel(
        "\n".join(lines),
        title="[bold]Exploitability Summary[/bold]",
        subtitle="[dim]static analysis only -- runtime mitigations may differ[/dim]",
        border_style="yellow",
    ))


def format_plain(report: PEReport) -> str:
    """Produce a plain-text report without rich markup."""
    lines: list[str] = []

    def hr(title: str) -> None:
        lines.append("")
        lines.append("=" * 60)
        lines.append(f"  {title}")
        lines.append("=" * 60)

    def row(label: str, value: str) -> None:
        lines.append(f"  {label:<24s} {value}")

    def yn(val: Optional[bool], invert: bool = False) -> str:
        if val is None:
            return "Unknown"
        if invert:
            val = not val
        return "Yes" if val else "No"

    fi = report.file_info
    hr("PE Information")
    row("File", fi.path)
    row("Size", f"{fi.size:,} bytes")
    row("Machine", fi.machine)
    row("Subsystem", fi.subsystem)
    row("Compiler Timestamp", fi.timestamp)
    row("Linker Version", fi.linker_version)

    mit = report.mitigations
    hr("PE Mitigations (static)")
    row("NX_COMPAT", yn(mit.nx_compat))
    row("DYNAMIC_BASE (ASLR)", yn(mit.dynamic_base))
    row("HIGH_ENTROPY_VA", yn(mit.high_entropy_va))
    row("GUARD_CF (CFG)", yn(mit.guard_cf))
    row("NO_SEH", yn(mit.no_seh))
    row("SafeSEH", yn(mit.safeseh) if not mit.no_seh else "N/A")
    row("Relocations Present", yn(mit.relocations_present))
    row("GS Security Cookie", yn(mit.gs_cookie))

    ml = report.memory_layout
    hr("Memory Layout")
    row("Image Base", f"0x{ml['image_base']:08X}")
    row("Entry Point", f"0x{ml['entry_point']:08X}")
    row("Image Size", f"0x{ml['image_size']:X}")
    row("Section Alignment", f"0x{ml['section_alignment']:X}")
    row("File Alignment", f"0x{ml['file_alignment']:X}")

    hr("Sections")
    lines.append(f"  {'Name':<10s} {'VirtAddr':>10s} {'VirtSize':>10s} "
                 f"{'RawSize':>10s} {'Entropy':>8s} {'Perms'}")
    for s in report.sections:
        perms = ("R" if s.readable else "-") + \
                ("W" if s.writable else "-") + \
                ("X" if s.executable else "-")
        lines.append(
            f"  {s.name:<10s} 0x{s.virtual_address:08X} "
            f"0x{s.virtual_size:>8X} 0x{s.raw_size:>8X} "
            f"{s.entropy:>8.2f} {perms}"
        )

    if report.imports:
        hr("Imported DLLs")
        for entry in report.imports:
            lines.append(f"  {entry.dll} ({len(entry.functions)} functions)")

    cat = report.categorized_imports
    categories = [
        ("Exploitation APIs", cat.exploitation),
        ("Dangerous CRT", cat.dangerous_crt),
        ("Networking", cat.networking),
    ]
    has_cat = any(f for _, f in categories)
    if has_cat:
        hr("Interesting APIs")
        for label, funcs in categories:
            if funcs:
                row(label, ", ".join(funcs))

    gc = report.gadget_counts
    if gc.ret > 0:
        hr("Gadget Pre-Enumeration")
        for label, count in [
            ("RET", gc.ret), ("POP r32; RET", gc.pop_ret),
            ("POP POP RET", gc.pop_pop_ret),
            ("JMP ESP", gc.jmp_esp), ("CALL ESP", gc.call_esp),
        ]:
            row(label, str(count))

    ex = report.exploitability
    hr("Exploitability Summary")
    lines.append(f"  ROP Candidate: {'YES' if ex.rop_candidate else 'NO'}")
    for r in ex.reasons:
        lines.append(f"    + {r}")
    for w in ex.warnings:
        lines.append(f"    - {w}")

    lines.append("")
    return "\n".join(lines)
