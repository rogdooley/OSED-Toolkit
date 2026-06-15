"""Tests for the stack slot allocator (Phase 2)."""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def revshell_layout(manifest_dir):
    from Tools.emitter.schema import load
    from Tools.emitter.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return build_layout(manifest)


@pytest.fixture
def calc_layout(manifest_dir):
    from Tools.emitter.schema import load
    from Tools.emitter.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    return build_layout(manifest)


# ---------------------------------------------------------------------------
# Module-base offset assertions
# ---------------------------------------------------------------------------

def test_module_base_offsets(revshell_layout):
    assert revshell_layout.slot("kernel32.dll").offset == 0x20
    assert revshell_layout.slot("ws2_32.dll").offset == 0x24


# ---------------------------------------------------------------------------
# API slot offset assertions
# revshell.yaml declares 8 functions in order:
#   CreateProcessA, LoadLibraryA, GetProcAddress, ExitProcess, WinExec,
#   WSAStartup, WSASocketA, connect
# Module bases occupy 0x20 and 0x24 (2 slots), so API slots start at 0x28.
# ---------------------------------------------------------------------------

def test_api_slot_offsets(revshell_layout):
    assert revshell_layout.slot("CreateProcessA").offset == 0x28
    assert revshell_layout.slot("LoadLibraryA").offset == 0x2c
    assert revshell_layout.slot("GetProcAddress").offset == 0x30
    assert revshell_layout.slot("ExitProcess").offset == 0x34
    assert revshell_layout.slot("WinExec").offset == 0x38
    assert revshell_layout.slot("WSAStartup").offset == 0x3c
    assert revshell_layout.slot("WSASocketA").offset == 0x40
    assert revshell_layout.slot("connect").offset == 0x44


# ---------------------------------------------------------------------------
# Struct size assertions
# ---------------------------------------------------------------------------

def test_struct_sizes(revshell_layout):
    assert revshell_layout.slot("STARTUPINFOA").size == 0x44
    assert revshell_layout.slot("PROCESS_INFORMATION").size == 0x10
    assert revshell_layout.slot("WSADATA").size == 0x190
    assert revshell_layout.slot("sockaddr_in").size == 0x10


# ---------------------------------------------------------------------------
# Struct zone starts at hard constant 0x80
# ---------------------------------------------------------------------------

def test_struct_zone_starts_at_0x80(revshell_layout):
    assert revshell_layout.slot("STARTUPINFOA").offset == 0x80


# ---------------------------------------------------------------------------
# Category assertions
# ---------------------------------------------------------------------------

def test_slot_categories(revshell_layout):
    assert revshell_layout.slot("kernel32.dll").category == "module_base"
    assert revshell_layout.slot("ws2_32.dll").category == "module_base"
    assert revshell_layout.slot("CreateProcessA").category == "api"
    assert revshell_layout.slot("STARTUPINFOA").category == "structure"
    assert revshell_layout.slot("WSADATA").category == "structure"


def test_slots_by_category_module_base(revshell_layout):
    bases = revshell_layout.slots_by_category("module_base")
    names = [s.name for s in bases]
    assert names == ["kernel32.dll", "ws2_32.dll"]


def test_slots_by_category_api(revshell_layout):
    apis = revshell_layout.slots_by_category("api")
    names = [s.name for s in apis]
    assert names == [
        "CreateProcessA", "LoadLibraryA", "GetProcAddress", "ExitProcess",
        "WinExec", "WSAStartup", "WSASocketA", "connect",
    ]


# ---------------------------------------------------------------------------
# No overlap
# ---------------------------------------------------------------------------

def test_no_slot_overlap(revshell_layout):
    all_slots = revshell_layout.all_slots()
    # Build set of all occupied bytes; no byte should appear twice
    occupied: set[int] = set()
    for slot in all_slots:
        for byte_offset in range(slot.offset, slot.offset + slot.size):
            assert byte_offset not in occupied, (
                f"Slot '{slot.name}' overlaps at offset 0x{byte_offset:02x}"
            )
            occupied.add(byte_offset)


def test_struct_zone_does_not_overlap_api_zone(revshell_layout):
    api_slots = revshell_layout.slots_by_category("api")
    struct_slots = revshell_layout.slots_by_category("structure")
    if api_slots and struct_slots:
        last_api_end = max(s.offset + s.size for s in api_slots)
        first_struct_start = min(s.offset for s in struct_slots)
        assert last_api_end <= first_struct_start


# ---------------------------------------------------------------------------
# ebp_ref format
# ---------------------------------------------------------------------------

def test_ebp_ref_format(revshell_layout):
    assert revshell_layout.slot("CreateProcessA").ebp_ref == "[ebp-0x28]"
    assert revshell_layout.slot("kernel32.dll").ebp_ref == "[ebp-0x20]"


# ---------------------------------------------------------------------------
# String sizing
# ---------------------------------------------------------------------------

def test_string_slot_label(revshell_layout):
    slot = revshell_layout.slot("cmd")
    assert slot.category == "string"
    # "cmd.exe" = 7 chars + 1 null = 8 bytes -> padded to 8 (already aligned)
    assert slot.size == 8


def test_string_slot_follows_struct_zone(revshell_layout):
    struct_slots = revshell_layout.slots_by_category("structure")
    string_slots = revshell_layout.slots_by_category("string")
    if struct_slots and string_slots:
        last_struct_end = max(s.offset + s.size for s in struct_slots)
        first_string_start = min(s.offset for s in string_slots)
        assert first_string_start >= last_struct_end


# ---------------------------------------------------------------------------
# Unknown slot raises
# ---------------------------------------------------------------------------

def test_unknown_slot_raises(revshell_layout):
    with pytest.raises(KeyError):
        revshell_layout.slot("NotARealSlot")


# ---------------------------------------------------------------------------
# Minimal (calc) manifest
# ---------------------------------------------------------------------------

def test_calc_layout_minimal(calc_layout):
    # calc.yaml has only WinExec, ExitProcess (both kernel32)
    assert calc_layout.slot("kernel32.dll").offset == 0x20
    # No ws2_32 module base
    with pytest.raises(KeyError):
        calc_layout.slot("ws2_32.dll")
    assert calc_layout.slot("WinExec").offset == 0x24
    assert calc_layout.slot("ExitProcess").offset == 0x28
    # No WSA structs
    with pytest.raises(KeyError):
        calc_layout.slot("WSADATA")


def test_calc_layout_only_one_module_base(calc_layout):
    bases = calc_layout.slots_by_category("module_base")
    assert len(bases) == 1
    assert bases[0].name == "kernel32.dll"
