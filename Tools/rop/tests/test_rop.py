"""
Unit tests for Tools.rop — all gadget addresses are fake.

No real binary gadgets, no network, no file I/O (except the from_file test
which uses tmp_path).  Every address is chosen to be null-free so the full
VirtualProtect chain passes null-byte bad-char checks.
"""

from __future__ import annotations

import json
import struct

import pytest

from Tools.rop.chain import RopChain, VirtualProtectChain, VIRTUALPROTECT_REQUIRED_GADGETS
from Tools.rop.gadget_db import GadgetDB, GadgetDBError
from Tools.rop.models import (
    GadgetRef,
    PaddingBlock,
    RawDword,
    ShellcodePtr,
    ValidationIssue,
    WritablePtr,
)
from Tools.rop.printer import DryRunPrinter
from Tools.rop.serializer import ChainSerializer, SerializationError
from Tools.rop.validator import ChainValidator


# ── Fake gadget database ──────────────────────────────────────────────────────
#
# Addresses chosen to be:
#   - Non-zero
#   - No null bytes (valid for b"\x00" bad-char checks)
#   - Distinct (catches accidental cross-lookup)

FAKE_GADGETS: dict[str, dict] = {
    # All addresses use 0x41414141-range so every byte is 0x41-0x4d (no null bytes).
    "pop_edi_ret":        {"address": "0x41414141", "module": "fake.dll", "instruction": "pop edi; ret"},
    "ptr_to_ret":         {"address": "0x41414142", "module": "fake.dll", "instruction": "ret"},
    "pop_esi_ret":        {"address": "0x41414143", "module": "fake.dll", "instruction": "pop esi; ret"},
    "virtualprotect_ptr": {"address": "0x41414144", "module": "fake.dll", "instruction": "IAT VirtualProtect"},
    "pop_ebp_ret":        {"address": "0x41414145", "module": "fake.dll", "instruction": "pop ebp; ret"},
    "jmp_esp":            {"address": "0x41414146", "module": "fake.dll", "instruction": "jmp esp"},
    "pop_eax_ret":        {"address": "0x41414147", "module": "fake.dll", "instruction": "pop eax; ret"},
    "neg_eax_ret":        {"address": "0x41414148", "module": "fake.dll", "instruction": "neg eax; ret"},
    "xchg_eax_ebx_ret":   {"address": "0x41414149", "module": "fake.dll", "instruction": "xchg eax, ebx; ret"},
    "pop_edx_ret":        {"address": "0x4141414a", "module": "fake.dll", "instruction": "pop edx; ret"},
    "pop_ecx_ret":        {"address": "0x4141414b", "module": "fake.dll", "instruction": "pop ecx; ret"},
    "pushad_ret":         {"address": "0x4141414c", "module": "fake.dll", "instruction": "pushad; ret"},
    "writable_ptr":       {"address": "0x4141414d", "module": "fake.dll", "instruction": "(writable static)"},
}


def make_db(extra: dict[str, dict] | None = None) -> GadgetDB:
    data = dict(FAKE_GADGETS)
    if extra:
        data.update(extra)
    return GadgetDB.from_dict(data)


# ── GadgetDB ──────────────────────────────────────────────────────────────────


class TestGadgetDB:
    def test_loads_from_dict(self) -> None:
        db = make_db()
        assert len(db) == len(FAKE_GADGETS)

    def test_get_known_gadget_attributes(self) -> None:
        db = make_db()
        g = db.get("pop_eax_ret")
        assert g.address == 0x41414147
        assert g.module == "fake.dll"
        assert "pop eax" in g.instruction

    def test_get_missing_raises(self) -> None:
        db = make_db()
        with pytest.raises(GadgetDBError, match="not found"):
            db.get("nonexistent")

    def test_contains_known(self) -> None:
        assert make_db().contains("pop_eax_ret")

    def test_contains_unknown(self) -> None:
        assert not make_db().contains("ghost")

    def test_hex_address_parsing(self) -> None:
        db = GadgetDB.from_dict({"g": {"address": "0xdeadbeef", "module": "x", "instruction": "ret"}})
        assert db.get("g").address == 0xDEADBEEF

    def test_int_address_parsing(self) -> None:
        db = GadgetDB.from_dict({"g": {"address": 0x12345678, "module": "x", "instruction": "ret"}})
        assert db.get("g").address == 0x12345678

    def test_zero_address_rejected(self) -> None:
        with pytest.raises(GadgetDBError, match="non-zero"):
            GadgetDB.from_dict({"g": {"address": "0x00000000", "module": "x", "instruction": "ret"}})

    def test_invalid_hex_string_raises(self) -> None:
        with pytest.raises(GadgetDBError, match="Invalid gadget"):
            GadgetDB.from_dict({"g": {"address": "not_hex", "module": "x", "instruction": "ret"}})

    def test_missing_address_key_raises(self) -> None:
        with pytest.raises(GadgetDBError, match="Invalid gadget"):
            GadgetDB.from_dict({"g": {"module": "x", "instruction": "ret"}})

    def test_pack_is_little_endian(self) -> None:
        db = GadgetDB.from_dict({"g": {"address": "0x10203040", "module": "x", "instruction": "ret"}})
        assert db.get("g").pack() == b"\x40\x30\x20\x10"

    def test_names_sorted(self) -> None:
        db = make_db()
        names = db.names()
        assert names == sorted(names)

    def test_from_file_roundtrip(self, tmp_path) -> None:
        p = tmp_path / "gadgets.json"
        p.write_text(json.dumps(FAKE_GADGETS), encoding="utf-8")
        db = GadgetDB.from_file(p)
        assert db.contains("pop_eax_ret")

    def test_from_file_bad_json_raises(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{ not json }", encoding="utf-8")
        with pytest.raises(GadgetDBError, match="Invalid JSON"):
            GadgetDB.from_file(p)

    def test_from_file_missing_file_raises(self, tmp_path) -> None:
        with pytest.raises(GadgetDBError, match="Cannot read"):
            GadgetDB.from_file(tmp_path / "missing.json")

    def test_from_file_non_object_raises(self, tmp_path) -> None:
        p = tmp_path / "arr.json"
        p.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(GadgetDBError, match="JSON object"):
            GadgetDB.from_file(p)


# ── ChainElement models ───────────────────────────────────────────────────────


class TestChainElementModels:
    def test_raw_dword_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="32-bit"):
            RawDword(0x1_0000_0000)

    def test_raw_dword_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="32-bit"):
            RawDword(-1)

    def test_padding_block_zero_count_raises(self) -> None:
        with pytest.raises(ValueError, match="count"):
            PaddingBlock(0)

    def test_padding_block_negative_count_raises(self) -> None:
        with pytest.raises(ValueError, match="count"):
            PaddingBlock(-3)

    def test_padding_block_bad_value_raises(self) -> None:
        with pytest.raises(ValueError, match="32-bit"):
            PaddingBlock(1, value=0x1_0000_0000)

    def test_frozen_gadget_ref(self) -> None:
        ref = GadgetRef("pop_eax_ret", "test")
        with pytest.raises(Exception):
            ref.name = "other"  # type: ignore[misc]

    def test_validation_issue_str_with_index(self) -> None:
        vi = ValidationIssue("error", "MISSING_GADGET", "not found", element_index=3)
        s = str(vi)
        assert "ERROR" in s
        assert "element 3" in s
        assert "MISSING_GADGET" in s

    def test_validation_issue_str_without_index(self) -> None:
        vi = ValidationIssue("warning", "NO_RETURN_TARGET", "no jmp found")
        assert "element" not in str(vi)


# ── RopChain (generic builder) ────────────────────────────────────────────────


class TestRopChain:
    def test_push_gadget_appends_gadget_ref(self) -> None:
        rc = RopChain()
        rc.push_gadget("pop_eax_ret", "test")
        elems = rc.elements()
        assert len(elems) == 1
        assert isinstance(elems[0], GadgetRef)
        assert elems[0].name == "pop_eax_ret"
        assert elems[0].purpose == "test"

    def test_push_dword_appends_raw_dword(self) -> None:
        rc = RopChain()
        rc.push_dword(0xDEADBEEF, "sentinel")
        assert isinstance(rc.elements()[0], RawDword)
        assert rc.elements()[0].value == 0xDEADBEEF

    def test_push_writable_appends_writable_ptr(self) -> None:
        rc = RopChain()
        rc.push_writable("writable_ptr")
        assert isinstance(rc.elements()[0], WritablePtr)
        assert rc.elements()[0].name == "writable_ptr"

    def test_push_shellcode_ptr_appends_shellcode_ptr(self) -> None:
        rc = RopChain()
        rc.push_shellcode_ptr("return here")
        elem = rc.elements()[0]
        assert isinstance(elem, ShellcodePtr)
        assert elem.purpose == "return here"

    def test_push_padding_appends_padding_block(self) -> None:
        rc = RopChain()
        rc.push_padding(4, 0x42424242, "junk")
        elem = rc.elements()[0]
        assert isinstance(elem, PaddingBlock)
        assert elem.count == 4
        assert elem.value == 0x42424242

    def test_byte_length_simple(self) -> None:
        rc = RopChain()
        rc.push_gadget("a")
        rc.push_dword(0x41)
        rc.push_padding(3)
        assert rc.dword_count() == 5
        assert rc.byte_length() == 20

    def test_fluent_chaining_returns_self(self) -> None:
        rc = RopChain()
        result = rc.push_gadget("a").push_dword(1).push_shellcode_ptr()
        assert result is rc

    def test_extend_merges_elements(self) -> None:
        rc1 = RopChain().push_gadget("pop_eax_ret")
        rc2 = RopChain().push_dword(0x41)
        rc1.extend(rc2)
        assert rc1.dword_count() == 2
        assert isinstance(rc1.elements()[0], GadgetRef)
        assert isinstance(rc1.elements()[1], RawDword)

    def test_elements_returns_copy(self) -> None:
        rc = RopChain().push_gadget("pop_eax_ret")
        elems = rc.elements()
        elems.clear()
        assert rc.dword_count() == 1  # original unchanged


# ── VirtualProtectChain ───────────────────────────────────────────────────────


class TestVirtualProtectChain:
    def test_plan_returns_list(self) -> None:
        chain = VirtualProtectChain().plan()
        assert isinstance(chain, list)
        assert len(chain) > 0

    def test_plan_contains_all_required_element_types(self) -> None:
        chain = VirtualProtectChain().plan()
        types = {type(e) for e in chain}
        assert GadgetRef in types
        assert RawDword in types
        assert WritablePtr in types
        assert ShellcodePtr in types

    def test_plan_has_exactly_one_shellcode_ptr(self) -> None:
        chain = VirtualProtectChain().plan()
        assert sum(1 for e in chain if isinstance(e, ShellcodePtr)) == 1

    def test_plan_has_exactly_one_writable_ptr(self) -> None:
        chain = VirtualProtectChain().plan()
        assert sum(1 for e in chain if isinstance(e, WritablePtr)) == 1

    def test_plan_contains_protect_flags(self) -> None:
        chain = VirtualProtectChain(protect_flags=0x40).plan()
        assert any(isinstance(e, RawDword) and e.value == 0x40 for e in chain)

    def test_negated_size_0x201_is_null_free(self) -> None:
        neg = (-0x201) & 0xFFFFFFFF
        assert 0 not in struct.pack("<I", neg), "0x201 negation must be null-free"

    def test_plan_encodes_negated_size(self) -> None:
        vp = VirtualProtectChain(shellcode_size=0x201)
        neg = (-0x201) & 0xFFFFFFFF
        chain = vp.plan()
        assert any(isinstance(e, RawDword) and e.value == neg for e in chain)

    def test_all_required_gadgets_referenced_in_plan(self) -> None:
        chain = VirtualProtectChain().plan()
        refs = {e.name for e in chain if isinstance(e, GadgetRef)}
        refs |= {e.name for e in chain if isinstance(e, WritablePtr)}
        assert VIRTUALPROTECT_REQUIRED_GADGETS.issubset(refs), (
            f"Missing from plan: {VIRTUALPROTECT_REQUIRED_GADGETS - refs}"
        )

    def test_nop_filler_0x90909090_present(self) -> None:
        chain = VirtualProtectChain().plan()
        assert any(isinstance(e, RawDword) and e.value == 0x90909090 for e in chain)

    def test_shellcode_ptr_is_last_element(self) -> None:
        chain = VirtualProtectChain().plan()
        assert isinstance(chain[-1], ShellcodePtr)

    def test_invalid_shellcode_size_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="shellcode_size"):
            VirtualProtectChain(shellcode_size=0)

    def test_invalid_shellcode_size_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="shellcode_size"):
            VirtualProtectChain(shellcode_size=-1)

    def test_invalid_protect_flags_raises(self) -> None:
        with pytest.raises(ValueError, match="protect_flags"):
            VirtualProtectChain(protect_flags=0x04)  # PAGE_READWRITE, not executable

    def test_valid_protect_flags_page_execute(self) -> None:
        vp = VirtualProtectChain(protect_flags=0x20)
        assert vp.protect_flags == 0x20

    def test_valid_protect_flags_page_execute_writecopy(self) -> None:
        vp = VirtualProtectChain(protect_flags=0x80)
        assert vp.protect_flags == 0x80


# ── ChainValidator ────────────────────────────────────────────────────────────


class TestChainValidator:
    def _v(self) -> ChainValidator:
        return ChainValidator()

    def test_full_vp_chain_no_errors(self) -> None:
        db = make_db()
        chain = VirtualProtectChain().plan()
        issues = self._v().validate(chain, db, bad_chars=b"")
        errors = [i for i in issues if i.severity == "error"]
        assert errors == [], f"Unexpected errors: {errors}"

    def test_full_vp_chain_null_byte_only_from_protect_flags(self) -> None:
        # Gadget addresses are null-free (0x41414141 range).
        # The only null bytes come from the literal RawDword(0x40) pushed for
        # flNewProtect — 0x40 packed as 4 LE bytes is 0x40 0x00 0x00 0x00.
        # This is expected and is why real exploits need an encoding trick for
        # the protect flags (e.g. neg/not, or build it via inc/shl gadgets).
        db = make_db()
        chain = VirtualProtectChain().plan()
        issues = self._v().validate(chain, db, bad_chars=b"\x00")
        bad_issues = [i for i in issues if i.code == "BAD_CHARS"]
        assert len(bad_issues) == 1
        assert "0x00000040" in bad_issues[0].message or "0x40" in bad_issues[0].message

    def test_missing_gadget_detected(self) -> None:
        db = GadgetDB.from_dict({})
        chain = [GadgetRef("pop_eax_ret", "test")]
        issues = self._v().validate(chain, db)
        assert any(i.code == "MISSING_GADGET" for i in issues)

    def test_missing_gadget_has_correct_index(self) -> None:
        db = GadgetDB.from_dict({})
        chain = [RawDword(0x41414141), GadgetRef("missing")]
        issues = self._v().validate(chain, db)
        mg = [i for i in issues if i.code == "MISSING_GADGET"]
        assert mg[0].element_index == 1

    def test_missing_writable_ptr_detected(self) -> None:
        chain = [GadgetRef("pop_eax_ret"), RawDword(0x41)]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert any(i.code == "NO_WRITABLE_PTR" for i in issues)

    def test_writable_ptr_present_clears_no_writable_ptr(self) -> None:
        chain = [WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert not any(i.code == "NO_WRITABLE_PTR" for i in issues)

    def test_bad_char_in_raw_dword(self) -> None:
        chain = [RawDword(0x00414141, "has null"), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db, bad_chars=b"\x00")
        assert any(i.code == "BAD_CHARS" for i in issues)

    def test_bad_char_in_gadget_address(self) -> None:
        db = GadgetDB.from_dict({
            "null_gadget": {"address": "0x10000001", "module": "x", "instruction": "ret"},
            "writable_ptr": {"address": "0x10001001", "module": "x", "instruction": "w"},
        })
        chain = [GadgetRef("null_gadget"), WritablePtr("writable_ptr")]
        issues = ChainValidator().validate(chain, db, bad_chars=b"\x00")
        assert any(i.code == "BAD_CHARS" for i in issues)

    def test_bad_char_in_padding_value(self) -> None:
        chain = [PaddingBlock(2, 0x00414141), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db, bad_chars=b"\x00")
        assert any(i.code == "BAD_CHARS" for i in issues)

    def test_shellcode_ptr_skipped_in_bad_char_check(self) -> None:
        # ShellcodePtr has no known address at validation time and must never
        # generate a BAD_CHARS issue, even when bad_chars includes 0x00.
        # Use a chain with only ShellcodePtr so no other element can fire.
        chain = [ShellcodePtr()]
        db = make_db()
        issues = self._v().validate(chain, db, bad_chars=b"\x00")
        bad_issues = [i for i in issues if i.code == "BAD_CHARS"]
        assert bad_issues == []

    def test_no_bad_chars_arg_skips_check(self) -> None:
        chain = [RawDword(0x00000000), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db, bad_chars=b"")
        assert not any(i.code == "BAD_CHARS" for i in issues)

    def test_no_return_target_warning(self) -> None:
        chain = [RawDword(0x41414141), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert any(i.code == "NO_RETURN_TARGET" for i in issues)

    def test_shellcode_ptr_satisfies_return_target(self) -> None:
        chain = [ShellcodePtr(), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert not any(i.code == "NO_RETURN_TARGET" for i in issues)

    def test_jmp_esp_gadget_satisfies_return_target(self) -> None:
        chain = [GadgetRef("jmp_esp"), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert not any(i.code == "NO_RETURN_TARGET" for i in issues)

    def test_stack_alignment_warning_when_unaligned(self) -> None:
        # 3 dwords = 12 bytes (not 16-byte aligned)
        chain = [RawDword(0x41414141), RawDword(0x41414141), WritablePtr("writable_ptr")]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert any(i.code == "STACK_ALIGNMENT" for i in issues)

    def test_stack_alignment_ok_when_aligned(self) -> None:
        # 4 dwords = 16 bytes (16-byte aligned)
        chain = [
            RawDword(0x41414141), RawDword(0x41414141),
            RawDword(0x41414141), WritablePtr("writable_ptr"),
        ]
        db = make_db()
        issues = self._v().validate(chain, db)
        assert not any(i.code == "STACK_ALIGNMENT" for i in issues)

    def test_all_issues_are_validation_issue_instances(self) -> None:
        db = GadgetDB.from_dict({})
        chain = [GadgetRef("missing")]
        issues = self._v().validate(chain, db)
        assert all(isinstance(i, ValidationIssue) for i in issues)

    def test_multiple_bad_chars_all_detected(self) -> None:
        # 0x0a and 0x0d both in different elements
        chain = [
            RawDword(0x0a414141, "lf byte"),
            RawDword(0x41414141, "clean"),
            RawDword(0x410d4141, "cr byte"),
            WritablePtr("writable_ptr"),
        ]
        db = make_db()
        issues = self._v().validate(chain, db, bad_chars=b"\x0a\x0d")
        bad = [i for i in issues if i.code == "BAD_CHARS"]
        assert len(bad) == 2
        assert {i.element_index for i in bad} == {0, 2}


# ── ChainSerializer ───────────────────────────────────────────────────────────


class TestChainSerializer:
    def _s(self) -> ChainSerializer:
        return ChainSerializer()

    def test_raw_dword_packs_little_endian(self) -> None:
        result = self._s().serialize([RawDword(0xDEADBEEF)], make_db())
        assert result == struct.pack("<I", 0xDEADBEEF)

    def test_gadget_ref_packs_address(self) -> None:
        result = self._s().serialize([GadgetRef("pop_eax_ret")], make_db())
        assert result == struct.pack("<I", 0x41414147)

    def test_writable_ptr_packs_address(self) -> None:
        result = self._s().serialize([WritablePtr("writable_ptr")], make_db())
        assert result == struct.pack("<I", 0x4141414D)

    def test_shellcode_ptr_packs_supplied_address(self) -> None:
        result = self._s().serialize([ShellcodePtr()], make_db(), shellcode_addr=0xABCDEF11)
        assert result == struct.pack("<I", 0xABCDEF11)

    def test_shellcode_ptr_without_addr_raises(self) -> None:
        with pytest.raises(SerializationError, match="shellcode_addr"):
            self._s().serialize([ShellcodePtr()], make_db())

    def test_shellcode_ptr_out_of_range_raises(self) -> None:
        with pytest.raises(SerializationError, match="32-bit"):
            self._s().serialize([ShellcodePtr()], make_db(), shellcode_addr=0x1_0000_0000)

    def test_padding_block_repeats_value(self) -> None:
        result = self._s().serialize([PaddingBlock(3, 0x41414141)], make_db())
        assert result == b"\x41\x41\x41\x41" * 3

    def test_full_chain_length(self) -> None:
        db = make_db()
        chain = VirtualProtectChain().plan()
        result = ChainSerializer().serialize(chain, db, shellcode_addr=0x41414141)
        assert isinstance(result, bytes)
        # No PaddingBlocks in VP plan; one entry = 4 bytes
        assert len(result) == len(chain) * 4

    def test_missing_gadget_propagates_db_error(self) -> None:
        db = GadgetDB.from_dict({})
        chain = [GadgetRef("missing")]
        with pytest.raises(Exception, match="missing"):
            self._s().serialize(chain, db)

    def test_concatenation_order(self) -> None:
        chain = [RawDword(0x11111111), RawDword(0x22222222), RawDword(0x33333333)]
        result = self._s().serialize(chain, make_db())
        assert result == (
            b"\x11\x11\x11\x11"
            b"\x22\x22\x22\x22"
            b"\x33\x33\x33\x33"
        )


# ── DryRunPrinter (smoke test — output correctness checked visually) ───────────


class TestDryRunPrinter:
    def test_print_chain_does_not_raise(self, capsys) -> None:
        db = make_db()
        chain = VirtualProtectChain().plan()
        DryRunPrinter().print_chain(chain, db, bad_chars=b"\x00", use_color=False)
        out = capsys.readouterr().out
        assert "IDX" in out
        assert "PURPOSE" in out
        assert "Total:" in out

    def test_missing_gadget_shown_as_missing(self, capsys) -> None:
        db = GadgetDB.from_dict({})
        chain = [GadgetRef("nonexistent", "test")]
        DryRunPrinter().print_chain(chain, db, use_color=False)
        out = capsys.readouterr().out
        assert "MISSING" in out

    def test_shellcode_ptr_shows_dynamic(self, capsys) -> None:
        db = make_db()
        chain = [ShellcodePtr("return target")]
        DryRunPrinter().print_chain(chain, db, use_color=False)
        out = capsys.readouterr().out
        assert "<dynamic>" in out

    def test_padding_block_expands_to_multiple_rows(self, capsys) -> None:
        db = make_db()
        chain = [PaddingBlock(3, 0x41414141, "junk")]
        DryRunPrinter().print_chain(chain, db, use_color=False)
        out = capsys.readouterr().out
        # Should have row indices 00, 01, 02
        assert "[00]" in out
        assert "[01]" in out
        assert "[02]" in out

    def test_total_line_correct_count(self, capsys) -> None:
        db = make_db()
        chain = [RawDword(0x41414141), RawDword(0x42424242)]
        DryRunPrinter().print_chain(chain, db, use_color=False)
        out = capsys.readouterr().out
        assert "2 dwords" in out
        assert "8 bytes" in out
