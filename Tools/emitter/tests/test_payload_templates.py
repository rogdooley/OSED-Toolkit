"""Tests for payload template modules."""
from __future__ import annotations

import re
import socket
import struct

import pytest


@pytest.fixture
def revshell_manifest(manifest_dir):
    from Tools.emitter.schema import load
    return load(str(manifest_dir / "revshell.yaml"))


@pytest.fixture
def default_config():
    from Tools.emitter.payload_templates.base import TemplateConfig
    return TemplateConfig(lhost="192.168.1.116", lport=9001)


def test_reverse_shell_wsastartup_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSAStartup").ebp_ref in asm


def test_reverse_shell_wsasocketa_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSASocketA").ebp_ref in asm


def test_reverse_shell_connect_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("connect").ebp_ref in asm


def test_reverse_shell_createprocessa_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("CreateProcessA").ebp_ref in asm


def test_reverse_shell_socket_handle_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("socket_handle").ebp_ref in asm


def test_reverse_shell_lhost_as_hex(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    lhost = default_config.lhost
    ip_le = struct.unpack("<I", socket.inet_aton(lhost))[0]
    asm = t.emit(revshell_layout, default_config)
    assert f"0x{ip_le:08x}" in asm


def test_reverse_shell_lport_as_hex(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    port_be = socket.htons(default_config.lport)
    asm = t.emit(revshell_layout, default_config)
    assert f"0x{port_be:04x}" in asm


def test_reverse_shell_no_hardcoded_offsets(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    # Every [ebp-0xNN] in the output must correspond to a known layout slot
    known_refs = {s.ebp_ref for s in revshell_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_run_command_winexec_slot(manifest_dir, calc_layout):
    from Tools.emitter.payload_templates.run_command import RunCommandTemplate
    from Tools.emitter.payload_templates.base import TemplateConfig
    t = RunCommandTemplate()
    config = TemplateConfig(command="calc.exe", badchars={0x00})
    asm = t.emit(calc_layout, config)
    assert calc_layout.slot("WinExec").ebp_ref in asm


def test_run_command_uses_cmd_slot_when_available(manifest_dir, default_config):
    from Tools.emitter.payload_templates.run_command import RunCommandTemplate
    from Tools.emitter.schema import load
    from Tools.emitter.stack_alloc import build_layout
    from Tools.emitter.build import _merge_template_requirements
    t = RunCommandTemplate()
    manifest = load(str(manifest_dir / "revshell.yaml"))
    manifest = _merge_template_requirements(manifest, t, default_config)
    layout = build_layout(manifest)
    asm = t.emit(layout, default_config)
    cmd_ref = layout.slot("cmd").ebp_ref
    assert cmd_ref in asm
    assert "lea  eax" in asm


def test_run_command_inline_push_fallback(calc_layout):
    from Tools.emitter.payload_templates.run_command import RunCommandTemplate
    from Tools.emitter.payload_templates.base import TemplateConfig
    t = RunCommandTemplate()
    # calc manifest has 'calc' slot, not 'cmd' — triggers inline push fallback
    config = TemplateConfig(command="calc.exe", badchars={0x00})
    asm = t.emit(calc_layout, config)
    assert calc_layout.slot("WinExec").ebp_ref in asm


def test_reverse_shell_cmd_slot_referenced(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    cmd_ref = revshell_layout.slot("cmd").ebp_ref
    assert cmd_ref in asm


def test_reverse_shell_startupinfoa_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("STARTUPINFOA").ebp_ref in asm


def test_reverse_shell_wsadata_slot(revshell_layout, default_config):
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSADATA").ebp_ref in asm


# ---------------------------------------------------------------------------
# Auto-derivation: probe_slots and _merge_template_requirements
# ---------------------------------------------------------------------------


class TestProbeSlots:
    """PayloadTemplate.probe_slots discovers slot references from emit()."""

    def test_reverse_shell_probe_includes_apis(self, default_config):
        from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        for api in ("WSAStartup", "WSASocketA", "connect", "CreateProcessA"):
            assert api in slots

    def test_reverse_shell_probe_includes_variables(self, default_config):
        from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        assert "socket_handle" in slots

    def test_reverse_shell_probe_includes_structures(self, default_config):
        from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        for struct in ("WSADATA", "sockaddr_in", "STARTUPINFOA", "PROCESS_INFORMATION"):
            assert struct in slots

    def test_probe_returns_unique_names(self, default_config):
        from Tools.emitter.payload_templates.tcp_download import TcpDownloadTemplate
        slots = TcpDownloadTemplate().probe_slots(default_config)
        assert len(slots) == len(set(slots))

    def test_run_command_probe_includes_optional_cmd(self):
        from Tools.emitter.payload_templates.run_command import RunCommandTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        config = TemplateConfig(command="calc.exe")
        slots = RunCommandTemplate().probe_slots(config)
        assert "WinExec" in slots
        assert "cmd" in slots


class TestMergeTemplateRequirements:
    """_merge_template_requirements auto-adds missing APIs and variables."""

    def test_adds_missing_api(self, manifest_dir):
        from Tools.emitter.schema import load, Manifest
        from Tools.emitter.build import _merge_template_requirements
        from Tools.emitter.payload_templates.run_command import RunCommandTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        assert "WinExec" not in manifest.functions
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, RunCommandTemplate(), config)
        assert "WinExec" in merged.functions

    def test_adds_missing_variable(self, manifest_dir):
        from Tools.emitter.schema import load, Manifest
        from Tools.emitter.build import _merge_template_requirements
        from Tools.emitter.payload_templates.bind_shell import BindShellTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        assert "bind_socket" not in {v.name for v in manifest.variables}
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, BindShellTemplate(), config)
        assert "bind_socket" in {v.name for v in merged.variables}

    def test_does_not_duplicate_existing(self, manifest_dir):
        from Tools.emitter.schema import load
        from Tools.emitter.build import _merge_template_requirements
        from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, ReverseShellTemplate(), config)
        assert merged.functions.count("WSAStartup") == 1
        assert merged.functions.count("connect") == 1

    def test_auto_adds_loadlibrarya_for_ws2(self):
        from Tools.emitter.schema import Manifest, StringEntry
        from Tools.emitter.build import _merge_template_requirements
        from Tools.emitter.payload_templates.tcp_stager import TcpStagerTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        bare = Manifest(badchars={0x00}, functions=[], strings=[
            StringEntry(label="ws2_dll", value="ws2_32.dll", method="push"),
        ])
        config = TemplateConfig()
        merged = _merge_template_requirements(bare, TcpStagerTemplate(), config)
        assert "LoadLibraryA" in merged.functions

    def test_noop_when_manifest_complete(self, manifest_dir):
        from Tools.emitter.schema import load
        from Tools.emitter.build import _merge_template_requirements
        from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
        from Tools.emitter.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, ReverseShellTemplate(), config)
        assert merged.functions == manifest.functions

    def test_build_with_incomplete_manifest_succeeds(self, manifest_dir, tmp_path):
        """An incomplete manifest + template should auto-fill and build."""
        from Tools.emitter.build import build
        from Tools.emitter.payload_templates.base import TemplateConfig
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="run_command",
            config=TemplateConfig(command="calc.exe"),
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "WinExec" in result.asm
