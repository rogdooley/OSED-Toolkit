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
    ip_be = struct.unpack(">I", socket.inet_aton(lhost))[0]
    asm = t.emit(revshell_layout, default_config)
    assert f"0x{ip_be:08x}" in asm


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


def test_run_command_uses_cmd_slot_when_available(revshell_layout, default_config):
    from Tools.emitter.payload_templates.run_command import RunCommandTemplate
    t = RunCommandTemplate()
    asm = t.emit(revshell_layout, default_config)
    # revshell manifest has a 'cmd' slot → should use lea instead of inline push
    cmd_ref = revshell_layout.slot("cmd").ebp_ref
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
