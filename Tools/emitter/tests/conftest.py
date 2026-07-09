"""Shared fixtures for emitter tests."""
from __future__ import annotations

import pathlib

import pytest


@pytest.fixture
def manifest_dir() -> pathlib.Path:
    return pathlib.Path(__file__).parent.parent / "manifests"


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


@pytest.fixture
def revshell_doc(revshell_layout, manifest_dir):
    from Tools.emitter.schema import load
    from Tools.emitter.doc_gen import emit_full_contract_md
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return emit_full_contract_md(manifest, revshell_layout)


@pytest.fixture
def revshell_doc_with_cheatsheet(revshell_layout, manifest_dir):
    from Tools.emitter.schema import load
    from Tools.emitter.doc_gen import emit_full_contract_md
    from Tools.emitter.payload_templates.reverse_shell import ReverseShellTemplate
    from Tools.emitter.payload_templates.base import TemplateConfig
    manifest = load(str(manifest_dir / "revshell.yaml"))
    template = ReverseShellTemplate()
    config = TemplateConfig(lhost="192.168.1.100", lport=9001, badchars=manifest.badchars)
    return emit_full_contract_md(manifest, revshell_layout, template, config, shellcode_size=512)
