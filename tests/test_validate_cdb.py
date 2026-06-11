import os
import sys
import tempfile

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.models import Stage
from badchars_wds.validate_cdb import (
    BP_HIT,
    CDBValidationHarness,
    INSTALL_MARKER,
    LIST_BEGIN_MARKER,
    LIST_END_MARKER,
    _breakpoint_module_name,
    _extract_breakpoint_listing,
    generate_validation_wds,
)


class _FakeSender(object):
    def __init__(self, on_send=None):
        self.payloads = []
        self._on_send = on_send

    def send(self, payload):
        self.payloads.append(payload)
        if self._on_send is not None:
            self._on_send(payload)


class _FakeDriver(object):
    def __init__(self, transcript="", running=True):
        self._transcript = transcript
        self._running = running
        self.started = False
        self.killed = False

    def start(self):
        self.started = True

    def kill(self):
        self.killed = True
        self._running = False

    def is_running(self):
        return self._running

    def transcript(self):
        return self._transcript

    def wait(self, timeout=None):
        return 0


def test_generate_validation_wds_contains_markers_and_breakpoint():
    stage = Stage(
        breakpoint="badchar_target!call_strcpy",
        dump_expr="poi(@esp+4)+2006",
        dump_size=512,
        step_mode="none",
        temp_dump_path="C:/dbg/dump.bin",
        final_dump_path="C:/dbg/dump.bin",
    )
    script = generate_validation_wds(stage)
    assert "bp badchar_target!call_strcpy" in script
    assert INSTALL_MARKER in script
    assert LIST_BEGIN_MARKER in script
    assert LIST_END_MARKER in script
    assert BP_HIT in script
    assert ".reload /f badchar_target.exe" in script


def test_extract_breakpoint_listing_returns_block():
    transcript = "\n".join(
        [
            "x",
            LIST_BEGIN_MARKER,
            " 0 e 000573c0     0001 (0001)  0:**** badchar_target!call_strcpy",
            LIST_END_MARKER,
            "y",
        ]
    )
    listing = _extract_breakpoint_listing(transcript)
    assert listing == [" 0 e 000573c0     0001 (0001)  0:**** badchar_target!call_strcpy"]


def test_breakpoint_module_name_handles_symbol_and_offset_forms():
    assert _breakpoint_module_name("badchar_target!call_strcpy") == "badchar_target"
    assert _breakpoint_module_name("badchar_target+0x73c0") == "badchar_target"
    assert _breakpoint_module_name("0x625011AF") is None


def test_validation_harness_reports_hit_and_dump_written():
    with tempfile.TemporaryDirectory() as tmpdir:
        dump_path = os.path.join(tmpdir, "dump.bin")

        def _write_dump(_payload):
            with open(dump_path, "wb") as handle:
                handle.write(b"x" * 128)

        stage = Stage(
            breakpoint="badchar_target!call_strcpy",
            dump_expr="poi(@esp+4)+2006",
            dump_size=512,
            step_mode="none",
            temp_dump_path=dump_path,
            final_dump_path=dump_path,
        )
        transcript = "\n".join(
            [
                INSTALL_MARKER,
                LIST_BEGIN_MARKER,
                " 0 e 000573c0     0001 (0001)  0:**** badchar_target!call_strcpy",
                LIST_END_MARKER,
                BP_HIT,
            ]
        )
        harness = CDBValidationHarness(
            driver=_FakeDriver(transcript=transcript, running=True),
            sender=_FakeSender(on_send=_write_dump),
            stage=stage,
            offset=0,
            dump_dir=tmpdir,
            magic=b"\xbc\xf0\xbc\xf0",
            excluded_bytes=set([0]),
            timeout=0.01,
            restart_delay=0.0,
        )
        result = harness.run()
        assert result.breakpoint_command_sent is True
        assert result.breakpoint_listed is True
        assert result.breakpoint_hit is True
        assert result.dump_written is True
