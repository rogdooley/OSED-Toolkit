import os
import sys
import tempfile
import threading
import time

import pytest

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.cdb import CDBDriver


class FakeStdout(object):
    def __init__(self, lines):
        self._lines = list(lines)
        self._index = 0
        self._lock = threading.Lock()

    def readline(self):
        with self._lock:
            if self._index < len(self._lines):
                value = self._lines[self._index]
                self._index += 1
                return value
        time.sleep(0.01)
        return ""


class FakeProcess(object):
    def __init__(self, lines=None, wait_return=0):
        self.stdout = FakeStdout(lines or [])
        self._poll = None
        self._wait_return = wait_return
        self.terminate_called = 0
        self.kill_called = 0
        self.wait_calls = []

    def poll(self):
        return self._poll

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        self._poll = self._wait_return
        return self._wait_return

    def terminate(self):
        self.terminate_called += 1

    def kill(self):
        self.kill_called += 1
        self._poll = -9


def test_start_builds_expected_invocation(monkeypatch):
    captured = {}
    fake = FakeProcess(lines=["line1\n"], wait_return=0)

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return fake

    monkeypatch.setattr("subprocess.Popen", fake_popen)

    driver = CDBDriver(
        cdb_path="cdb.exe",
        target_command=["target.exe", "-x"],
        script_path="generated.wds",
    )
    driver.start()
    rc = driver.wait(timeout=1.0)

    assert rc == 0
    assert captured["args"] == [
        "cdb.exe",
        "-o",
        "-G",
        "-cf",
        "generated.wds",
        "target.exe",
        "-x",
    ]
    assert captured["kwargs"]["stdout"] is not None
    assert captured["kwargs"]["stderr"] is not None
    assert "line1" in driver.transcript()


def test_saw_marker_uses_transcript(monkeypatch):
    fake = FakeProcess(lines=["abc\n", "BADCHAR_CRASH\n"], wait_return=0)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: fake)

    driver = CDBDriver("cdb.exe", ["target.exe"], "script.wds")
    driver.start()
    driver.wait(timeout=1.0)

    assert driver.saw_marker("BADCHAR_CRASH") is True
    assert driver.saw_marker("DOES_NOT_EXIST") is False


def test_kill_terminates_running_process(monkeypatch):
    fake = FakeProcess(lines=[], wait_return=0)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: fake)

    driver = CDBDriver("cdb.exe", ["target.exe"], "script.wds")
    driver.start()
    assert driver.is_running() is True
    driver.kill()
    assert fake.terminate_called == 1
    assert driver.is_running() is False


def test_wait_timeout_propagates(monkeypatch):
    class TimeoutProcess(FakeProcess):
        def wait(self, timeout=None):
            raise TimeoutError()

    fake = TimeoutProcess(lines=["x\n"])
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: fake)

    driver = CDBDriver("cdb.exe", ["target.exe"], "script.wds")
    driver.start()
    with pytest.raises(TimeoutError):
        driver.wait(timeout=0.01)
    driver.kill()


def test_transcript_optional_log_file(monkeypatch):
    fake = FakeProcess(lines=["first\n", "second\n"], wait_return=0)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: fake)

    fd, log_path = tempfile.mkstemp(prefix="cdb-driver-", suffix=".log")
    os.close(fd)
    try:
        driver = CDBDriver(
            cdb_path="cdb.exe",
            target_command=["target.exe"],
            script_path="script.wds",
            log_path=log_path,
        )
        driver.start()
        driver.wait(timeout=1.0)

        assert "first" in driver.transcript()
        with open(log_path, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert "first" in content
        assert "second" in content
    finally:
        os.unlink(log_path)


def test_invalid_constructor_inputs():
    with pytest.raises(ValueError):
        CDBDriver("", ["target.exe"], "script.wds")
    with pytest.raises(ValueError):
        CDBDriver("cdb.exe", [], "script.wds")
    with pytest.raises(ValueError):
        CDBDriver("cdb.exe", ["target.exe"], "")
