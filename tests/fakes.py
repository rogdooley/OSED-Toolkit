"""Reusable fakes for integration tests."""

import os


CAPTURED_PAYLOADS = []


def reset_captured_payloads():
    # type: () -> None
    del CAPTURED_PAYLOADS[:]


def capture_payload(payload):
    # type: (bytes) -> None
    CAPTURED_PAYLOADS.append(payload)


class FakeSender(object):
    def __init__(self, on_send=None):
        self.payloads = []
        self._on_send = on_send

    def send(self, payload):
        self.payloads.append(payload)
        if self._on_send:
            self._on_send(payload)


class FakeDumpWriter(object):
    def __init__(self, dump_path):
        self.dump_path = dump_path

    def write(self, data):
        parent = os.path.dirname(self.dump_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent)
        with open(self.dump_path, "wb") as handle:
            handle.write(data)


class _BaseDriver(object):
    def __init__(self):
        self.running = False
        self.start_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0
        self._marker = False
        self._transcript = ""
        self._wait_rc = 0

    def start(self):
        self.running = True
        self.start_calls += 1

    def kill(self):
        self.running = False
        self.kill_calls += 1

    def is_running(self):
        return self.running

    def wait(self, timeout=None):
        self.wait_calls += 1
        return self._wait_rc

    def saw_marker(self, marker):
        return self._marker and marker == "BADCHAR_CRASH"

    def transcript(self):
        return self._transcript

    def has_live_target(self):
        return self.running


class FakePersistentDriver(_BaseDriver):
    pass


class FakeCrashMarkerDriver(_BaseDriver):
    def trigger_crash(self):
        self.running = False
        self._marker = True
        self._transcript = "BADCHAR_CRASH"
        self._wait_rc = 1

    def has_live_target(self):
        # Fail-closed semantics for uncertain/dead state.
        return self.running


class FakeExitedDriver(_BaseDriver):
    def trigger_exit(self, returncode):
        self.running = False
        self._marker = False
        self._wait_rc = returncode

    def has_live_target(self):
        return self.running
