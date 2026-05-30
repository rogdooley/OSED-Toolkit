"""
Unit tests for Tools/badchars_wds/orchestrator.py

All tests run without a real debugger or network connection.
CDBDriver and filesystem operations are mocked or use temporary directories.
"""

import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, call
import errno

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.analyzer import generate_candidate_bytes
from badchars_wds.models import Stage
from badchars_wds.orchestrator import (
    BadCharOrchestrator,
    IterationResult,
    IterationStatus,
    RestartPolicy,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

MAGIC = b"\xBC\xF0\xBC\xF0"
EXCLUDED_DEFAULT = {0x00}


def _make_stage(dump_dir):
    """Stage with absolute paths rooted in ``dump_dir``."""
    return Stage(
        breakpoint="msvcrt!strcpy",
        dump_expr="poi(@esp+4)",
        dump_size=512,
        step_mode="pt",
        temp_dump_path=os.path.join(dump_dir, "_tmp.bin"),
        final_dump_path=os.path.join(dump_dir, "dump.bin"),
    )


def _make_driver(is_running=True, saw_crash=False, wait_rc=0):
    """CDBDriver mock with configurable state.

    is_running=True  → driver starts on first call to _ensure_driver_running()
                       (is_running returns False once, then True for all polls)
    is_running=False → driver appears immediately dead / crash-per-payload
                       (is_running always returns False; start() is still called
                       each iteration, then _wait_for_dump() exits via
                       _classify_exit() immediately)
    """
    driver = MagicMock()
    if is_running:
        # First call in _ensure_driver_running() sees False → start() is called.
        # All subsequent poll calls in _wait_for_dump() see True → stays alive.
        driver.is_running.side_effect = [False] + [True] * 1000
    else:
        # Driver is always dead: _ensure_driver_running() starts it, but
        # _wait_for_dump() immediately detects it as exited.
        driver.is_running.side_effect = [False] * 1000
    driver.saw_marker.return_value = saw_crash
    driver.wait.return_value = wait_rc
    driver.transcript.return_value = "BADCHAR_CRASH" if saw_crash else ""
    driver.has_live_target.return_value = is_running
    return driver


def _make_orchestrator(driver, stage, sender, dump_dir, timeout=2.0, max_iterations=5):
    return BadCharOrchestrator(
        driver=driver,
        stage=stage,
        sender=sender,
        offset=0,
        dump_dir=dump_dir,
        magic=MAGIC,
        timeout=timeout,
        restart_delay=0,
        max_iterations=max_iterations,
        excluded_bytes=EXCLUDED_DEFAULT,
        restart_policy=RestartPolicy.CONDITIONAL,
    )


def _write_dump(dump_path, data):
    """Write binary data to dump_path (simulates cdb .writemem + rename)."""
    with open(dump_path, "wb") as fh:
        fh.write(data)


def _make_clean_dump(excluded=None):
    """Return MAGIC + matching candidates — a perfectly clean dump."""
    exc = excluded if excluded is not None else EXCLUDED_DEFAULT
    return MAGIC + generate_candidate_bytes(exc)


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------

class TestConstruction(unittest.TestCase):

    def test_magic_overlapping_excluded_raises(self):
        """
        Magic bytes that appear in excluded_bytes are a hard error.
        The validation mechanism would be self-defeating from iteration one.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage   = _make_stage(tmpdir)
            driver  = _make_driver()
            sender  = MagicMock()
            # MAGIC contains 0xBC and 0xF0 — add 0xBC to excluded to trigger
            with self.assertRaises(ValueError):
                BadCharOrchestrator(
                    driver=driver,
                    stage=stage,
                    sender=sender,
                    offset=0,
                    dump_dir=tmpdir,
                    magic=MAGIC,
                    timeout=5.0,
                    restart_delay=0,
                    max_iterations=5,
                    excluded_bytes={0x00, 0xBC},  # 0xBC is in MAGIC
                )

    def test_non_callable_sender_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(TypeError):
                BadCharOrchestrator(
                    driver=_make_driver(),
                    stage=_make_stage(tmpdir),
                    sender="not_callable",
                    offset=0,
                    dump_dir=tmpdir,
                    magic=MAGIC,
                    timeout=5.0,
                    restart_delay=0,
                    max_iterations=5,
                    excluded_bytes=EXCLUDED_DEFAULT,
                )

    def test_negative_offset_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError):
                _make_orchestrator(
                    _make_driver(), _make_stage(tmpdir), MagicMock(), tmpdir,
                )
                # offset defaults to 0 in helper; test directly
                BadCharOrchestrator(
                    driver=_make_driver(),
                    stage=_make_stage(tmpdir),
                    sender=MagicMock(),
                    offset=-1,
                    dump_dir=tmpdir,
                    magic=MAGIC,
                    timeout=5.0,
                    restart_delay=0,
                    max_iterations=5,
                    excluded_bytes=EXCLUDED_DEFAULT,
                )

    def test_zero_timeout_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError):
                BadCharOrchestrator(
                    driver=_make_driver(),
                    stage=_make_stage(tmpdir),
                    sender=MagicMock(),
                    offset=0,
                    dump_dir=tmpdir,
                    magic=MAGIC,
                    timeout=0,
                    restart_delay=0,
                    max_iterations=5,
                    excluded_bytes=EXCLUDED_DEFAULT,
                )

    def test_invalid_restart_policy_type_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(TypeError):
                BadCharOrchestrator(
                    driver=_make_driver(),
                    stage=_make_stage(tmpdir),
                    sender=MagicMock(),
                    offset=0,
                    dump_dir=tmpdir,
                    magic=MAGIC,
                    timeout=1.0,
                    restart_delay=0,
                    max_iterations=5,
                    excluded_bytes=EXCLUDED_DEFAULT,
                    restart_policy="conditional",
                )


# ---------------------------------------------------------------------------
# Stale dump cleanup
# ---------------------------------------------------------------------------

class TestStaleDumpCleanup(unittest.TestCase):

    def test_stale_dump_deleted_before_send(self):
        """
        A dump file left over from a previous run must be deleted before the
        sender is called — not after.  Otherwise, the first poll could return
        data from the wrong iteration.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            # Pre-existing stale file.
            _write_dump(dump_path, b"stale content from previous run")
            self.assertTrue(os.path.exists(dump_path))

            dump_existed_at_send_time = []

            def sender(payload):
                dump_existed_at_send_time.append(os.path.exists(dump_path))

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=0.15)
            orch.run()

            self.assertTrue(len(dump_existed_at_send_time) >= 1)
            self.assertFalse(
                dump_existed_at_send_time[0],
                "Stale dump.bin should have been deleted before sender() was called",
            )

    def test_absent_dump_does_not_raise(self):
        """_clear_stale() must tolerate the file being absent (OSError)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, MagicMock(), tmpdir, timeout=0.15)
            # No dump file exists — should not raise on first _clear_stale call.
            try:
                orch.run()
            except Exception as exc:
                self.fail("run() raised unexpectedly: {}".format(exc))

    def test_stale_dump_retry_once_then_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stage = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            sender = MagicMock()
            orch = _make_orchestrator(driver, stage, sender, tmpdir, timeout=0.15)

            original_remove = os.remove
            calls = {"n": 0}

            def flaky_remove(path):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError(errno.EACCES, "sharing violation")
                return original_remove(path)

            dump_path = os.path.join(tmpdir, "dump.bin")
            _write_dump(dump_path, b"stale")
            try:
                import badchars_wds.orchestrator as orch_mod

                old_remove = orch_mod.os.remove
                orch_mod.os.remove = flaky_remove
                try:
                    orch._clear_stale_dump()
                finally:
                    orch_mod.os.remove = old_remove
            except Exception as exc:
                self.fail("retry should have succeeded, got: {}".format(exc))

            self.assertGreaterEqual(calls["n"], 2)

    def test_stale_dump_retry_failure_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stage = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            sender = MagicMock()
            orch = _make_orchestrator(driver, stage, sender, tmpdir, timeout=0.15)

            def always_fail(_path):
                raise OSError(errno.EACCES, "sharing violation")

            import badchars_wds.orchestrator as orch_mod

            old_remove = orch_mod.os.remove
            orch_mod.os.remove = always_fail
            try:
                with self.assertRaises(RuntimeError):
                    orch._clear_stale_dump()
            finally:
                orch_mod.os.remove = old_remove


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

class TestTimeout(unittest.TestCase):

    def test_no_dump_returns_empty_list(self):
        """
        If no dump ever appears and the driver stays alive, run() must return
        an empty confirmed list after the timeout — not raise or hang.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            sender = MagicMock()

            orch = _make_orchestrator(driver, stage, sender, tmpdir, timeout=0.15)
            start  = time.monotonic()
            result = orch.run()
            elapsed = time.monotonic() - start

            self.assertEqual(result, [])
            # Should have timed out roughly on schedule (+/- generous margin).
            self.assertGreater(elapsed, 0.05)
            self.assertLess(elapsed, 3.0)

    def test_driver_start_called(self):
        """run() must call driver.start() exactly once."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, MagicMock(), tmpdir, timeout=0.15)
            orch.run()
            driver.start.assert_called_once()

    def test_driver_kill_called_on_exit(self):
        """run() must call driver.kill() when the loop finishes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, MagicMock(), tmpdir, timeout=0.15)
            orch.run()
            driver.kill.assert_called_once()

    def test_conditional_policy_restarts_when_session_not_live(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stage = _make_stage(tmpdir)
            driver = _make_driver(is_running=True)
            driver.is_running.side_effect = [True, False] + [True] * 100
            driver.has_live_target.return_value = False
            orch = _make_orchestrator(driver, stage, MagicMock(), tmpdir, timeout=0.15)
            orch.run()
            self.assertTrue(driver.kill.called)


# ---------------------------------------------------------------------------
# Short dump
# ---------------------------------------------------------------------------

class TestShortDump(unittest.TestCase):

    def test_dump_smaller_than_magic_stops_loop(self):
        """
        A dump file that is smaller than len(magic) must be classified as a
        ShortDump and the loop must stop without misinterpreting the data.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            def sender(payload):
                # Write fewer bytes than the magic length (4).
                _write_dump(dump_path, b"\xBC\xF0")  # 2 bytes — too short

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            self.assertEqual(result, [])

    def test_dump_exactly_magic_length_with_wrong_prefix(self):
        """A file exactly len(magic) bytes with the wrong contents → MagicMismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            def sender(payload):
                _write_dump(dump_path, b"\xDE\xAD\xBE\xEF")  # wrong magic, right size

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Magic mismatch
# ---------------------------------------------------------------------------

class TestMagicMismatch(unittest.TestCase):

    def test_wrong_magic_stops_loop(self):
        """
        If the first bytes of the dump do not match the configured magic, the
        loop must stop.  This indicates dump_expr points to the wrong address.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            candidates = generate_candidate_bytes(EXCLUDED_DEFAULT)

            def sender(payload):
                # Valid length, wrong magic.
                _write_dump(dump_path, b"\xDE\xAD\xBE\xEF" + candidates)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            self.assertEqual(result, [])

    def test_correct_magic_not_confused_with_mismatch(self):
        """Sanity: correct magic should pass validation, not raise MagicMismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            candidates = generate_candidate_bytes(EXCLUDED_DEFAULT)

            def sender(payload):
                _write_dump(dump_path, MAGIC + candidates)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            # Clean dump → no bad chars.
            self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Successful comparison path
# ---------------------------------------------------------------------------

class TestSuccessfulComparison(unittest.TestCase):

    def test_clean_dump_returns_empty_list(self):
        """
        When the observed bytes exactly match the candidates, run() returns an
        empty list: no bad chars found.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            def sender(payload):
                _write_dump(dump_path, _make_clean_dump())

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertEqual(result, [])

    def test_sender_receives_magic_in_payload(self):
        """
        The payload passed to sender must contain the magic bytes at position
        ``offset``.  With offset=0 the magic starts at byte 0.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            payloads  = []

            def sender(payload):
                payloads.append(payload)
                _write_dump(dump_path, _make_clean_dump())

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            orch.run()

            self.assertTrue(len(payloads) >= 1)
            sent = payloads[0]
            self.assertTrue(
                sent[:len(MAGIC)] == MAGIC,
                "Magic not found at offset 0 in payload",
            )

    def test_payload_contains_padding(self):
        """Payload must end with the default b'C' * 32 padding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            payloads  = []

            def sender(payload):
                payloads.append(payload)
                _write_dump(dump_path, _make_clean_dump())

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            orch.run()

            self.assertTrue(payloads[0].endswith(b"C" * 32))

    def test_offset_inserts_a_padding(self):
        """When offset > 0, payload must start with that many b'A' bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            payloads  = []

            def sender(payload):
                payloads.append(payload)
                _write_dump(dump_path, _make_clean_dump())

            driver = _make_driver(is_running=True)
            orch = BadCharOrchestrator(
                driver=driver,
                stage=stage,
                sender=sender,
                offset=16,
                dump_dir=tmpdir,
                magic=MAGIC,
                timeout=2.0,
                restart_delay=0,
                max_iterations=5,
                excluded_bytes=EXCLUDED_DEFAULT,
            )
            orch.run()

            self.assertEqual(payloads[0][:16], b"A" * 16)
            self.assertEqual(payloads[0][16:20], MAGIC)


# ---------------------------------------------------------------------------
# Divergence → bad char discovery
# ---------------------------------------------------------------------------

class TestDivergence(unittest.TestCase):

    def test_single_divergence_adds_one_bad_char(self):
        """
        When the dump shows a divergence at offset 0 (expected 0x01, got 0x02),
        the orchestrator must add 0x01 to the confirmed list and retry.
        On the clean second pass, run() returns [0x01].
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    # Candidates are [0x01..0xff]. Simulate 0x01 → 0x02.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT)
                    _write_dump(dump_path, MAGIC + bytes([0x02]) + cands[1:])
                else:
                    # Second pass excludes 0x01; candidates start at 0x02.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT | {0x01})
                    _write_dump(dump_path, MAGIC + cands)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertEqual(result, [0x01])
            self.assertEqual(call_count[0], 2)

    def test_multiple_divergences_accumulate(self):
        """
        Each iteration removes one bad char.  With two bad chars, three
        iterations should be needed (two divergences + one clean pass).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                known_bad = EXCLUDED_DEFAULT | set(
                    [0x01] * (call_count[0] > 1) +
                    [0x02] * (call_count[0] > 2)
                )
                cands = generate_candidate_bytes(known_bad)
                if call_count[0] == 1:
                    # Diverge on 0x01.
                    _write_dump(dump_path, MAGIC + bytes([0x02]) + cands[1:])
                elif call_count[0] == 2:
                    # 0x01 excluded now; diverge on 0x02.
                    _write_dump(dump_path, MAGIC + bytes([0x03]) + cands[1:])
                else:
                    # Clean pass.
                    _write_dump(dump_path, MAGIC + cands)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertIn(0x01, result)
            self.assertIn(0x02, result)
            self.assertEqual(call_count[0], 3)

    def test_truncated_observation_adds_bad_char(self):
        """
        A Truncated comparison result (observed shorter than expected) must
        surface the first missing byte as a bad char.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    # Candidates = [0x01..0xff]; truncate after first byte.
                    # observed = [0x01]; expected continues to 0x02 → Truncated.
                    _write_dump(dump_path, MAGIC + b"\x01")
                else:
                    # 0x02 is first "missing" byte → excluded next pass.
                    # This test just verifies something was added.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT | {0x02})
                    _write_dump(dump_path, MAGIC + cands)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertTrue(len(result) >= 1)


# ---------------------------------------------------------------------------
# Crash marker
# ---------------------------------------------------------------------------

class TestCrashMarker(unittest.TestCase):

    def test_crash_marker_stops_loop(self):
        """
        When is_running() returns False and saw_marker('BADCHAR_CRASH') is True,
        the loop must stop immediately and return an empty confirmed list.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            sender = MagicMock()  # never writes dump

            driver = _make_driver(is_running=False, saw_crash=True, wait_rc=1)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            self.assertEqual(result, [])
            driver.saw_marker.assert_called_with("BADCHAR_CRASH")

    def test_crash_marker_checked_with_correct_string(self):
        """saw_marker must be called with the literal string 'BADCHAR_CRASH'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            sender = MagicMock()
            driver = _make_driver(is_running=False, saw_crash=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            orch.run()

            calls = [str(c) for c in driver.saw_marker.call_args_list]
            self.assertTrue(
                any("BADCHAR_CRASH" in c for c in calls),
                "saw_marker was not called with 'BADCHAR_CRASH'",
            )

    def test_crash_after_partial_confirmation(self):
        """
        If one bad char was found before a crash, run() must return that
        partial list, not swallow it.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            call_count = [0]

            # After is_running returns False on the second iteration, driver
            # is treated as crashed.
            is_running_results = [True, True, True, False]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First pass: diverge on 0x01.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT)
                    _write_dump(dump_path, MAGIC + bytes([0x02]) + cands[1:])
                # Second call: no dump written → driver will crash.

            driver = MagicMock()
            driver.is_running.side_effect = is_running_results + [False] * 100
            driver.saw_marker.return_value = True
            driver.transcript.return_value = "BADCHAR_CRASH"
            driver.wait.return_value = 1

            orch = BadCharOrchestrator(
                driver=driver,
                stage=stage,
                sender=sender,
                offset=0,
                dump_dir=tmpdir,
                magic=MAGIC,
                timeout=2.0,
                restart_delay=0,
                max_iterations=10,
                excluded_bytes=EXCLUDED_DEFAULT,
            )
            result = orch.run()

            self.assertIn(0x01, result)


# ---------------------------------------------------------------------------
# Debugger exited (no crash marker)
# ---------------------------------------------------------------------------

class TestDebuggerExited(unittest.TestCase):

    def test_exit_without_crash_marker_stops_loop(self):
        """
        When is_running() returns False and no crash marker is present,
        the loop must stop and return an empty confirmed list.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            sender = MagicMock()

            driver = _make_driver(is_running=False, saw_crash=False, wait_rc=0)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=2.0)
            result = orch.run()

            self.assertEqual(result, [])

    def test_exit_without_marker_does_not_raise(self):
        """DebuggerExited must be handled gracefully, not propagated as an exception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stage  = _make_stage(tmpdir)
            driver = _make_driver(is_running=False, saw_crash=False)
            try:
                orch = _make_orchestrator(driver, stage, MagicMock(), tmpdir, timeout=2.0)
                orch.run()
            except Exception as exc:
                self.fail("run() raised unexpectedly on DebuggerExited: {}".format(exc))

    def test_exit_is_distinct_from_crash(self):
        """
        DEBUGGER_EXITED (no marker) and CRASH (marker present) must not be
        confused.  Verify that saw_marker() is the distinguishing call.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage = _make_stage(tmpdir)

            # Case 1: crashed
            d_crash = _make_driver(is_running=False, saw_crash=True)
            orch1   = _make_orchestrator(d_crash, stage, MagicMock(), tmpdir)
            orch1.run()
            d_crash.saw_marker.assert_called()

            # Case 2: clean exit
            d_exit = _make_driver(is_running=False, saw_crash=False)
            orch2  = _make_orchestrator(d_exit, stage, MagicMock(), tmpdir)
            orch2.run()
            d_exit.saw_marker.assert_called()


# ---------------------------------------------------------------------------
# File size stabilisation
# ---------------------------------------------------------------------------

class TestSizeStabilisation(unittest.TestCase):

    def test_dump_read_only_after_size_stable(self):
        """
        The orchestrator must not read a dump file that is still growing.
        Simulate by writing the file in two stages (small then full size).
        The test verifies the final result is correct, not partial.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage      = _make_stage(tmpdir)
            dump_path  = os.path.join(tmpdir, "dump.bin")
            candidates = generate_candidate_bytes(EXCLUDED_DEFAULT)
            full_dump  = MAGIC + candidates

            def sender(payload):
                # Write a partial file first, then the complete file slightly later.
                _write_dump(dump_path, full_dump[:2])
                # Overwrite with full content after a short pause.
                time.sleep(0.03)
                _write_dump(dump_path, full_dump)

            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir, timeout=3.0)
            result = orch.run()

            # If the partial write was consumed, magic would have failed.
            # A clean result means the full dump was read.
            self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# max_iterations guard
# ---------------------------------------------------------------------------

class TestMaxIterations(unittest.TestCase):

    def test_stops_after_max_iterations(self):
        """
        If bad chars are found on every iteration without a clean pass,
        run() must stop after max_iterations and return whatever was found.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                # Always diverge: inject wrong first byte.
                cands = generate_candidate_bytes(
                    EXCLUDED_DEFAULT | set(range(1, call_count[0]))
                )
                if cands:
                    _write_dump(dump_path, MAGIC + bytes([cands[0] ^ 0xFF]) + cands[1:])
                else:
                    _write_dump(dump_path, MAGIC + cands)

            driver = _make_driver(is_running=True)
            orch = BadCharOrchestrator(
                driver=driver,
                stage=stage,
                sender=sender,
                offset=0,
                dump_dir=tmpdir,
                magic=MAGIC,
                timeout=2.0,
                restart_delay=0,
                max_iterations=3,
                excluded_bytes=EXCLUDED_DEFAULT,
            )
            result = orch.run()

            self.assertLessEqual(call_count[0], 3)
            self.assertIsInstance(result, list)


# ---------------------------------------------------------------------------
# Conditional driver lifecycle
# ---------------------------------------------------------------------------

class TestConditionalRestart(unittest.TestCase):
    """
    _ensure_driver_running() must be lazy + conditional:
      - Persistent service targets: driver stays alive between iterations.
        start() must be called exactly once for the whole run.
      - Crash-per-payload targets: driver exits after each iteration.
        start() must be called at the beginning of every iteration.
    """

    def test_persistent_service_start_called_once(self):
        """
        When the driver stays alive across iterations, start() must be called
        exactly once regardless of how many iterations run.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First pass: diverge on 0x01.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT)
                    _write_dump(dump_path, MAGIC + bytes([0x02]) + cands[1:])
                else:
                    # Second pass: clean.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT | {0x01})
                    _write_dump(dump_path, MAGIC + cands)

            # is_running=True: first call returns False (so start() fires),
            # then True for all subsequent polls → simulates persistent service.
            driver = _make_driver(is_running=True)
            orch   = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertEqual(result, [0x01])
            # Exactly one start() call across both iterations.
            driver.start.assert_called_once()

    def test_crash_target_restarts_driver_each_iteration(self):
        """
        When the driver exits after delivering the first payload (crash-per-
        payload target), _ensure_driver_running() must restart it at the
        beginning of the next iteration.

        Simulate: driver exits immediately for every is_running() call, but
        we wire the CRASH path (saw_marker=True) only for iterations > 1 by
        manually controlling is_running side_effect to allow the first dump
        to be collected.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")
            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First iteration: write a diverging dump before driver exits.
                    cands = generate_candidate_bytes(EXCLUDED_DEFAULT)
                    _write_dump(dump_path, MAGIC + bytes([0x02]) + cands[1:])
                # Second iteration: no dump → driver exits → CRASH or DEBUGGER_EXITED.

            # Call sequence for is_running():
            #
            # Iteration 1:
            #   [0] _ensure_driver_running → False → start() called (count=1)
            #   _wait_for_dump: dump already written by sender, so
            #     _try_read_stable_dump() returns data immediately → is_running()
            #     is NOT called in the poll loop.
            #
            # Iteration 2:
            #   [1] _ensure_driver_running → False → start() called (count=2)
            #   [2] _wait_for_dump poll 1 → no dump → is_running()=False
            #       → _classify_exit() → CRASH (terminal)
            driver = MagicMock()
            driver.is_running.side_effect = [False, False, False] + [False] * 100
            driver.saw_marker.return_value = True   # CRASH path on exit
            driver.wait.return_value = 1

            orch = BadCharOrchestrator(
                driver=driver,
                stage=stage,
                sender=sender,
                offset=0,
                dump_dir=tmpdir,
                magic=MAGIC,
                timeout=2.0,
                restart_delay=0,
                max_iterations=10,
                excluded_bytes=EXCLUDED_DEFAULT,
            )
            result = orch.run()

            # Bad char from iteration 1 must be preserved.
            self.assertIn(0x01, result)
            # start() must have been called twice (once per iteration).
            self.assertEqual(driver.start.call_count, 2)

    def test_already_running_driver_not_started(self):
        """
        If the caller passes in a driver that is already running (is_running
        returns True on the very first call), start() must never be called.
        This models a driver that was started externally before run().
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            stage     = _make_stage(tmpdir)
            dump_path = os.path.join(tmpdir, "dump.bin")

            def sender(payload):
                # Write a clean dump immediately.
                _write_dump(dump_path, _make_clean_dump())

            driver = MagicMock()
            # Driver reports running from the very first call → never start().
            driver.is_running.return_value = True
            driver.saw_marker.return_value = False
            driver.wait.return_value = 0

            orch = _make_orchestrator(driver, stage, sender, tmpdir)
            result = orch.run()

            self.assertEqual(result, [])
            driver.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
