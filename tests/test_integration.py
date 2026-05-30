import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from badchars_wds.analyzer import generate_candidate_bytes
from badchars_wds.config import ConfigValidationError, load_config
from badchars_wds.orchestrator import BadCharOrchestrator
from badchars_wds.transport import CallbackSender
from fakes import (
    CAPTURED_PAYLOADS,
    FakeCrashMarkerDriver,
    FakeDumpWriter,
    FakeExitedDriver,
    FakePersistentDriver,
    reset_captured_payloads,
)


MAGIC_HEX = "bcf0bcf0"
MAGIC = bytes.fromhex(MAGIC_HEX)


def _base_config(tmpdir):
    return {
        "driver": {
            "cdb_path": "cdb.exe",
            "target_command": ["target.exe"],
        },
        "stage": {
            "breakpoint": "mod!fn",
            "dump_expr": "poi(@esp+4)",
            "dump_size": 512,
            "step_mode": "pt",
            "temp_dump_path": os.path.join(tmpdir, "_tmp.bin"),
            "final_dump_path": os.path.join(tmpdir, "dump.bin"),
        },
        "orchestrator": {
            "offset": 0,
            "dump_dir": tmpdir,
            "magic": MAGIC_HEX,
            "timeout": 0.3,
            "restart_delay": 0.0,
            "max_iterations": 5,
            "excluded_bytes": [0],
            "restart_policy": "conditional",
        },
        "transport": {
            "type": "callback",
            "callback_name": "fakes.capture_payload",
        },
    }


class TestIntegration(unittest.TestCase):
    def test_persistent_profile_divergence_then_clean(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_data = _base_config(tmpdir)
            cfg_path = os.path.join(tmpdir, "config.json")
            with open(cfg_path, "w", encoding="utf-8") as handle:
                json.dump(cfg_data, handle)

            loaded = load_config(cfg_path)
            driver = FakePersistentDriver()
            dump = FakeDumpWriter(loaded.stage.final_dump_path)

            call_count = [0]

            def sender(payload):
                call_count[0] += 1
                if call_count[0] == 1:
                    candidates = generate_candidate_bytes(set([0]))
                    dump.write(MAGIC + b"\x02" + candidates[1:])
                else:
                    candidates = generate_candidate_bytes(set([0, 1]))
                    dump.write(MAGIC + candidates)

            orch = BadCharOrchestrator(
                driver=driver,
                stage=loaded.stage,
                sender=sender,
                offset=loaded.offset,
                dump_dir=loaded.dump_dir,
                magic=loaded.magic,
                timeout=loaded.timeout,
                restart_delay=loaded.restart_delay,
                max_iterations=loaded.max_iterations,
                excluded_bytes=loaded.excluded_bytes,
                restart_policy=loaded.restart_policy,
            )
            result = orch.run()
            self.assertEqual(result, [1])
            self.assertEqual(driver.start_calls, 1)
            self.assertEqual(driver.kill_calls, 1)

    def test_crash_marker_branch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = load_config(_write_cfg(tmpdir, _base_config(tmpdir)))
            driver = FakeCrashMarkerDriver()

            def sender(_payload):
                driver.trigger_crash()

            orch = BadCharOrchestrator(
                driver=driver,
                stage=loaded.stage,
                sender=sender,
                offset=loaded.offset,
                dump_dir=loaded.dump_dir,
                magic=loaded.magic,
                timeout=loaded.timeout,
                restart_delay=loaded.restart_delay,
                max_iterations=loaded.max_iterations,
                excluded_bytes=loaded.excluded_bytes,
                restart_policy=loaded.restart_policy,
            )
            result = orch.run()
            self.assertEqual(result, [])
            self.assertEqual(driver.wait_calls, 0)

    def test_debugger_exited_branch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = load_config(_write_cfg(tmpdir, _base_config(tmpdir)))
            driver = FakeExitedDriver()

            def sender(_payload):
                driver.trigger_exit(7)

            orch = BadCharOrchestrator(
                driver=driver,
                stage=loaded.stage,
                sender=sender,
                offset=loaded.offset,
                dump_dir=loaded.dump_dir,
                magic=loaded.magic,
                timeout=loaded.timeout,
                restart_delay=loaded.restart_delay,
                max_iterations=loaded.max_iterations,
                excluded_bytes=loaded.excluded_bytes,
                restart_policy=loaded.restart_policy,
            )
            result = orch.run()
            self.assertEqual(result, [])
            self.assertEqual(driver.wait_calls, 1)

    def test_config_aggregates_issues_with_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = _base_config(tmpdir)
            del bad["transport"]["callback_name"]
            bad["stage"]["dump_exr"] = bad["stage"].pop("dump_expr")
            bad["transport"]["port"] = "9999"
            bad["transport"]["type"] = "tcp"

            path = _write_cfg(tmpdir, bad)
            with self.assertRaises(ConfigValidationError) as ctx:
                load_config(path)

            issues = ctx.exception.issues
            paths = [i.path for i in issues]
            self.assertIn("stage.dump_exr", paths)
            self.assertIn("stage.dump_expr", paths)
            self.assertIn("transport.host", paths)
            self.assertIn("transport.port", paths)
            self.assertTrue(all(i.actual_repr is not None for i in issues))

    def test_override_conflicting_forms_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = _write_cfg(tmpdir, _base_config(tmpdir))
            with self.assertRaises(ConfigValidationError) as ctx:
                load_config(
                    cfg_path,
                    overrides={
                        "dump-expr": "poi(@esp+8)",
                        "dump_expr": "poi(@esp+12)",
                    },
                )
            self.assertTrue(any("conflicting arguments" in i.message for i in ctx.exception.issues))

    def test_callback_sender_from_callback_name(self):
        reset_captured_payloads()
        sender = CallbackSender(callback_name="fakes.capture_payload")
        sender.send(b"ABC")
        self.assertEqual(CAPTURED_PAYLOADS[-1], b"ABC")


def _write_cfg(tmpdir, data):
    path = os.path.join(tmpdir, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return path


if __name__ == "__main__":
    unittest.main()
