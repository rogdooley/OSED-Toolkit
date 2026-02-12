import json
import subprocess
import sys
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures" / "crashtriage"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "Tools.crashtriage.cli.triage_crash", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_human_success():
    dump_file = FIXTURES / "x86_windbg_eip_clean.txt"
    result = _run_cli("-l", "3000", "--input", str(dump_file))
    assert result.returncode == 0
    assert "Crash triage summary" in result.stdout
    assert "EIP: 42306142" in result.stdout


def test_cli_json_success():
    dump_file = FIXTURES / "x64_rip_clean.txt"
    result = _run_cli("-l", "5000", "--input", str(dump_file), "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["detected_arch"] == "x64"
    assert payload["candidates"][0]["register"] == "RIP"


def test_cli_parse_failure_exit_code_2():
    dump_file = FIXTURES / "malformed_noise_only.txt"
    result = _run_cli("-l", "1000", "--input", str(dump_file))
    assert result.returncode == 2
