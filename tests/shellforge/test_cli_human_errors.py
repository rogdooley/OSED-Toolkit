from __future__ import annotations

from shellforge.cli import main


def test_human_error_is_mapped_without_traceback(capsys) -> None:
    code = main(["pe", "list", "/tmp/does_not_exist.bin"])
    assert code == 3
    stderr = capsys.readouterr().err
    assert "ERROR [pe.list][file_not_found]" in stderr
    assert "Traceback" not in stderr


def test_human_error_verbose_includes_exception_type(capsys) -> None:
    code = main(["--verbose", "pe", "list", "/tmp/does_not_exist.bin"])
    assert code == 3
    stderr = capsys.readouterr().err
    assert "ERROR [pe.list][file_not_found][FileNotFoundError]" in stderr
