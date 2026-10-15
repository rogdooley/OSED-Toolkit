"""Host-side source-contract checks for the Windows-only common library."""

from __future__ import annotations

from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
COMMON = LAB_ROOT / "common"


def test_common_api_uses_explicit_lengths_for_socket_and_file_input() -> None:
    """Replacing an explicit-length read with a string API must fail here."""
    header = (COMMON / "io_helpers.h").read_text(encoding="utf-8")
    assert "common_recv_exact(SOCKET socket_fd, uint8_t *buffer, size_t length" in header
    assert "common_read_file_all(const wchar_t *path, uint8_t **out, size_t *out_len" in header

    source = (COMMON / "io_helpers.c").read_text(encoding="utf-8")
    for forbidden in ("strcpy", "strncpy", "strlen", "strchr", "%s"):
        assert forbidden not in source
    assert "recv(" in source
    assert "ReadFile(" in source
    assert "DWORD_MAX" not in source
    assert "MAXDWORD" in source


def test_stage_trace_is_compile_time_optional_and_has_no_runtime_control_channel() -> None:
    """Exposing tracing in student binaries must fail this boundary check."""
    header = (COMMON / "stage_trace.h").read_text(encoding="utf-8")
    source = (COMMON / "stage_trace.c").read_text(encoding="utf-8")
    assert "stage_trace_capture" in header
    assert "BADCHARS_INSTRUCTOR_TRACE" in source
    for forbidden in ("CreateNamedPipe", "CreateFile", "GetEnvironmentVariable", "socket("):
        assert forbidden not in source
