from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    FILE_NOT_FOUND = "file_not_found"
    FILE_READ_ERROR = "file_read_error"
    INVALID_PE_SIGNATURE = "invalid_pe_signature"
    INVALID_NT_SIGNATURE = "invalid_nt_signature"
    UNSUPPORTED_PE_FORMAT = "unsupported_pe_format"
    INVALID_OPTIONAL_HEADER = "invalid_optional_header"
    INVALID_RVA = "invalid_rva"
    PARSE_ERROR = "parse_error"
    INVALID_ARGUMENT = "invalid_argument"
    INTERNAL_ERROR = "internal_error"


class ShellforgeError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}
