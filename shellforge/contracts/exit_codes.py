from __future__ import annotations

from shellforge.contracts.errors import ErrorCode


class ExitCodeMapper:
    SUCCESS = 0
    INVALID_ARGS = 2
    FILE_ERROR = 3
    PARSE_ERROR = 4
    UNSUPPORTED_FORMAT = 5
    INTERNAL = 10

    @classmethod
    def from_error_code(cls, code: ErrorCode) -> int:
        if code == ErrorCode.INVALID_ARGUMENT:
            return cls.INVALID_ARGS
        if code in {ErrorCode.FILE_NOT_FOUND, ErrorCode.FILE_READ_ERROR}:
            return cls.FILE_ERROR
        if code == ErrorCode.UNSUPPORTED_PE_FORMAT:
            return cls.UNSUPPORTED_FORMAT
        if code in {
            ErrorCode.INVALID_PE_SIGNATURE,
            ErrorCode.INVALID_NT_SIGNATURE,
            ErrorCode.INVALID_OPTIONAL_HEADER,
            ErrorCode.INVALID_RVA,
            ErrorCode.PARSE_ERROR,
        }:
            return cls.PARSE_ERROR
        return cls.INTERNAL
