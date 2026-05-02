from __future__ import annotations

from shellforge.contracts.errors import ErrorCode, ShellforgeError


class ExceptionMapper:
    @staticmethod
    def to_error(exc: Exception) -> tuple[ErrorCode, str, dict[str, object]]:
        if isinstance(exc, ShellforgeError):
            details = dict(exc.details)
            details.setdefault("exception_type", exc.__class__.__name__)
            return exc.code, str(exc), details
        if isinstance(exc, FileNotFoundError):
            return ErrorCode.FILE_NOT_FOUND, str(exc), {"exception_type": exc.__class__.__name__}
        if isinstance(exc, (PermissionError, OSError)):
            return ErrorCode.FILE_READ_ERROR, str(exc), {"exception_type": exc.__class__.__name__}
        if isinstance(exc, ValueError):
            return ErrorCode.INVALID_ARGUMENT, str(exc), {"exception_type": exc.__class__.__name__}
        return ErrorCode.INTERNAL_ERROR, "Unhandled internal error", {"exception_type": exc.__class__.__name__}
