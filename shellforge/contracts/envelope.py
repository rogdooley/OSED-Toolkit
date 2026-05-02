from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from shellforge.contracts.errors import ErrorCode
from shellforge.contracts.schema import SCHEMA_VERSION
from shellforge.contracts.version import TOOL_VERSION


@dataclass(frozen=True, slots=True)
class ResponseEnvelope:
    @staticmethod
    def _base(command: str) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "request_id": str(uuid4()),
            "command": command,
        }

    @classmethod
    def success(cls, *, command: str, result: dict[str, object]) -> dict[str, object]:
        envelope = cls._base(command)
        envelope.update({"ok": True, "result": result})
        return envelope

    @classmethod
    def error(
        cls,
        *,
        command: str,
        code: ErrorCode,
        message: str,
        details: dict[str, object] | None = None,
    ) -> dict[str, object]:
        envelope = cls._base(command)
        envelope.update(
            {
                "ok": False,
                "error": {
                    "code": code.value,
                    "message": message,
                    "details": details or {},
                },
            }
        )
        return envelope
