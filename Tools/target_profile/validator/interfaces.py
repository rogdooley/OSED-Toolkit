from typing import Protocol


class PayloadSender(Protocol):
    def send(self, payload: bytes) -> None: ...


class DebuggerBackend(Protocol):
    def capture_dump(
        self, breakpoint: str, dump_expr: str, sender: PayloadSender
    ) -> bytes: ...
