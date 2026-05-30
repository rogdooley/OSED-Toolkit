import os
import socket
import time
from typing import Callable, List, Optional, Set, Tuple

from Tools.badchars.badchars import BadCharAnalyzer, BadCharResult


class BadCharLoop:
    """
    Automates bad character discovery:
    1. Sends a payload via a caller-supplied sender function
    2. Waits for WinDbg to write a memory dump via .writemem + rename
    3. Analyzes with BadCharAnalyzer
    4. Iterates until no new bad chars are found

    Requires the WinDbg script in scripts/badchar_bp.wds to be active.
    """

    def __init__(
        self,
        sender: Callable[[bytes], None],
        offset: int,
        total_size: int,
        dump_path: str = r"C:\badchar\dump.bin",
        exclude: Tuple[int, ...] = (0x00,),
        timeout: int = 15,
    ):
        self.sender = sender
        self.offset = offset
        self.total_size = total_size
        self.dump_path = dump_path
        self.exclude = set(exclude)
        self.timeout = timeout
        self.analyzer = BadCharAnalyzer(exclude=self.exclude)

    def _build_payload(self, test_bytes: bytes) -> bytes:
        pad = max(0, self.total_size - self.offset - len(test_bytes))
        return b"A" * self.offset + test_bytes + b"C" * pad

    def _wait_for_dump(self) -> bool:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if os.path.exists(self.dump_path):
                return True
            time.sleep(0.1)
        return False

    def _read_dump(self, expected_len: int) -> bytes:
        with open(self.dump_path, "rb") as f:
            data = f.read()
        os.remove(self.dump_path)
        return data[:expected_len]

    def run_once(self, known_bad: Optional[Set[int]] = None) -> BadCharResult:
        """Send one payload and return the analysis result."""
        if known_bad is None:
            known_bad = set()

        test_bytes = bytes(
            b for b in range(1, 256)
            if b not in self.exclude and b not in known_bad
        )

        if os.path.exists(self.dump_path):
            os.remove(self.dump_path)

        payload = self._build_payload(test_bytes)
        self.sender(payload)

        if not self._wait_for_dump():
            raise TimeoutError(
                "Dump not written to {} within {}s. "
                "Check the WinDbg breakpoint is active.".format(self.dump_path, self.timeout)
            )

        observed = self._read_dump(len(test_bytes))
        return self.analyzer.analyze(test_bytes, observed)

    def run_full(self, max_iterations: int = 30) -> List[int]:
        """Iterate until the test sequence passes clean. Returns sorted bad char list."""
        known_bad = set()  # type: Set[int]

        for i in range(1, max_iterations + 1):
            candidates = 255 - len(self.exclude) - len(known_bad)
            print("[*] Iteration {}: testing {} bytes".format(i, candidates))

            result = self.run_once(known_bad)

            if not result.badchars and not result.transformed:
                print("[+] Clean pass. Confirmed bad chars: {}".format(_fmt(sorted(known_bad))))
                return sorted(known_bad)

            newly_found = set(result.badchars) | set(result.transformed.keys())
            known_bad |= newly_found
            print("[!] Found this pass: {}".format(_fmt(sorted(newly_found))))
            print("[*] Cumulative:      {}".format(_fmt(sorted(known_bad))))

            for src, dst in result.transformed.items():
                print("    0x{:02x} -> 0x{:02x} (transformed)".format(src, dst))

        print("[-] Max iterations reached. Known bad: {}".format(_fmt(sorted(known_bad))))
        return sorted(known_bad)


def _fmt(badchars: List[int]) -> str:
    return " ".join("\\x{:02x}".format(b) for b in badchars)


def make_tcp_sender(host: str, port: int) -> Callable[[bytes], None]:
    """Raw TCP sender — wrap this to add protocol framing (e.g. SMTP PASS, FTP USER)."""
    def send(payload: bytes) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, port))
            s.sendall(payload)
        finally:
            s.close()
    return send
