"""Minimal subprocess wrapper for cdb.exe (Python 3.7 compatible)."""

import io
import subprocess
import threading
from typing import Dict, List, Optional


class CDBDriver(object):
    def __init__(
        self,
        cdb_path,  # type: str
        target_command,  # type: List[str]
        script_path,  # type: str
        log_path=None,  # type: Optional[str]
        cwd=None,  # type: Optional[str]
        env=None,  # type: Optional[Dict[str, str]]
    ):
        if not cdb_path:
            raise ValueError("cdb_path is required")
        if not target_command:
            raise ValueError("target_command is required")
        if not script_path:
            raise ValueError("script_path is required")

        self._cdb_path = cdb_path
        self._target_command = list(target_command)
        self._script_path = script_path
        self._log_path = log_path
        self._cwd = cwd
        self._env = env

        self._proc = None  # type: Optional[subprocess.Popen]
        self._reader = None  # type: Optional[threading.Thread]
        self._transcript_parts = []  # type: List[str]
        self._transcript_lock = threading.Lock()
        self._stop_reader = threading.Event()
        self._log_handle = None  # type: Optional[io.TextIOBase]

    def start(self):
        # type: () -> None
        if self._proc is not None and self.is_running():
            raise RuntimeError("process is already running")

        self._stop_reader.clear()
        self._transcript_parts = []

        if self._log_path:
            self._log_handle = open(self._log_path, "w", encoding="utf-8")

        args = [self._cdb_path, "-o", "-g", "-G", "-cf", self._script_path]
        args.extend(self._target_command)

        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=self._cwd,
            env=self._env,
            universal_newlines=True,
            bufsize=1,
        )

        self._reader = threading.Thread(target=self._reader_loop, name="cdb-reader")
        self._reader.daemon = True
        self._reader.start()

    def kill(self):
        # type: () -> None
        proc = self._proc
        if proc is None:
            return

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                proc.kill()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    pass

        self._stop_reader.set()
        self._join_reader()
        self._close_log()

    def is_running(self):
        # type: () -> bool
        return self._proc is not None and self._proc.poll() is None

    def has_live_target(self):
        # type: () -> bool
        """
        Conservative target-liveness signal for orchestration decisions.

        Fail-closed semantics: returns False when uncertain.
        This minimal driver cannot reliably distinguish "cdb alive, inferior
        dead" from "fully usable session", so the safe default is False.
        """
        return False

    def wait(self, timeout=None):
        # type: (Optional[float]) -> int
        if self._proc is None:
            raise RuntimeError("process has not been started")

        returncode = self._proc.wait(timeout=timeout)
        self._join_reader()
        self._close_log()
        return returncode

    def transcript(self):
        # type: () -> str
        with self._transcript_lock:
            return "".join(self._transcript_parts)

    def saw_marker(self, marker):
        # type: (str) -> bool
        if marker is None:
            raise ValueError("marker is required")
        return marker in self.transcript()

    def _reader_loop(self):
        # type: () -> None
        proc = self._proc
        if proc is None or proc.stdout is None:
            return

        while True:
            line = proc.stdout.readline()
            if line:
                self._append_transcript(line)
                continue
            if proc.poll() is not None:
                break
            if self._stop_reader.is_set():
                break

    def _append_transcript(self, text):
        # type: (str) -> None
        with self._transcript_lock:
            self._transcript_parts.append(text)
        if self._log_handle is not None:
            self._log_handle.write(text)
            self._log_handle.flush()

    def _join_reader(self):
        # type: () -> None
        if self._reader is not None and self._reader.is_alive():
            self._reader.join(timeout=1.0)

    def _close_log(self):
        # type: () -> None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
