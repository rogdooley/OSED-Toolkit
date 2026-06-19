"""
Thin deterministic state machine for bad character discovery.

State machine (per iteration):
    ENSURE_DRIVER -> PREPARE -> SEND -> WAIT_FOR_DUMP ->
    VALIDATE -> ANALYZE -> CLASSIFY -> UPDATE_STATE -> CLEANUP

Lifecycle model: lazy + conditional.
    The driver is started only when not already running.

    Persistent service targets (SLMail, FTP daemons):
        Driver starts once and stays alive across all iterations.
        No unnecessary process churn.

    Crash-per-payload targets (Vulnserver, single-process apps):
        Driver exits after each payload lands.
        _ensure_driver_running() detects this and restarts automatically.

    Assumption (v1): is_running() reflects cdb process liveness only.
    It does not distinguish cdb-alive-but-inferior-dead state.
    That case requires driver.is_session_usable() (future work).

Responsibilities:
    - iteration lifecycle
    - excluded byte state
    - dump synchronisation policy
    - coordination of helpers

Does NOT own:
    - debugger script rendering  (wds.py)
    - subprocess management      (cdb.py)
    - byte comparison logic      (analyzer.py)
    - transport logic            (caller's sender callback)

Logging:
    All log records carry an ``iter`` key via LoggerAdapter.
    To surface it in output, configure a format that includes %(iter)s.
    Example:
        logging.basicConfig(format="[iter=%(iter)s] %(levelname)s %(message)s")
"""

import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Set, Union

from .analyzer import compare_observed, generate_candidate_bytes, validate_magic
from .cdb import CDBDriver
from .models import Divergence, Match, Stage, Truncated, WDSConfig
from .wds import generate_wds

_module_logger = logging.getLogger(__name__)

_CRASH_MARKER = "BADCHAR_CRASH"
_SCRIPT_FILENAME = "badchar_bp.wds"
_SIZE_SETTLE_SECONDS = 0.02
_POLL_INTERVAL_SECONDS = 0.05
_STALE_RETRY_DELAY_SECONDS = 0.05


# ---------------------------------------------------------------------------
# Iteration result taxonomy
# ---------------------------------------------------------------------------

class IterationStatus(Enum):
    """
    Exhaustive classification of iteration outcomes.
    Terminal statuses stop the loop. Retry statuses continue it.
    """
    CLEAN           = "clean"            # all candidates matched; no bad chars
    DIVERGENCE      = "divergence"       # one bad byte found (mismatch)
    TRUNCATED       = "truncated"        # one bad byte found (observed too short)
    TIMEOUT         = "timeout"          # dump never appeared in time
    CRASH           = "crash"            # debugger exited with crash marker
    INVALID_DUMP    = "invalid_dump"     # dump too short or wrong magic
    DEBUGGER_EXITED = "debugger_exited"  # debugger exited, no crash marker


class RestartPolicy(Enum):
    ALWAYS = "always"
    CONDITIONAL = "conditional"
    NEVER = "never"


_RETRY_STATUSES = frozenset({
    IterationStatus.DIVERGENCE,
    IterationStatus.TRUNCATED,
})


@dataclass
class IterationResult:
    """
    Structured outcome for one iteration.
    Used at every stage boundary; never collapsed into bare booleans or
    generic exceptions.
    """
    status:    IterationStatus
    iteration: int
    bad_byte:  Optional[int] = None   # set on DIVERGENCE / TRUNCATED
    reason:    Optional[str] = None   # human-readable context for terminal states


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class BadCharOrchestrator(object):
    """
    Coordinates bad character discovery as a thin state machine.

    Payload layout per iteration:
        [A * offset][MAGIC][candidate_bytes][C * 32]

    Invariant: dump_expr in Stage must evaluate to the address where MAGIC
    begins in the destination buffer after the copy, so that:
        dump[0 : len(magic)] == magic
    The caller is responsible for constructing dump_expr accordingly
    (e.g. "poi(@esp+4)+2606" rather than "poi(@esp+4)" for a 2606-byte offset).
    """

    def __init__(
        self,
        driver,           # type: CDBDriver
        stage,            # type: Stage
        sender,           # type: Callable[[bytes], None]
        offset,           # type: int
        dump_dir,         # type: str
        magic,            # type: bytes
        timeout,          # type: float
        restart_delay,    # type: float
        max_iterations,   # type: int
        excluded_bytes,   # type: Set[int]
        restart_policy=RestartPolicy.CONDITIONAL,  # type: RestartPolicy
        filler_byte=0x41,  # type: int
        pad_byte=0x43,     # type: int
        pad_len=32,        # type: int
    ):
        if not callable(sender):
            raise TypeError("sender must be callable")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if restart_delay < 0:
            raise ValueError("restart_delay must be >= 0")
        if max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")
        if not isinstance(restart_policy, RestartPolicy):
            raise TypeError("restart_policy must be a RestartPolicy")
        if not (0 <= filler_byte <= 0xFF):
            raise ValueError("filler_byte must be in 0..255")
        if not (0 <= pad_byte <= 0xFF):
            raise ValueError("pad_byte must be in 0..255")
        if pad_len < 0:
            raise ValueError("pad_len must be >= 0")

        # Hard failure: magic bytes that overlap excluded bytes make the
        # dump validation mechanism self-defeating from iteration one.
        validate_magic(magic, excluded_bytes)

        # The dumped region must be large enough to hold the magic plus every
        # candidate byte, otherwise the observed buffer is truncated by the
        # debugger itself and every iteration reports a spurious bad byte.
        excluded_set = set(excluded_bytes)
        candidate_count = 256 - len([b for b in excluded_set if 0 <= b <= 0xFF])
        min_dump_size = len(magic) + candidate_count
        if stage.dump_size < min_dump_size:
            raise ValueError(
                "stage.dump_size={} too small; need >= {} "
                "(magic {} + candidates {})".format(
                    stage.dump_size, min_dump_size, len(magic), candidate_count,
                )
            )

        self._driver          = driver
        self._stage           = stage
        self._sender          = sender
        self._offset          = offset
        self._dump_dir        = dump_dir
        self._magic           = magic
        self._timeout         = float(timeout)
        self._restart_delay   = float(restart_delay)
        self._max_iterations  = max_iterations
        self._excluded_bytes  = frozenset(excluded_bytes)  # never mutated
        self._restart_policy  = restart_policy
        self._filler_byte     = filler_byte
        self._pad_byte        = pad_byte
        self._pad_len         = pad_len

        # A filler or pad byte that is itself a known bad char silently
        # corrupts the payload before the candidate region is reached.
        for label, value in (("filler_byte", filler_byte), ("pad_byte", pad_byte)):
            if value in self._excluded_bytes:
                self._log_warn_pending = (
                    "{}=0x{:02x} is in excluded_bytes; payload framing may be "
                    "corrupted on this target".format(label, value)
                )
                break
        else:
            self._log_warn_pending = None

        self._script_path = os.path.join(dump_dir, _SCRIPT_FILENAME)
        self._dump_path   = self._resolve_dump_path()

        # LoggerAdapter injects iteration context into every log record.
        # Update self._log_extra["iter"] at the top of each iteration.
        self._log_extra = {"iter": 0}
        self._log = logging.LoggerAdapter(_module_logger, self._log_extra)
        if restart_policy == RestartPolicy.NEVER:
            self._log.warning(
                "restart_policy=never may produce invalid results on unstable targets"
            )
        if self._log_warn_pending:
            self._log.warning(self._log_warn_pending)

        # Runtime state — reset at the start of every run() call so run()
        # is safely re-entrant.
        self._iteration = 0
        self._excluded  = set()   # type: Set[int]
        self._confirmed = []      # type: List[int]

        # How the most recent run() ended. Lets callers distinguish
        # "completed cleanly, no bad chars" from "stopped early on a fault".
        # One of: "clean", "exhausted", or a terminal IterationStatus value.
        self.final_status = None       # type: Optional[str]
        self.final_reason = None       # type: Optional[str]

    # -----------------------------------------------------------------------
    # Public
    # -----------------------------------------------------------------------

    def run(self):
        # type: () -> List[int]
        """
        Execute the full iterative bad character discovery loop.

        Returns a sorted list of confirmed bad character byte values.
        Stops on the first terminal condition.

        Guarantees driver.kill() is called on all exit paths, including
        exceptions raised by the sender or filesystem operations.
        """
        self._iteration = 0
        self._excluded  = set(self._excluded_bytes)
        self._confirmed = []
        self.final_status = None
        self.final_reason = None

        try:
            while self._iteration < self._max_iterations:
                self._iteration += 1
                self._log_extra["iter"] = self._iteration

                result = self._run_iteration()

                if result.status == IterationStatus.CLEAN:
                    self._log.info("status=CLEAN")
                    self.final_status = "clean"
                    break

                if result.status in _RETRY_STATUSES:
                    self._update_state(result)
                    continue

                # Terminal condition — log and stop. No automatic retry.
                self._log.warning(
                    "terminal status=%s reason=%s",
                    result.status.value,
                    result.reason or "none",
                )
                self.final_status = result.status.value
                self.final_reason = result.reason
                break
            else:
                self._log.warning(
                    "max_iterations=%d reached without clean pass",
                    self._max_iterations,
                )
                self.final_status = "exhausted"
                self.final_reason = "max_iterations={} reached".format(
                    self._max_iterations
                )
        finally:
            self._driver.kill()

        final = sorted(set(self._confirmed))
        self._log.info(
            "complete confirmed_count=%d bad_chars=[%s]",
            len(final),
            _fmt_hex(final),
        )
        return final

    # -----------------------------------------------------------------------
    # Iteration
    # -----------------------------------------------------------------------

    def _run_iteration(self):
        # type: () -> IterationResult
        """
        Execute one complete pass through the state machine stages.
        Returns a single structured IterationResult; no hidden side effects.
        """
        self._ensure_driver_running()

        candidates = self._prepare_iteration()
        self._send_buffer(candidates)

        raw = self._wait_for_dump()
        if isinstance(raw, IterationResult):
            self._cleanup_iteration(raw)
            return raw

        observed = self._validate_dump(raw, len(candidates))
        if isinstance(observed, IterationResult):
            self._cleanup_iteration(observed)
            return observed

        comparison = self._analyze_dump(observed, candidates)
        result     = self._classify_result(comparison)
        self._cleanup_iteration(result)
        return result

    # -----------------------------------------------------------------------
    # Stages
    # -----------------------------------------------------------------------

    def _ensure_driver_running(self):
        # type: () -> None
        """
        Start the debugger if needed, honouring the restart policy.

        is_running() is the liveness signal:
          - ALWAYS:      kill any running session, then start fresh every
                         iteration.
          - NEVER:       keep a running session; (re)start only when not
                         running. Warned about at construction time.
          - CONDITIONAL: keep a running session (persistent services such as
                         SLMail), and start only when not running — which is
                         exactly the first iteration, or a crash-per-payload
                         target (Vulnserver) whose cdb exited after the
                         previous payload landed.

        Design note: CONDITIONAL trusts is_running() alone. The previous
        implementation also consulted driver.has_live_target(), but that
        signal is documented as fail-closed (False when uncertain). Treating
        "uncertain" as "dead" forced a kill+restart on *every* iteration, so
        persistent services were needlessly relaunched and the conditional
        policy was indistinguishable from ALWAYS. A future driver that can
        positively detect "cdb alive but inferior dead" should surface that as
        an explicit restart trigger; uncertainty must never force a restart.
        """
        running = self._driver.is_running()

        if running:
            if self._restart_policy == RestartPolicy.ALWAYS:
                self._driver.kill()
            else:
                # NEVER and CONDITIONAL both keep a live session.
                return

        self._write_script()
        self._log.debug("stage=START_DRIVER script=%s", self._script_path)
        self._driver.start()
        if self._restart_delay > 0:
            time.sleep(self._restart_delay)

    def _prepare_iteration(self):
        # type: () -> bytes
        """Clear any stale dump and generate fresh candidate bytes."""
        self._clear_stale_dump()
        candidates = generate_candidate_bytes(self._excluded)
        self._log.debug(
            "stage=PREPARE candidates=%d excluded=[%s]",
            len(candidates),
            _fmt_hex(sorted(self._excluded)),
        )
        return candidates

    def _send_buffer(self, candidates):
        # type: (bytes) -> None
        """Build the payload and transmit it through the caller-supplied sender."""
        payload = self._build_payload(candidates)
        self._log.debug("stage=SEND payload_len=%d", len(payload))
        self._sender(payload)

    def _wait_for_dump(self):
        # type: () -> Union[bytes, IterationResult]
        """
        Poll for dump.bin until one of:
          - file appears and size is stable  → returns raw bytes
          - driver exits                     → IterationResult (CRASH or DEBUGGER_EXITED)
          - timeout elapses                  → IterationResult (TIMEOUT)

        All timeout policy lives here. No other component enforces timeouts.
        Uses time.monotonic() to avoid sensitivity to system clock changes.
        """
        self._log.debug("stage=WAIT_FOR_DUMP timeout=%.1fs", self._timeout)
        deadline = time.monotonic() + self._timeout

        while time.monotonic() < deadline:
            data = self._try_read_stable_dump()
            if data is not None:
                return data

            if not self._driver.is_running():
                return self._classify_exit()

            time.sleep(_POLL_INTERVAL_SECONDS)

        return IterationResult(
            status=IterationStatus.TIMEOUT,
            iteration=self._iteration,
            reason="dump_not_found elapsed={:.1f}s".format(self._timeout),
        )

    def _validate_dump(self, data, expected_observed_len):
        # type: (bytes, int) -> Union[bytes, IterationResult]
        """
        Validate magic prefix and minimum size.

        Returns observed bytes (magic stripped) on success.
        Returns IterationResult(INVALID_DUMP) if magic is absent or wrong.

        A dump where magic is valid but the observed region is shorter than
        expected is logged but not classified as INVALID_DUMP here; the
        analyzer will surface it as Truncated, which the classify stage
        handles correctly. This is a classification boundary choice, not a
        correctness gap.
        """
        magic_len = len(self._magic)

        if len(data) < magic_len:
            return IterationResult(
                status=IterationStatus.INVALID_DUMP,
                iteration=self._iteration,
                reason="short_dump_no_magic actual={} minimum={}".format(
                    len(data), magic_len,
                ),
            )

        if data[:magic_len] != self._magic:
            return IterationResult(
                status=IterationStatus.INVALID_DUMP,
                iteration=self._iteration,
                reason="magic_mismatch found=0x{} expected=0x{}".format(
                    data[:magic_len].hex(), self._magic.hex(),
                ),
            )

        observed = data[magic_len:]

        if len(observed) < expected_observed_len:
            self._log.debug(
                "stage=VALIDATE short_observed actual=%d expected=%d "
                "(will surface as Truncated in comparison)",
                len(observed),
                expected_observed_len,
            )

        return observed

    def _analyze_dump(self, observed, candidates):
        """Delegate byte comparison to the analyzer. No interpretation here."""
        return compare_observed(candidates, observed)

    def _classify_result(self, comparison):
        # type: (...) -> IterationResult
        """Map a ComparisonResult to a structured IterationResult."""
        if isinstance(comparison, Match):
            return IterationResult(
                status=IterationStatus.CLEAN,
                iteration=self._iteration,
            )

        bad_byte = _extract_bad_byte(comparison)

        if isinstance(comparison, Divergence):
            self._log.info(
                "stage=ANALYZE divergence offset=0x%x expected=0x%02x actual=0x%02x",
                comparison.offset,
                comparison.expected_byte,
                comparison.actual_byte if comparison.actual_byte is not None else -1,
            )
            return IterationResult(
                status=IterationStatus.DIVERGENCE,
                iteration=self._iteration,
                bad_byte=bad_byte,
                reason="offset=0x{:x}".format(comparison.offset),
            )

        if isinstance(comparison, Truncated):
            self._log.info(
                "stage=ANALYZE truncated offset=0x%x expected=0x%02x",
                comparison.offset,
                comparison.expected_byte,
            )
            return IterationResult(
                status=IterationStatus.TRUNCATED,
                iteration=self._iteration,
                bad_byte=bad_byte,
                reason="offset=0x{:x}".format(comparison.offset),
            )

        # Defensive: unknown comparison type should never occur given the
        # current analyzer contract, but classified explicitly rather than
        # silently ignored.
        self._log.warning(
            "stage=ANALYZE unknown_result type=%s",
            type(comparison).__name__,
        )
        return IterationResult(
            status=IterationStatus.INVALID_DUMP,
            iteration=self._iteration,
            reason="unknown_comparison_result type={}".format(
                type(comparison).__name__,
            ),
        )

    def _classify_exit(self):
        # type: () -> IterationResult
        """Determine why the driver exited without producing a dump."""
        if self._driver.saw_marker(_CRASH_MARKER):
            self._log.warning("stage=WAIT_FOR_DUMP crash_marker_found")
            return IterationResult(
                status=IterationStatus.CRASH,
                iteration=self._iteration,
                reason="crash_marker_in_transcript",
            )
        try:
            rc = self._driver.wait(timeout=2.0)
        except Exception:
            rc = -1
        self._log.warning(
            "stage=WAIT_FOR_DUMP debugger_exited returncode=%d", rc,
        )
        return IterationResult(
            status=IterationStatus.DEBUGGER_EXITED,
            iteration=self._iteration,
            reason="returncode={}".format(rc),
        )

    def _update_state(self, result):
        # type: (IterationResult) -> None
        """Record a confirmed bad character and expand the exclusion set."""
        if result.bad_byte is not None:
            self._excluded.add(result.bad_byte)
            self._confirmed.append(result.bad_byte)
            self._log.info(
                "state=UPDATE bad_byte=0x%02x cumulative=%d confirmed=[%s]",
                result.bad_byte,
                len(self._confirmed),
                _fmt_hex(sorted(self._confirmed)),
            )

    def _cleanup_iteration(self, result):
        # type: (IterationResult) -> None
        """Log iteration boundary. Placeholder for future cleanup needs."""
        self._log.debug(
            "stage=CLEANUP status=%s bad_byte=%s",
            result.status.value,
            "0x{:02x}".format(result.bad_byte) if result.bad_byte is not None else "none",
        )

    # -----------------------------------------------------------------------
    # Filesystem subsystem
    # -----------------------------------------------------------------------

    def _try_read_stable_dump(self):
        # type: () -> Optional[bytes]
        """
        Single non-blocking attempt to read a stable dump file.

        This is the sole synchronisation point for dump acquisition.
        Returns raw bytes if the file is present and size-stable.
        Returns None if the file is absent, mid-write, or unreadable.

        Size stability is enforced by two stat() calls separated by
        _SIZE_SETTLE_SECONDS. Mismatching sizes indicate an in-progress write;
        None is returned and the caller retries on the next poll cycle.
        """
        if not os.path.exists(self._dump_path):
            return None
        try:
            s1 = os.path.getsize(self._dump_path)
            time.sleep(_SIZE_SETTLE_SECONDS)
            s2 = os.path.getsize(self._dump_path)
        except OSError:
            return None
        if s1 != s2 or s1 == 0:
            return None
        try:
            with open(self._dump_path, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def _clear_stale_dump(self):
        # type: () -> None
        """Remove any leftover dump file before the next iteration's send."""
        try:
            os.remove(self._dump_path)
            self._log.debug("cleared_stale_dump path=%s", self._dump_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            self._log.warning(
                "stale_dump_delete_failed attempt=1 path=%s error=%s",
                self._dump_path,
                exc,
            )
            time.sleep(_STALE_RETRY_DELAY_SECONDS)
            try:
                os.remove(self._dump_path)
                self._log.debug("cleared_stale_dump_retry path=%s", self._dump_path)
            except FileNotFoundError:
                return
            except OSError as retry_exc:
                raise RuntimeError(
                    "failed to delete stale dump after retry: {}".format(self._dump_path)
                ) from retry_exc

    # -----------------------------------------------------------------------
    # Script and payload helpers
    # -----------------------------------------------------------------------

    def _write_script(self):
        # type: () -> None
        config  = WDSConfig(stage=self._stage)
        content = generate_wds(config)
        os.makedirs(self._dump_dir, exist_ok=True)
        with open(self._script_path, "w") as fh:
            fh.write(content)
        self._log.debug("wrote_script path=%s", self._script_path)

    def _build_payload(self, candidates):
        # type: (bytes) -> bytes
        leading = bytes([self._filler_byte]) * self._offset
        trailing = bytes([self._pad_byte]) * self._pad_len
        return leading + self._magic + candidates + trailing

    def _resolve_dump_path(self):
        # type: () -> str
        """Resolve final_dump_path to absolute. Relative paths join dump_dir."""
        path = self._stage.final_dump_path
        if os.path.isabs(path):
            return path
        return os.path.join(self._dump_dir, path)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _extract_bad_byte(result):
    # type: (...) -> Optional[int]
    """
    Return the problematic byte from a ComparisonResult.

    Centralises knowledge of analyzer result structure so that the orchestrator
    does not interpret Divergence / Truncated fields at multiple call sites.
    If the analyzer contract changes, only this function needs updating.
    """
    if isinstance(result, (Divergence, Truncated)):
        return result.expected_byte
    return None


def _fmt_hex(values):
    # type: (List[int]) -> str
    return " ".join("0x{:02x}".format(v) for v in values)
