"""Model definitions for WDS generation and byte comparison."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Stage:
    breakpoint: str
    dump_expr: str
    dump_size: int
    step_mode: str = "none"
    custom_step: Optional[str] = None
    temp_dump_path: str = "dump.tmp.bin"
    final_dump_path: str = "dump.bin"
    quit_after_dump: bool = False


@dataclass
class WDSConfig:
    stage: Stage
    enable_second_chance_av: bool = True


class ComparisonResult(object):
    """Base model for all comparison outcomes."""

    def __init__(self, kind):
        self.kind = kind


class Match(ComparisonResult):
    """Expected and observed byte sequences are identical."""

    def __init__(self):
        super(Match, self).__init__("match")


class Truncated(ComparisonResult):
    """Observed bytes ended before expected bytes."""

    def __init__(
        self,
        offset,  # type: int
        expected_byte,  # type: int
        remaining_expected_len,  # type: int
        observed_len,  # type: int
    ):
        super(Truncated, self).__init__("truncated")
        self.offset = offset
        self.expected_byte = expected_byte
        self.remaining_expected_len = remaining_expected_len
        self.observed_len = observed_len


class Divergence(ComparisonResult):
    """Observed byte differs from expected at a specific offset."""

    def __init__(
        self,
        offset,  # type: int
        expected_byte,  # type: int
        actual_byte,  # type: Optional[int]
        remaining_expected_len,  # type: int
        observed_len,  # type: int
    ):
        super(Divergence, self).__init__("divergence")
        self.offset = offset
        self.expected_byte = expected_byte
        self.actual_byte = actual_byte
        self.remaining_expected_len = remaining_expected_len
        self.observed_len = observed_len
