from dataclasses import dataclass


@dataclass
class Attempt:
    breakpoint: str
    dump_expr: str
    confidence: float
    result: str  # 'pass', 'fail', 'timeout'
    reason: str  # empty string on pass


@dataclass
class LocatedResult:
    copy_site_id: str
    breakpoint: str
    dump_expr: str
    confidence: float
    attempts: list[Attempt]


@dataclass
class ValidationFailure:
    attempts: list[Attempt]
