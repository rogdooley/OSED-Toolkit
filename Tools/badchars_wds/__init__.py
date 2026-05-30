"""Deterministic WinDbg/cdb script generator."""

from .analyzer import compare_observed, generate_candidate_bytes, validate_magic
from .cdb import CDBDriver
from .models import (
    ComparisonResult,
    Divergence,
    Match,
    Stage,
    Truncated,
    WDSConfig,
)
from .orchestrator import (
    BadCharOrchestrator,
    IterationResult,
    IterationStatus,
    RestartPolicy,
)
from .wds import generate_wds

__all__ = [
    "BadCharOrchestrator",
    "ComparisonResult",
    "CDBDriver",
    "Divergence",
    "IterationResult",
    "IterationStatus",
    "RestartPolicy",
    "Match",
    "Stage",
    "Truncated",
    "WDSConfig",
    "compare_observed",
    "generate_candidate_bytes",
    "generate_wds",
    "validate_magic",
]
