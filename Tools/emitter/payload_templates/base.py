"""Base class and config dataclass for payload templates."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class TemplateConfig:
    """Runtime parameters for a payload template."""
    lhost: str = "127.0.0.1"
    lport: int = 4444
    command: str = "cmd.exe"
    src_path: str = "C:\\source.txt"
    dst_path: str = "C:\\dest.txt"
    badchars: set[int] = field(default_factory=lambda: {0x00})


class PayloadTemplate(ABC):
    """Base class for all payload templates.

    Subclasses declare REQUIRED_FUNCTIONS and REQUIRED_VARIABLES, then
    implement emit() to generate payload-specific assembly.

    Contract: emit() MUST use layout.slot(name).ebp_ref for all stack
    references. Hardcoded [ebp-0xNN] offsets are forbidden.
    """

    REQUIRED_FUNCTIONS: tuple[str, ...] = ()
    REQUIRED_VARIABLES: tuple[str, ...] = ()

    @abstractmethod
    def emit(self, layout, config: TemplateConfig) -> str:
        """Emit payload-specific assembly.

        Returns a string of assembly text with a comment header.
        All [ebp-0xNN] references must come from layout.slot(name).ebp_ref.
        """
