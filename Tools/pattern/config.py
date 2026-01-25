# pattern/config.py

from dataclasses import dataclass
from typing import List, Literal


@dataclass(frozen=True)
class PatternConfig:
    word_size: int = 4
    endianness: Literal["little", "big"] = "little"
    alphabets: List[bytes] = None

    def __post_init__(self):
        if self.word_size not in (4, 8):
            raise ValueError("word_size must be 4 or 8")

        if self.alphabets is None:
            object.__setattr__(
                self,
                "alphabets",
                [
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    b"abcdefghijklmnopqrstuvwxyz",
                    b"0123456789",
                ],
            )

        if not self.alphabets or any(not a for a in self.alphabets):
            raise ValueError(
                "alphabets must be a non-empty list of non-empty byte sets"
            )
