# tools/badchars/badchars.py

from typing import Dict, Iterable, List


class BadCharResult:
    """
    Represents the result of a bad character analysis.
    """

    def __init__(
        self,
        badchars: List[int],
        transformed: Dict[int, int],
    ):
        self.badchars = badchars
        self.transformed = transformed

    def __bool__(self) -> bool:
        return bool(self.badchars or self.transformed)


class BadCharAnalyzer:
    """
    Compares intended input bytes against observed memory bytes
    to identify bad characters and transformations.
    """

    def __init__(self, exclude: Iterable[int] = (0x00,)):
        """
        :param exclude: Bytes to exclude from testing (e.g. null byte)
        """
        self.exclude = set(exclude)

    def generate_test_bytes(self) -> bytes:
        """
        Generate a canonical badchar test sequence.
        Typical output: \\x01\\x02...\\xff (minus excluded bytes)
        """
        return bytes(i for i in range(256) if i not in self.exclude)

    def analyze(
        self,
        expected: bytes,
        observed: bytes,
    ) -> BadCharResult:
        badchars = set()
        transformed = {}

        i = 0  # index into expected
        j = 0  # index into observed

        while i < len(expected):
            # Case 4 — observed exhausted
            if j >= len(observed):
                badchars.update(expected[i:])
                break

            exp = expected[i]
            obs = observed[j]

            # Case 1 — exact match
            if exp == obs:
                i += 1
                j += 1
                continue

            # Case 2 — observed byte appears later in expected
            try:
                next_match = expected.index(obs, i + 1)
            except ValueError:
                next_match = None

            if next_match is not None:
                # Bytes between i and next_match are missing
                for k in range(i, next_match):
                    badchars.add(expected[k])
                i = next_match
                continue

            # Case 3 — transformation
            badchars.add(exp)
            transformed[exp] = obs
            i += 1
            j += 1

        return BadCharResult(
            badchars=sorted(badchars),
            transformed=transformed,
        )
