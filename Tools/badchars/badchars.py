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
        """
        Compare expected vs observed memory bytes.

        :param expected: Bytes sent into the program
        :param observed: Bytes read back from memory
        :return: BadCharResult
        """
        # TODO:
        # - Walk both byte streams
        # - Detect:
        #   * missing bytes
        #   * altered bytes
        # - Populate:
        #   * badchars (list of ints)
        #   * transformed mapping (original -> observed)
        raise NotImplementedError
