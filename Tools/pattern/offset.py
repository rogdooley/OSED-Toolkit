# pattern/offset.py

from typing import Optional, Union

from .config import PatternConfig
from .generator import PatternGenerator

QueryType = Union[str, bytes, int]


class OffsetResolver:
    def __init__(self, config: PatternConfig):
        self.config = config
        self.generator = PatternGenerator(config)

    def find_offset(
        self,
        length: int,
        query: QueryType,
        *,
        raw: bool = False,
    ) -> Optional[int]:
        """
        Locate the offset of a crashed register value within a generated pattern.

        :param length: Length of the original pattern
        :param query: Hex string, bytes, or integer value from debugger
        :param raw: If True, treat query as raw memory bytes (no endian reversal)
        :return: Offset as int, or None if not found
        """

        # STEP 1 — normalize query to bytes
        needle = self._normalize_query(query, raw=raw)

        # STEP 2 — validate length matches word size
        if len(needle) != self.config.word_size:
            raise ValueError(
                f"Query length {len(needle)} does not match word size {self.config.word_size}"
            )

        # STEP 3 — regenerate pattern
        pattern = self.generator.create(length)

        # STEP 4 — search
        offset = pattern.find(needle)
        return offset if offset != -1 else None

    def _normalize_query(self, query: QueryType, *, raw: bool) -> bytes:
        """
        Convert query input into a byte sequence suitable for pattern searching.

        Rules:
        - Hex strings and integers represent register values
        - Apply endianness reversal unless raw=True
        - Raw bytes are treated as memory order
        """

        # CASE 1 — bytes (memory order)
        if isinstance(query, bytes):
            return query

        # CASE 2 — integer (register value)
        if isinstance(query, int):
            b = query.to_bytes(self.config.word_size, "big")
            if not raw and self.config.endianness == "little":
                b = b[::-1]
            return b

        # CASE 3 — string (assume hex register value)
        if isinstance(query, str):
            # TODO:
            # 1. Strip optional "0x"
            # 2. Validate hex string
            # 3. Convert hex → bytes
            # 4. Apply endianness reversal unless raw=True
            # 5. Return bytes
            if query.startswith("0x"):
                stripped_query = query[2:]
            else:
                stripped_query = query

            if len(stripped_query) % 2 != 0:
                raise ValueError(f"Query string {query} is not a hex string!")

            b = bytes.fromhex(stripped_query)

            if not raw and self.config.endianness == "little":
                b = b[::-1]

            return b

        raise TypeError(f"Unsupported query type: {type(query)}")
