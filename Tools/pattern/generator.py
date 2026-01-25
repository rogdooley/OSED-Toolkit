# pattern/generator.py

from itertools import product

from .config import PatternConfig


class PatternGenerator:
    def __init__(self, config: PatternConfig):
        self.config = config

    def create(self, length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be positive")

        output = bytearray()

        # Cartesian product over alphabet sets
        for token in product(*self.config.alphabets):
            output.extend(token)

            if len(output) >= length:
                return bytes(output[:length])

        return bytes(output[:length])
