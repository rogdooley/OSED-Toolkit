"""Hash algorithms for export-name-to-address resolution in shellcode."""


def ror_hash(name: str, rotation: int = 13) -> int:
    """ROR-N + ADD per byte. Industry standard, default ROR-13."""
    h = 0
    for c in name:
        h = ((h >> rotation) | (h << (32 - rotation))) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def rolxor_hash(name: str, rotation: int = 7) -> int:
    """ROL-N + XOR per byte. Metasploit variant, default ROL-7."""
    h = 0
    for c in name:
        h = ((h << rotation) | (h >> (32 - rotation))) & 0xFFFFFFFF
        h = (h ^ ord(c)) & 0xFFFFFFFF
    return h


ALGOS: dict = {
    'ror':    ror_hash,
    'rolxor': rolxor_hash,
}

DEFAULT_ROTATION: dict = {
    'ror':    13,
    'rolxor': 7,
}


def compute_hash(name: str, algo: str, rotation: int) -> int:
    """Compute a hash using the named algorithm at the given rotation."""
    return ALGOS[algo](name, rotation)
