from shellforge.hashes.crc32 import CRC32HashProvider, crc32_hash
from shellforge.hashes.rol import ROL7HashProvider, rol7_hash
from shellforge.hashes.ror13 import ROR13HashProvider, ror13_hash

HASHERS = {
    "ror13": ror13_hash,
    "crc32": crc32_hash,
    "rol7": rol7_hash,
}

__all__ = [
    "HASHERS",
    "ROR13HashProvider",
    "CRC32HashProvider",
    "ROL7HashProvider",
    "ror13_hash",
    "crc32_hash",
    "rol7_hash",
]
