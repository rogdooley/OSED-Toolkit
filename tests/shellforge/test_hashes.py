from shellforge.hashes.crc32 import crc32_hash
from shellforge.hashes.rol import rol7_hash
from shellforge.hashes.ror13 import ror13_hash


def test_ror13_known_value() -> None:
    assert ror13_hash("GetProcAddress") == 0x7C0DFCAA


def test_crc32_known_value() -> None:
    assert crc32_hash("GetProcAddress") == 0xC97C1FFF


def test_rol7_known_value() -> None:
    assert rol7_hash("GetProcAddress") == 0xFC7F1554
