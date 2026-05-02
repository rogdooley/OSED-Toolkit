from __future__ import annotations

from shellforge.encoders.xor import XorEncoder
from shellforge.hashes.crc32 import CRC32HashProvider
from shellforge.hashes.rol import ROL7HashProvider
from shellforge.hashes.ror13 import ROR13HashProvider
from shellforge.interfaces import Encoder, HashProvider, PayloadProvider, TargetBackend
from shellforge.payloads.calc import CalcPayloadProvider
from shellforge.payloads.demo import DemoPayloadProvider
from shellforge.payloads.resolver import DynamicResolverPayloadProvider
from shellforge.targets.windows_x64 import WindowsX64Target
from shellforge.targets.windows_x86 import WindowsX86Target


def get_targets() -> dict[str, TargetBackend]:
    targets: list[TargetBackend] = [WindowsX86Target(), WindowsX64Target()]
    return {target.architecture.value: target for target in targets}


def get_payload_providers() -> dict[str, PayloadProvider]:
    providers: list[PayloadProvider] = [
        DemoPayloadProvider(),
        CalcPayloadProvider(),
        DynamicResolverPayloadProvider(),
    ]
    return {provider.name: provider for provider in providers}


def get_hash_providers() -> dict[str, HashProvider]:
    providers: list[HashProvider] = [ROR13HashProvider(), CRC32HashProvider(), ROL7HashProvider()]
    return {provider.name: provider for provider in providers}


def get_encoders() -> dict[str, Encoder]:
    encoders: list[Encoder] = [XorEncoder()]
    return {encoder.name: encoder for encoder in encoders}
