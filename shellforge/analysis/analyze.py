from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Callable

from shellforge.analysis.disasm import disassemble_bytes
from shellforge.analysis.entropy import shannon_entropy
from shellforge.analysis.printable import printable_ratio
from shellforge.hashes.crc32 import crc32_hash
from shellforge.hashes.rol import rol7_hash
from shellforge.hashes.ror13 import ror13_hash

_COMMON_API_SYMBOLS = [
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "CreateProcessA",
    "CreateProcessW",
    "WinExec",
    "WSAStartup",
    "WSASocketA",
    "connect",
    "NtAllocateVirtualMemory",
]


@dataclass(frozen=True, slots=True)
class AnalyzeMatch:
    offset: int
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class AnalyzeResult:
    detected_arch: str
    detection_confidence: float
    size: int
    entropy: float
    printable_ratio: float
    null_byte_count: int
    peb_walk_signatures: list[AnalyzeMatch]
    segment_access_signatures: list[AnalyzeMatch]
    egg_markers: list[AnalyzeMatch]
    nop_sleds: list[AnalyzeMatch]
    decoder_loop_signatures: list[AnalyzeMatch]
    api_hash_constants: list[AnalyzeMatch]
    api_hash_cross_references: list[dict[str, object]]
    entropy_windows: list[dict[str, float | int]]
    printable_strings: list[str]
    strings_truncated: bool
    heuristics: list[dict[str, object]]


def analyze_bytes(
    data: bytes,
    *,
    arch: str = "auto",
    window: int = 64,
    step: int = 16,
    strings_min_len: int = 4,
    max_strings: int = 50,
    max_hits: int = 25,
    hash_cross_reference: dict[int, list[str]] | None = None,
) -> AnalyzeResult:
    selected_arch, arch_confidence = _select_arch(data, arch)
    peb = _find_peb_walk_signatures(data)
    seg = _find_segment_access_signatures(data)
    eggs = _find_egg_markers(data)
    nops = _find_nop_sleds(data)
    decoders = _find_decoder_loop_signatures(data, selected_arch)
    hash_candidates = _find_api_hash_constants(data)
    hash_xrefs = _cross_reference_hash_constants(hash_candidates, hash_cross_reference)
    strings, strings_truncated = _extract_printable_strings(data, min_len=strings_min_len, max_count=max_strings)
    heuristics = _heuristics_summary(peb, seg, eggs, nops, decoders, hash_candidates, max_hits=max_hits)

    return AnalyzeResult(
        detected_arch=selected_arch,
        detection_confidence=arch_confidence,
        size=len(data),
        entropy=shannon_entropy(data),
        printable_ratio=printable_ratio(data),
        null_byte_count=data.count(0),
        peb_walk_signatures=peb,
        segment_access_signatures=seg,
        egg_markers=eggs,
        nop_sleds=nops,
        decoder_loop_signatures=decoders,
        api_hash_constants=hash_candidates,
        api_hash_cross_references=hash_xrefs,
        entropy_windows=_sliding_entropy(data, window=window, step=step),
        printable_strings=strings,
        strings_truncated=strings_truncated,
        heuristics=heuristics,
    )


def _select_arch(data: bytes, arch: str) -> tuple[str, float]:
    lowered = arch.lower()
    if lowered in {"x86", "x64"}:
        return lowered, 1.0
    if lowered != "auto":
        return "x86", 0.5

    x86_score = 0.0
    x64_score = 0.0

    x86_score += 0.7 * _count_occurrences(data, b"\x64\xa1\x30\x00\x00\x00")
    x86_score += 0.2 * _count_fs_modrm(data)
    x86_score += 0.1 * _count_push_imm_like(data)

    x64_score += 0.8 * _count_occurrences(data, b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")
    x64_score += 0.15 * _count_rex_prefix(data)
    x64_score += 0.1 * _count_occurrences(data, b"\x48\x83\xec\x28")  # common shadow-space style prologue

    if x64_score > x86_score:
        total = x64_score + x86_score
        confidence = 0.55 if total == 0 else min(0.99, 0.5 + ((x64_score - x86_score) / max(total, 1e-6)) * 0.5)
        return "x64", round(confidence, 2)

    total = x64_score + x86_score
    confidence = 0.55 if total == 0 else min(0.99, 0.5 + ((x86_score - x64_score) / max(total, 1e-6)) * 0.5)
    return "x86", round(confidence, 2)


def _find_peb_walk_signatures(data: bytes) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    # x86 mov eax, fs:[30h]
    pattern_x86 = b"\x64\xa1\x30\x00\x00\x00"
    start = 0
    while True:
        index = data.find(pattern_x86, start)
        if index < 0:
            break
        matches.append(AnalyzeMatch(offset=index, kind="peb_walk", detail="x86 fs:[0x30]"))
        start = index + 1

    # x64 mov rax, gs:[60h]
    pattern_x64 = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    start = 0
    while True:
        index = data.find(pattern_x64, start)
        if index < 0:
            break
        matches.append(AnalyzeMatch(offset=index, kind="peb_walk", detail="x64 gs:[0x60]"))
        start = index + 1
    return matches


def _find_segment_access_signatures(data: bytes) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    fs_direct = b"\x64\xa1\x30\x00\x00\x00"
    gs_direct = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    for token, detail in ((fs_direct, "FS:[30]"), (gs_direct, "GS:[60]")):
        start = 0
        while True:
            index = data.find(token, start)
            if index < 0:
                break
            matches.append(AnalyzeMatch(offset=index, kind="segment_access", detail=detail))
            start = index + 1
    return matches


def _count_occurrences(data: bytes, token: bytes) -> int:
    count = 0
    start = 0
    while True:
        idx = data.find(token, start)
        if idx < 0:
            break
        count += 1
        start = idx + 1
    return count


def _count_fs_modrm(data: bytes) -> int:
    # Broad x86 FS segment prefix usage.
    count = 0
    for i in range(0, max(0, len(data) - 2)):
        if data[i] == 0x64 and data[i + 1] in {0x8B, 0x8A, 0xA1, 0x89}:
            count += 1
    return count


def _count_push_imm_like(data: bytes) -> int:
    # push imm32 pattern starts with 0x68.
    return data.count(0x68)


def _count_rex_prefix(data: bytes) -> int:
    return sum(1 for b in data if 0x40 <= b <= 0x4F)


def _find_egg_markers(data: bytes) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    for i in range(0, max(0, len(data) - 7)):
        left = data[i : i + 4]
        right = data[i + 4 : i + 8]
        if left != right:
            continue
        if len(set(left)) <= 1:
            continue
        text = left.decode("latin-1")
        if all(32 <= b <= 126 for b in left):
            detail = f"{text}{text}"
        else:
            detail = left.hex() * 2
        matches.append(AnalyzeMatch(offset=i, kind="egg_marker", detail=detail))
    return matches


def _find_nop_sleds(data: bytes, minimum: int = 8) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    i = 0
    while i < len(data):
        if data[i] != 0x90:
            i += 1
            continue
        start = i
        while i < len(data) and data[i] == 0x90:
            i += 1
        run = i - start
        if run >= minimum:
            matches.append(AnalyzeMatch(offset=start, kind="nop_sled", detail=f"length={run}"))
    return matches


def _find_decoder_loop_signatures(data: bytes, arch: str) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    disasm = disassemble_bytes(data, arch=arch, base=0)
    inst = disasm.instructions
    for i in range(len(inst)):
        window = inst[i : i + 8]
        if len(window) < 4:
            continue
        arith = sum(1 for item in window if item.mnemonic in {"xor", "add", "sub"})
        loops = sum(1 for item in window if item.mnemonic in {"loop", "jnz", "jmp"})
        if arith >= 3 and loops >= 1:
            matches.append(
                AnalyzeMatch(
                    offset=window[0].address,
                    kind="decoder_loop",
                    detail=f"arith_ops={arith}, loop_ops={loops}",
                )
            )
    return matches


def _find_api_hash_constants(data: bytes) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    targets: dict[int, str] = {}
    for symbol in _COMMON_API_SYMBOLS:
        targets[ror13_hash(symbol)] = f"ror13:{symbol}"
        targets[crc32_hash(symbol)] = f"crc32:{symbol}"
        targets[rol7_hash(symbol)] = f"rol7:{symbol}"

    for i in range(0, max(0, len(data) - 3)):
        value = struct.unpack_from("<I", data, i)[0]
        if value in targets:
            matches.append(
                AnalyzeMatch(
                    offset=i,
                    kind="api_hash_constant",
                    detail=f"0x{value:08x} -> {targets[value]}",
                )
            )
    return matches


def build_hash_cross_reference(
    symbols: list[str],
    hasher: Callable[[str], int],
    *,
    namespace: str | None = None,
) -> dict[int, list[str]]:
    rows: dict[int, list[str]] = {}
    for symbol in symbols:
        value = hasher(symbol)
        label = symbol if namespace is None else f"{namespace}!{symbol}"
        rows.setdefault(value, []).append(label)
    return rows


def _cross_reference_hash_constants(
    matches: list[AnalyzeMatch], hash_cross_reference: dict[int, list[str]] | None
) -> list[dict[str, object]]:
    if not hash_cross_reference:
        return []
    rows: list[dict[str, object]] = []
    for item in matches:
        value = _extract_hash_value(item.detail)
        if value is None:
            continue
        candidates = sorted(hash_cross_reference.get(value, []))
        if not candidates:
            continue
        rows.append(
            {
                "offset": item.offset,
                "hash_value": value,
                "hash_hex": f"0x{value:08x}",
                "matches": candidates,
            }
        )
    return rows


def _extract_hash_value(detail: str) -> int | None:
    token = detail.split(" ", 1)[0].lower()
    if not token.startswith("0x"):
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def _sliding_entropy(data: bytes, window: int, step: int) -> list[dict[str, float | int]]:
    if window <= 0 or step <= 0 or len(data) < window:
        return []
    rows: list[dict[str, float | int]] = []
    for start in range(0, len(data) - window + 1, step):
        chunk = data[start : start + window]
        rows.append(
            {
                "offset": start,
                "size": window,
                "entropy": round(shannon_entropy(chunk), 6),
            }
        )
    return rows


def _extract_printable_strings(data: bytes, min_len: int = 4, max_count: int = 50) -> tuple[list[str], bool]:
    strings: list[str] = []
    current: list[int] = []
    truncated = False
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_len:
            strings.append(bytes(current).decode("ascii", errors="ignore"))
            if len(strings) >= max_count:
                truncated = True
                return strings[:max_count], truncated
        current = []
    if len(current) >= min_len:
        strings.append(bytes(current).decode("ascii", errors="ignore"))
        if len(strings) > max_count:
            truncated = True
    return strings[:max_count], truncated


def _heuristics_summary(
    peb: list[AnalyzeMatch],
    seg: list[AnalyzeMatch],
    eggs: list[AnalyzeMatch],
    nops: list[AnalyzeMatch],
    decoders: list[AnalyzeMatch],
    hashes: list[AnalyzeMatch],
    *,
    max_hits: int,
) -> list[dict[str, object]]:
    def row(name: str, matches: list[AnalyzeMatch], base_confidence: float) -> dict[str, object]:
        count = len(matches)
        confidence = 0.0 if count == 0 else min(0.99, base_confidence + (0.03 * min(count - 1, 3)))
        offsets = [item.offset for item in matches[:max_hits]]
        return {
            "name": name,
            "matched": count > 0,
            "confidence": round(confidence, 2),
            "offsets": offsets,
            "total_hits": count,
            "truncated": count > max_hits,
        }

    rows = [
        row("peb_walk", peb, 0.9),
        row("segment_access", seg, 0.85),
        row("egg_marker", eggs, 0.75),
        row("nop_sled", nops, 0.8),
        row("decoder_loop", decoders, 0.7),
        row("api_hash_constant", hashes, 0.65),
    ]
    rows.sort(key=lambda item: (not bool(item["matched"]), -float(item["confidence"]), str(item["name"])))
    return rows
