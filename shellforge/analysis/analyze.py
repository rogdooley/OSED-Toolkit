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
    architecture_fingerprints: list[AnalyzeMatch]
    size: int
    entropy: float
    printable_ratio: float
    null_byte_count: int
    peb_walk_signatures: list[AnalyzeMatch]
    segment_access_signatures: list[AnalyzeMatch]
    egg_markers: list[AnalyzeMatch]
    nop_sleds: list[AnalyzeMatch]
    decoder_loop_signatures: list[AnalyzeMatch]
    xor_decoder_loop_signatures: list[AnalyzeMatch]
    additive_decoder_loop_signatures: list[AnalyzeMatch]
    api_hash_constants: list[AnalyzeMatch]
    api_hash_loop_signatures: list[AnalyzeMatch]
    api_hash_cross_references: list[dict[str, object]]
    entropy_windows: list[dict[str, float | int]]
    suspicious_entropy_windows: list[dict[str, float | int | str]]
    printable_strings: list[str]
    strings_truncated: bool
    likely_resolver_stubs: list[AnalyzeMatch]
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
    arch_fingerprints = _find_architecture_fingerprints(data)
    peb = _find_peb_walk_signatures(data)
    seg = _find_segment_access_signatures(data)
    eggs = _find_egg_markers(data)
    nops = _find_nop_sleds(data)
    xor_decoders, add_decoders = _find_decoder_loop_signatures(data, selected_arch)
    decoders = sorted(xor_decoders + add_decoders, key=lambda item: (item.offset, item.detail))
    hash_candidates = _find_api_hash_constants(data)
    api_hash_loops = _find_api_hash_loop_signatures(data, selected_arch)
    hash_xrefs = _cross_reference_hash_constants(hash_candidates, hash_cross_reference)
    entropy_profile = _sliding_entropy(data, window=window, step=step)
    suspicious_entropy = _find_suspicious_entropy_windows(entropy_profile)
    strings, strings_truncated = _extract_printable_strings(data, min_len=strings_min_len, max_count=max_strings)
    resolver_stubs = _find_likely_resolver_stubs(peb, seg, api_hash_loops, hash_candidates)
    heuristics = _heuristics_summary(
        peb,
        seg,
        eggs,
        nops,
        xor_decoders,
        add_decoders,
        hash_candidates,
        api_hash_loops,
        suspicious_entropy,
        resolver_stubs,
        max_hits=max_hits,
    )

    return AnalyzeResult(
        detected_arch=selected_arch,
        detection_confidence=arch_confidence,
        architecture_fingerprints=arch_fingerprints,
        size=len(data),
        entropy=shannon_entropy(data),
        printable_ratio=printable_ratio(data),
        null_byte_count=data.count(0),
        peb_walk_signatures=peb,
        segment_access_signatures=seg,
        egg_markers=eggs,
        nop_sleds=nops,
        decoder_loop_signatures=decoders,
        xor_decoder_loop_signatures=xor_decoders,
        additive_decoder_loop_signatures=add_decoders,
        api_hash_constants=hash_candidates,
        api_hash_loop_signatures=api_hash_loops,
        api_hash_cross_references=hash_xrefs,
        entropy_windows=entropy_profile,
        suspicious_entropy_windows=suspicious_entropy,
        printable_strings=strings,
        strings_truncated=strings_truncated,
        likely_resolver_stubs=resolver_stubs,
        heuristics=heuristics,
    )


def _find_architecture_fingerprints(data: bytes) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    for token, detail in (
        (b"\x64\xa1\x30\x00\x00\x00", "x86 fs:[0x30]"),
        (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "x64 gs:[0x60]"),
        (b"\x48\x83\xec\x28", "x64 shadow space prologue"),
    ):
        start = 0
        while True:
            index = data.find(token, start)
            if index < 0:
                break
            matches.append(AnalyzeMatch(offset=index, kind="arch_fingerprint", detail=detail))
            start = index + 1
    return matches


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


def _find_decoder_loop_signatures(data: bytes, arch: str) -> tuple[list[AnalyzeMatch], list[AnalyzeMatch]]:
    xor_matches: list[AnalyzeMatch] = []
    add_matches: list[AnalyzeMatch] = []
    disasm = disassemble_bytes(data, arch=arch, base=0)
    inst = disasm.instructions
    for i in range(len(inst)):
        window = inst[i : i + 8]
        if len(window) < 4:
            continue
        xor_ops = sum(1 for item in window if item.mnemonic == "xor")
        add_ops = sum(1 for item in window if item.mnemonic in {"add", "sub", "inc", "dec"})
        loops = sum(1 for item in window if item.mnemonic in {"loop", "jnz", "jmp"})
        if xor_ops >= 2 and loops >= 1:
            xor_matches.append(
                AnalyzeMatch(
                    offset=window[0].address,
                    kind="xor_decoder_loop",
                    detail=f"xor_ops={xor_ops}, loop_ops={loops}",
                )
            )
        if add_ops >= 2 and loops >= 1:
            add_matches.append(
                AnalyzeMatch(
                    offset=window[0].address,
                    kind="additive_decoder_loop",
                    detail=f"arith_ops={add_ops}, loop_ops={loops}",
                )
            )
    return xor_matches, add_matches


def _find_api_hash_loop_signatures(data: bytes, arch: str) -> list[AnalyzeMatch]:
    matches: list[AnalyzeMatch] = []
    disasm = disassemble_bytes(data, arch=arch, base=0)
    inst = disasm.instructions
    for i in range(len(inst)):
        window = inst[i : i + 12]
        if len(window) < 5:
            continue
        rotates = sum(1 for item in window if item.mnemonic in {"ror", "rol"})
        mix_ops = sum(1 for item in window if item.mnemonic in {"add", "xor"})
        loop_ops = sum(1 for item in window if item.mnemonic in {"jnz", "loop", "jmp"})
        byte_walk = any(item.mnemonic in {"lodsb", "movzx"} for item in window)
        if rotates >= 1 and mix_ops >= 1 and loop_ops >= 1 and byte_walk:
            matches.append(
                AnalyzeMatch(
                    offset=window[0].address,
                    kind="api_hash_loop",
                    detail=f"rotates={rotates}, mix_ops={mix_ops}, loop_ops={loop_ops}",
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


def _find_suspicious_entropy_windows(
    rows: list[dict[str, float | int]], *, high_threshold: float = 5.8
) -> list[dict[str, float | int | str]]:
    suspicious: list[dict[str, float | int | str]] = []
    for row in rows:
        entropy = float(row["entropy"])
        if entropy < high_threshold:
            continue
        suspicious.append(
            {
                "offset": int(row["offset"]),
                "size": int(row["size"]),
                "entropy": entropy,
                "label": "high_entropy",
            }
        )
    return suspicious


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
    xor_decoders: list[AnalyzeMatch],
    add_decoders: list[AnalyzeMatch],
    hashes: list[AnalyzeMatch],
    hash_loops: list[AnalyzeMatch],
    suspicious_entropy: list[dict[str, float | int | str]],
    resolver_stubs: list[AnalyzeMatch],
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
        row("xor_decoder_loop", xor_decoders, 0.72),
        row("additive_decoder_loop", add_decoders, 0.7),
        row("api_hash_constant", hashes, 0.65),
        row("api_hash_loop", hash_loops, 0.77),
        row("suspicious_entropy_window", [AnalyzeMatch(offset=int(item["offset"]), kind="entropy", detail=str(item["label"])) for item in suspicious_entropy], 0.68),
        row("likely_resolver_stub", resolver_stubs, 0.83),
    ]
    rows.sort(key=lambda item: (not bool(item["matched"]), -float(item["confidence"]), str(item["name"])))
    return rows


def _find_likely_resolver_stubs(
    peb: list[AnalyzeMatch],
    seg: list[AnalyzeMatch],
    hash_loops: list[AnalyzeMatch],
    hash_constants: list[AnalyzeMatch],
) -> list[AnalyzeMatch]:
    if not peb and not seg:
        return []
    if not hash_loops and not hash_constants:
        return []
    anchor = min([item.offset for item in (peb + seg + hash_loops + hash_constants)])
    return [
        AnalyzeMatch(
            offset=anchor,
            kind="likely_resolver_stub",
            detail=(
                f"peb_or_segment={len(peb) + len(seg)}, "
                f"hash_loops={len(hash_loops)}, hash_constants={len(hash_constants)}"
            ),
        )
    ]
