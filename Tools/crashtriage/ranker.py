from .models import ArchType, Candidate, ParsedCrash, RegisterValue

X86_PRIMARY = {"EIP"}
X86_STACK = {"ESP", "EBP"}
X64_PRIMARY = {"RIP"}
X64_STACK = {"RSP", "RBP"}


def infer_arch(parsed: ParsedCrash, forced_arch: str = "auto") -> ArchType:
    if forced_arch in ("x86", "x64"):
        return forced_arch

    reg_names = {reg.name for reg in parsed.registers}
    if any(name.startswith("R") for name in reg_names):
        return "x64"
    return "x86"


def _expected_width_for_arch(arch: ArchType) -> int:
    return 4 if arch == "x86" else 8


def _score_register(reg: RegisterValue, arch: ArchType) -> tuple[int, str]:
    if arch == "x86":
        if reg.name in X86_PRIMARY:
            return 100, "instruction pointer register"
        if reg.name in X86_STACK:
            return 80, "stack/base register"
        return 60, "general-purpose register"

    if reg.name in X64_PRIMARY:
        return 100, "instruction pointer register"
    if reg.name in X64_STACK:
        return 80, "stack/base register"
    return 60, "general-purpose register"


def _confidence(priority: int, width_ok: bool) -> tuple[str, str]:
    if priority >= 100 and width_ok:
        return "high", "IP register with expected width"
    if priority >= 80 and width_ok:
        return "medium", "strong signal with expected width"
    if width_ok:
        return "medium", "plausible candidate with expected width"
    return "low", "value width mismatches expected architecture"


def rank_candidates(parsed: ParsedCrash, arch: ArchType) -> list[Candidate]:
    candidates: list[Candidate] = []
    expected_width = _expected_width_for_arch(arch)
    seen: set[tuple[str | None, str]] = set()

    for reg in parsed.registers:
        priority, priority_reason = _score_register(reg, arch)
        width_ok = reg.width_bytes == expected_width
        conf, conf_reason = _confidence(priority, width_ok)
        reason = f"{priority_reason}; {conf_reason}"
        key = (reg.name, reg.value_hex)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            Candidate(
                register=reg.name,
                value_hex=reg.value_hex,
                source_line=reg.source_line,
                priority=priority,
                confidence=conf,
                reason=reason,
            )
        )

    for value in parsed.exception_values:
        width_ok = (len(value) // 2) == expected_width
        conf = "medium" if width_ok else "low"
        reason = (
            "exception/fault value; expected width match"
            if width_ok
            else "exception/fault value; width mismatch"
        )
        key = (None, value)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            Candidate(
                register=None,
                value_hex=value,
                source_line="exception context",
                priority=90,
                confidence=conf,
                reason=reason,
            )
        )

    return sorted(
        candidates,
        key=lambda c: (c.priority, c.confidence == "high", c.confidence == "medium"),
        reverse=True,
    )
