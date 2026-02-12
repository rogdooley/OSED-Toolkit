from .models import TriageResult


def format_human(result: TriageResult) -> str:
    lines: list[str] = []
    lines.append("[*] Crash triage summary")
    lines.append(f"  arch: {result.detected_arch}")
    lines.append(f"  endianness: {result.endianness}")
    lines.append(f"  exception: {result.exception or 'not detected'}")
    lines.append("")

    if result.candidates:
        lines.append("[*] Candidates")
        for candidate in result.candidates:
            reg = candidate.register or "EXCEPTION"
            lines.append(
                f"  {reg}: {candidate.value_hex} ({candidate.confidence}) - {candidate.reason}"
            )
    else:
        lines.append("[-] No candidates parsed")

    lines.append("")
    if result.recommendations:
        lines.append("[*] Suggested commands")
        for recommendation in result.recommendations:
            lines.append(f"  {recommendation.command}")
    else:
        lines.append("[-] No command recommendations generated")

    if result.notes:
        lines.append("")
        lines.append("[*] Notes")
        for note in result.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)


def format_json(result: TriageResult) -> dict:
    return {
        "detected_arch": result.detected_arch,
        "endianness": result.endianness,
        "exception": result.exception,
        "candidates": [
            {
                "register": c.register,
                "value_hex": c.value_hex,
                "priority": c.priority,
                "confidence": c.confidence,
                "reason": c.reason,
                "source_line": c.source_line,
            }
            for c in result.candidates
        ],
        "recommendations": [
            {
                "query": r.query,
                "raw": r.raw,
                "command": r.command,
                "based_on": r.based_on,
            }
            for r in result.recommendations
        ],
        "notes": result.notes,
    }
