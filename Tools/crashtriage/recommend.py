from .models import ArchType, Candidate, Recommendation


def _fit_query(value_hex: str, arch: ArchType) -> tuple[str | None, str | None]:
    expected_chars = 8 if arch == "x86" else 16

    if len(value_hex) == expected_chars:
        return value_hex, None

    if len(value_hex) > expected_chars:
        trimmed = value_hex[-expected_chars:]
        return trimmed, f"trimmed wider value {value_hex} to {trimmed}"

    return None, f"value {value_hex} too short for {arch}"


def build_recommendations(
    candidates: list[Candidate],
    *,
    length: int,
    arch: ArchType,
    endianness: str,
    all_candidates: bool = False,
) -> tuple[list[Recommendation], list[str]]:
    recommendations: list[Recommendation] = []
    notes: list[str] = []

    selected = candidates if all_candidates else candidates[:3]

    for candidate in selected:
        query, note = _fit_query(candidate.value_hex, arch)
        if note:
            notes.append(f"{candidate.register or 'EXCEPTION'}: {note}")
        if query is None:
            continue

        base = (
            "python -m Tools.pattern.cli.pattern_offset "
            f"-l {length} -q {query} --arch {arch} --endianness {endianness}"
        )
        source = candidate.register or "EXCEPTION"
        recommendations.append(
            Recommendation(
                query=query,
                raw=False,
                command=base,
                based_on=source,
            )
        )
        recommendations.append(
            Recommendation(
                query=query,
                raw=True,
                command=f"{base} --raw",
                based_on=source,
            )
        )

    if not candidates:
        notes.append("No register or exception candidates were parsed from the input.")
    elif not recommendations:
        notes.append("Candidates were found, but none had compatible width for recommendations.")

    return recommendations, notes
