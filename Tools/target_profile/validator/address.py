from interfaces import DebuggerBackend, PayloadSender
from results import Attempt, LocatedResult, ValidationFailure
from schema import CandidateProfile


def validate_address(
    profile: CandidateProfile,
    backend: DebuggerBackend,
    sender: PayloadSender,
    magic: bytes,
) -> LocatedResult | None:

    attempts: list[Attempt] = []

    # iterate over copy sites
    for copy_site in profile.copy_sites:
        bp = copy_site.inferences.candidate_breakpoint.expression
        dump_expressions = sorted(
            copy_site.inferences.candidate_dump_exprs,
            key=lambda x: x.confidence,
            reverse=True,
        )
        for expression in dump_expressions:
            dump = backend.capture_dump(
                breakpoint=bp, dump_expression=expression.expr, sender=sender
            )

            attempts.append(
                Attempt(
                    breakpoint=bp,
                    dump_expr=expression.expr,
                    confidence=expression.confidence,
                    result="pass" if dump.startswith(magic) else "fail",
                    reason="" if dump.startswith(magic) else "magic_mismatch",
                )
            )

            if dump.startswith(magic):
                return LocatedResult(
                    copy_site_id=copy_site.id,
                    breakpoint=bp,
                    dump_expression=expression.expr,
                    confidence=expression.confidence,
                    attempts=attempts,
                )

    return ValidationFailure(attempts)
