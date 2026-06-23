"""Pure script text generation for WinDbg/cdb .wds files."""

from .models import WDSConfig


def generate_wds(config):  # type: (WDSConfig) -> str
    """
    Build deterministic debugger script text from structured configuration.
    """
    if config is None:
        raise ValueError("config is required")
    if not isinstance(config, WDSConfig):
        raise TypeError("config must be a WDSConfig")

    stage = config.stage
    _validate_stage(stage)

    dump_end_expr = "({base}+0x{size:x})".format(
        base=_wrap_expr(stage.dump_expr), size=stage.dump_size
    )

    commands = []
    commands.append("sxd ibp")
    commands.append("sxd ld")
    commands.append("sxn av")
    if config.enable_second_chance_av:
        commands.append('sxe -c ".echo BADCHAR_CRASH; q" av')

    for cmd in (stage.extra_init_commands or []):
        commands.append(cmd)

    bp_parts = []
    step_cmd = _step_command(stage.step_mode, stage.custom_step)
    if step_cmd:
        bp_parts.append(step_cmd)
    bp_parts.append(
        '.writemem {temp} {start} {end}'.format(
            temp=_shell_quote_path(stage.temp_dump_path),
            start=_wrap_expr(stage.dump_expr),
            end=dump_end_expr,
        )
    )
    # Only emit the rename shell command when temp and final are distinct.
    # When they are the same, .writemem writes directly to the final path and
    # no rename is needed.  A self-rename (move X X) errors on Windows and
    # would silently swallow the breakpoint's remaining commands.
    if stage.temp_dump_path != stage.final_dump_path:
        bp_parts.append(
            '.shell -ci "cmd /c move /Y {temp} {final}"'.format(
                temp=_shell_quote_path(stage.temp_dump_path),
                final=_shell_quote_path(stage.final_dump_path),
            )
        )
    if stage.quit_after_dump:
        bp_parts.append("q")
    else:
        bp_parts.append("g")

    # Escape every " in the body before embedding it in the outer bp "..." string.
    # Any bare " inside that string terminates it early, silently discarding all
    # commands that follow.  A single pass of " → \" is all WinDbg/cdb needs.
    body = "; ".join(bp_parts)
    body_escaped = body.replace('"', '\\"')
    commands.append('bp {bp} "{body}"'.format(bp=stage.breakpoint, body=body_escaped))
    commands.append("g")
    return "\n".join(commands) + "\n"


def _validate_stage(stage):
    if stage is None:
        raise ValueError("config.stage is required")

    if not stage.breakpoint or not stage.breakpoint.strip():
        raise ValueError("breakpoint must be non-empty")
    if not stage.dump_expr or not stage.dump_expr.strip():
        raise ValueError("dump_expr must be non-empty")
    if stage.dump_size <= 0:
        raise ValueError("dump_size must be > 0")
    if not stage.temp_dump_path or not stage.temp_dump_path.strip():
        raise ValueError("temp_dump_path must be non-empty")
    if not stage.final_dump_path or not stage.final_dump_path.strip():
        raise ValueError("final_dump_path must be non-empty")

    mode = stage.step_mode
    if mode not in ("none", "pt", "gu", "custom"):
        raise ValueError("step_mode must be one of: none, pt, gu, custom")
    if mode == "custom":
        if stage.custom_step is None or not stage.custom_step.strip():
            raise ValueError("custom_step is required when step_mode is custom")


def _step_command(step_mode, custom_step):
    if step_mode == "none":
        return None
    if step_mode == "pt":
        return "pt"
    if step_mode == "gu":
        return "gu"
    return custom_step.strip()


def _wrap_expr(expr):
    stripped = expr.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        return stripped
    return "({0})".format(stripped)


def _shell_quote_path(path):
    # type: (str) -> str
    """
    Wrap a path in double quotes if it contains spaces, so that .writemem and
    cmd.exe each treat it as a single token.

    Do NOT escape embedded quotes here.  All double-quote escaping for the
    surrounding bp "..." command string is done once, at the end of
    generate_wds(), by replacing every " with \" in the assembled body.
    Pre-escaping here would cause those characters to be double-escaped.
    """
    if " " in path:
        return '"' + path + '"'
    return path
