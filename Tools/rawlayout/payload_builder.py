from __future__ import annotations

import inspect
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class BuildContext:
    current_offset: int
    segment_offsets: dict[str, tuple[int, int]]
    total_size_so_far: int


ComputedFunc = Callable[..., bytes]
COMPUTED_FUNCTIONS: dict[str, ComputedFunc] = {}


def register_computed_function(
    name: str,
    func: ComputedFunc,
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("computed function name must be non-empty string")
    if not callable(func):
        raise ValueError("computed function must be callable")
    if name in COMPUTED_FUNCTIONS and not overwrite:
        raise ValueError(f"computed function already registered: {name!r}")
    COMPUTED_FUNCTIONS[name] = func


@dataclass(frozen=True)
class OverlapRecord:
    start: int
    end: int
    existing_segment: str
    new_segment: str


@dataclass(frozen=True)
class SegmentReport:
    name: str
    op: str
    start: int
    end: int
    allow_overlap: bool


@dataclass(frozen=True)
class LayoutReport:
    final_length: int
    labels: dict[str, int]
    segments: list[SegmentReport]
    overlaps: list[OverlapRecord]


@dataclass(frozen=True)
class LayoutBuildResult:
    payload: bytes
    report: LayoutReport


class ByteMap:
    def __init__(self) -> None:
        self._bytes: dict[int, int] = {}
        self._intervals: list[tuple[int, int, str]] = []
        self._max_end: int = 0
        self.overlaps: list[OverlapRecord] = []

    @property
    def max_end(self) -> int:
        return self._max_end

    def write(
        self,
        *,
        start: int,
        data: bytes,
        segment_name: str,
        allow_overlap: bool = False,
    ) -> int:
        if start < 0:
            raise ValueError(f"segment {segment_name!r} has negative start offset {start}")
        end = start + len(data)
        if len(data) == 0:
            return end

        conflicts = self._find_overlaps(start, end)
        if conflicts and not allow_overlap:
            detail_parts: list[str] = []
            for c_start, c_end, c_name in conflicts:
                ov_start = max(start, c_start)
                ov_end = min(end, c_end)
                detail_parts.append(
                    f"{c_name!r} overlap [{ov_start}, {ov_end}) (existing [{c_start}, {c_end}))"
                )
            details = "; ".join(detail_parts)
            raise ValueError(
                f"overlap detected for segment {segment_name!r} at [{start}, {end}): {details}. "
                "Set allow_overlap=true on this segment to permit overlap."
            )

        for c_start, c_end, c_name in conflicts:
            self.overlaps.append(
                OverlapRecord(
                    start=max(start, c_start),
                    end=min(end, c_end),
                    existing_segment=c_name,
                    new_segment=segment_name,
                )
            )

        for idx, b in enumerate(data):
            self._bytes[start + idx] = b

        self._intervals.append((start, end, segment_name))
        self._max_end = max(self._max_end, end)
        return end

    def _find_overlaps(self, start: int, end: int) -> list[tuple[int, int, str]]:
        return [
            (i_start, i_end, i_name)
            for i_start, i_end, i_name in self._intervals
            if i_start < end and start < i_end
        ]

    def materialize(self, *, length: int, fill_byte: int) -> bytes:
        if length < 0:
            raise ValueError("length must be >= 0")
        if not 0 <= fill_byte <= 0xFF:
            raise ValueError("fill_byte must be in range [0, 255]")
        out = bytearray([fill_byte] * length)
        for idx, b in self._bytes.items():
            if idx < length:
                out[idx] = b
        return bytes(out)

    def unwritten_runs(self, start: int, end: int) -> list[tuple[int, int]]:
        if start >= end:
            return []
        runs: list[tuple[int, int]] = []
        run_start: int | None = None
        for idx in range(start, end):
            if idx not in self._bytes:
                if run_start is None:
                    run_start = idx
            elif run_start is not None:
                runs.append((run_start, idx))
                run_start = None
        if run_start is not None:
            runs.append((run_start, end))
        return runs


def _parse_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be int-like, got bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field} must be int-like, got {type(value).__name__}")


def _parse_byte(value: Any, *, field: str) -> int:
    v = _parse_int(value, field=field)
    if not 0 <= v <= 0xFF:
        raise ValueError(f"{field} must be in range [0, 255], got {v}")
    return v


def _decode_escaped_bytes(text: str) -> bytes:
    return text.encode("utf-8").decode("unicode_escape").encode("latin-1", errors="strict")


def _parse_badchars(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, list):
        return bytes(_parse_byte(v, field="badchars[]") for v in value)
    if isinstance(value, str):
        raw = _decode_escaped_bytes(value)
        if b"\\x" in raw:
            out = bytearray()
            for part in raw.decode("latin-1").split("\\x"):
                if not part:
                    continue
                out.append(int(part[:2], 16))
                rest = part[2:]
                if rest.strip():
                    raise ValueError(f"Invalid badchars segment: {part!r}")
            return bytes(out)
        return raw
    raise ValueError("badchars must be list[int] or escaped string")


def _merge_validators(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    merged.update(override)
    return merged


def validate_bytes(
    data: bytes,
    *,
    stage: str,
    badchars: bytes = b"",
    assert_len_max: int | None = None,
    assert_len_exact: int | None = None,
    mutator: str | None = None,
    required_copied_len_min: int | None = None,
    mutators: dict[str, Callable[[bytes], bytes]] | None = None,
) -> None:
    if badchars:
        badset = set(badchars)
        hit = next(((idx, b) for idx, b in enumerate(data) if b in badset), None)
        if hit is not None:
            idx, b = hit
            raise ValueError(
                f"{stage}: badchar 0x{b:02x} at index {idx} (len={len(data)})"
            )

    if assert_len_max is not None and len(data) > assert_len_max:
        raise ValueError(f"{stage}: length {len(data)} exceeds max {assert_len_max}")
    if assert_len_exact is not None and len(data) != assert_len_exact:
        raise ValueError(f"{stage}: length {len(data)} does not equal {assert_len_exact}")

    if mutator:
        known = mutators or {"identity": lambda x: x, "c_string_null": _mutator_c_string_null}
        fn = known.get(mutator)
        if fn is None:
            raise ValueError(f"{stage}: unknown mutator {mutator!r}")
        copied = fn(data)
        if required_copied_len_min is not None and len(copied) < required_copied_len_min:
            raise ValueError(
                f"{stage}: copied length {len(copied)} is below required minimum "
                f"{required_copied_len_min} after mutator {mutator!r}"
            )


def _mutator_c_string_null(data: bytes) -> bytes:
    idx = data.find(b"\x00")
    return data if idx == -1 else data[:idx]


def generate_external_bytes(
    command: list[str],
    *,
    timeout_s: float,
    cwd: Path | None,
    env: dict[str, str] | None,
    max_output_bytes: int = 1_000_000,
) -> bytes:
    if not command or any(not isinstance(arg, str) for arg in command):
        raise ValueError("command must be a non-empty list[str]")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be > 0")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be > 0")

    proc_env = None
    if env is not None:
        proc_env = os.environ.copy()
        proc_env.update(env)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=True,
            shell=False,
            cwd=str(cwd) if cwd else None,
            env=proc_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"external command timed out after {timeout_s}s: {command}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"external command failed rc={exc.returncode}: {command}\n"
            f"stderr={exc.stderr.decode('latin-1', errors='replace')}"
        ) from exc

    output = result.stdout
    if len(output) > max_output_bytes:
        raise ValueError(
            f"external command output length {len(output)} exceeds max_output_bytes "
            f"{max_output_bytes}"
        )
    return output


def _eval_expr(expr: Any, *, params: dict[str, Any], labels: dict[str, int]) -> int:
    if isinstance(expr, bool):
        raise ValueError("boolean is not a valid numeric expression")
    if isinstance(expr, int):
        return expr
    if isinstance(expr, str):
        if expr in labels:
            return labels[expr]
        if expr in params:
            return _parse_int(params[expr], field=f"params[{expr}]")
        return int(expr, 0)
    if not isinstance(expr, dict) or len(expr) != 1:
        raise ValueError(f"unsupported expression: {expr!r}")

    op, value = next(iter(expr.items()))
    if op == "ref":
        if not isinstance(value, str) or value not in labels:
            raise ValueError(f"unknown label ref: {value!r}")
        return labels[value]
    if op == "param":
        if not isinstance(value, str) or value not in params:
            raise ValueError(f"unknown param ref: {value!r}")
        return _parse_int(params[value], field=f"params[{value}]")
    if op in {"add", "sub"}:
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError(f"{op} expression requires a 2-item list")
        left = _eval_expr(value[0], params=params, labels=labels)
        right = _eval_expr(value[1], params=params, labels=labels)
        return left + right if op == "add" else left - right
    raise ValueError(f"unsupported expression op: {op!r}")


def _eval_optional_int_expr(
    expr: Any,
    *,
    params: dict[str, Any],
    labels: dict[str, int],
) -> int | None:
    if expr is None:
        return None
    return _eval_expr(expr, params=params, labels=labels)


def load_layout_spec(path: str | Path) -> dict[str, Any]:
    spec_path = Path(path)
    raw = spec_path.read_text(encoding="utf-8")
    suffix = spec_path.suffix.lower()
    if suffix == ".json":
        return json.loads(raw)
    if suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ValueError(
                "YAML support requires PyYAML installed; use JSON or install pyyaml"
            ) from exc
        return yaml.safe_load(raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ValueError(
                f"Unknown spec extension for {spec_path}. Use .json, or install PyYAML for YAML."
            ) from exc
        return yaml.safe_load(raw)


def _resolve_external_command(
    command_ref: str,
    *,
    spec_commands: dict[str, Any],
    cli_commands: dict[str, list[str]],
) -> list[str]:
    if command_ref in cli_commands:
        return cli_commands[command_ref]
    cmd = spec_commands.get(command_ref)
    if not isinstance(cmd, list) or any(not isinstance(part, str) for part in cmd):
        raise ValueError(
            f"external command_ref {command_ref!r} not found as list[str] in overrides/spec"
        )
    return cmd


def _normalize_segment(raw_segment: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(raw_segment, dict):
        raise ValueError(f"segments[{index}] must be an object")

    if "op" in raw_segment:
        return dict(raw_segment)

    shorthand_ops = ["append", "at", "pad_to", "label", "assert_offset", "assert_max_size"]
    matched = [k for k in shorthand_ops if k in raw_segment]
    if len(matched) != 1:
        raise ValueError(
            f"segments[{index}] must include op or exactly one shorthand key in {shorthand_ops}"
        )

    op = matched[0]
    value = raw_segment[op]
    seg: dict[str, Any] = {"op": op}

    if op in {"label", "assert_offset", "assert_max_size"}:
        if op == "label":
            key_name = "name"
        elif op == "assert_offset":
            key_name = "offset"
        else:
            key_name = "max_size"
        if isinstance(value, dict):
            seg.update(value)
        else:
            seg[key_name] = value
        if "name" in raw_segment and "name" not in seg:
            seg["name"] = raw_segment["name"]
        return seg

    if isinstance(value, dict):
        seg.update(value)
    else:
        raise ValueError(f"segments[{index}].{op} must be an object")

    if "name" in raw_segment and "name" not in seg:
        seg["name"] = raw_segment["name"]
    return seg


def _invoke_computed(function_name: str, args: dict[str, Any], ctx: BuildContext) -> bytes:
    fn = COMPUTED_FUNCTIONS.get(function_name)
    if fn is None:
        raise ValueError(f"computed function not registered: {function_name!r}")

    sig = inspect.signature(fn)
    accepts_two = False
    accepts_one = False
    try:
        sig.bind({}, ctx)
        accepts_two = True
    except TypeError:
        pass
    try:
        sig.bind({})
        accepts_one = True
    except TypeError:
        pass

    if accepts_two:
        out = fn(args, ctx)
    elif accepts_one:
        out = fn(args)
    else:
        raise ValueError(
            f"computed function {function_name!r} must accept (args) or (args, context)"
        )
    if not isinstance(out, (bytes, bytearray)):
        raise ValueError(
            f"computed function {function_name!r} must return bytes, got {type(out).__name__}"
        )
    return bytes(out)


def _source_bytes_for_segment(
    segment: dict[str, Any],
    *,
    params: dict[str, Any],
    labels: dict[str, int],
    spec_dir: Path,
    external_commands_spec: dict[str, Any],
    external_commands_override: dict[str, list[str]],
    external_defaults: dict[str, Any],
    external_validation_defaults: dict[str, Any],
    build_ctx: BuildContext,
) -> bytes:
    source = segment.get("source", "bytes")

    if source == "bytes":
        value = segment.get("value", "")
        if not isinstance(value, str):
            raise ValueError("bytes source requires string field 'value'")
        data = _decode_escaped_bytes(value)
    elif source == "hex":
        value = segment.get("value", "")
        if not isinstance(value, str):
            raise ValueError("hex source requires string field 'value'")
        data = bytes.fromhex(value.replace(" ", ""))
    elif source == "text":
        value = segment.get("value", "")
        encoding = segment.get("encoding", "utf-8")
        if not isinstance(value, str):
            raise ValueError("text source requires string field 'value'")
        if not isinstance(encoding, str):
            raise ValueError("text source requires string field 'encoding'")
        data = value.encode(encoding)
    elif source == "int":
        value = _eval_expr(segment.get("value"), params=params, labels=labels)
        size = _parse_int(segment.get("size", 4), field="int.size")
        endian = segment.get("endian", "little")
        signed = bool(segment.get("signed", False))
        if size <= 0:
            raise ValueError("int.size must be > 0")
        if endian not in {"little", "big"}:
            raise ValueError("int.endian must be 'little' or 'big'")
        data = int(value).to_bytes(size, endian, signed=signed)
    elif source == "file":
        path_value = segment.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise ValueError("file source requires string field 'path'")
        p = Path(path_value)
        if not p.is_absolute():
            p = spec_dir / p
        data = p.read_bytes()
    elif source == "external":
        command_ref = segment.get("command_ref")
        if not isinstance(command_ref, str) or not command_ref:
            raise ValueError("external source requires string field 'command_ref'")
        command = _resolve_external_command(
            command_ref,
            spec_commands=external_commands_spec,
            cli_commands=external_commands_override,
        )
        timeout_s = float(segment.get("timeout_s", external_defaults["timeout_s"]))
        max_out = _parse_int(
            segment.get("max_output_bytes", external_defaults["max_output_bytes"]),
            field="external.max_output_bytes",
        )
        cwd = segment.get("cwd")
        cwd_path = Path(cwd) if isinstance(cwd, str) else spec_dir
        env = segment.get("env")
        if env is not None and not isinstance(env, dict):
            raise ValueError("external env must be object mapping string->string")
        env_dict = None if env is None else {str(k): str(v) for k, v in env.items()}
        data = generate_external_bytes(
            command,
            timeout_s=timeout_s,
            cwd=cwd_path,
            env=env_dict,
            max_output_bytes=max_out,
        )
        seg_validators = segment.get("validators", {})
        if not isinstance(seg_validators, dict):
            raise ValueError("segment.validators must be an object")
        validators = _merge_validators(external_validation_defaults, seg_validators)
        validate_bytes(
            data,
            stage=f"external:{segment.get('name', command_ref)}",
            badchars=_parse_badchars(validators.get("badchars")),
            assert_len_max=_eval_optional_int_expr(
                validators.get("assert_len_max"),
                params=params,
                labels=labels,
            ),
            assert_len_exact=_eval_optional_int_expr(
                validators.get("assert_len_exact"),
                params=params,
                labels=labels,
            ),
            mutator=validators.get("mutator"),
            required_copied_len_min=_eval_optional_int_expr(
                validators.get("required_copied_len_min"),
                params=params,
                labels=labels,
            ),
        )
    elif source == "computed":
        function_name = segment.get("function")
        args = segment.get("args", {})
        if not isinstance(function_name, str) or not function_name:
            raise ValueError("computed source requires string field 'function'")
        if not isinstance(args, dict):
            raise ValueError("computed source requires object field 'args'")
        data = _invoke_computed(function_name, args, build_ctx)
    else:
        raise ValueError(f"unsupported source: {source!r}")

    seg_validators = segment.get("validators", {})
    if not isinstance(seg_validators, dict):
        raise ValueError("segment.validators must be an object")
    if source != "external" and seg_validators:
        validate_bytes(
            data,
            stage=f"segment:{segment.get('name', 'unnamed')}",
            badchars=_parse_badchars(seg_validators.get("badchars")),
            assert_len_max=_eval_optional_int_expr(
                seg_validators.get("assert_len_max"),
                params=params,
                labels=labels,
            ),
            assert_len_exact=_eval_optional_int_expr(
                seg_validators.get("assert_len_exact"),
                params=params,
                labels=labels,
            ),
            mutator=seg_validators.get("mutator"),
            required_copied_len_min=_eval_optional_int_expr(
                seg_validators.get("required_copied_len_min"),
                params=params,
                labels=labels,
            ),
        )
    return data


def format_layout_report_table(report: LayoutReport) -> str:
    lines = [
        "Segment            Start   End     Size",
        "----------------------------------------",
    ]
    for s in report.segments:
        size = s.end - s.start
        lines.append(f"{s.name:<18} {s.start:<7} {s.end:<7} {size}")
    lines.append("----------------------------------------")
    lines.append(f"Total size: {report.final_length}")
    if report.overlaps:
        lines.append("Overlaps:")
        for ov in report.overlaps:
            lines.append(
                f"  {ov.new_segment} overlaps {ov.existing_segment} at [{ov.start}, {ov.end})"
            )
    return "\n".join(lines)


def build_payload(
    spec: dict[str, Any],
    *,
    spec_dir: Path | None = None,
    param_overrides: dict[str, Any] | None = None,
    external_commands_override: dict[str, list[str]] | None = None,
    fill_byte_override: int | None = None,
    external_timeout_s: float = 10.0,
    external_max_output_bytes: int = 1_000_000,
) -> LayoutBuildResult:
    if not isinstance(spec, dict):
        raise ValueError("layout spec must be an object")

    spec_dir = spec_dir or Path.cwd()
    params = dict(spec.get("params", {}))
    if param_overrides:
        params.update(param_overrides)

    segments_raw = spec.get("segments")
    if not isinstance(segments_raw, list):
        raise ValueError("spec.segments must be a list")

    external_commands_spec = spec.get("external_commands", {})
    if not isinstance(external_commands_spec, dict):
        raise ValueError("spec.external_commands must be an object")
    external_commands_override = external_commands_override or {}

    external_defaults = {
        "timeout_s": float(spec.get("external_timeout_s", external_timeout_s)),
        "max_output_bytes": _parse_int(
            spec.get("external_max_output_bytes", external_max_output_bytes),
            field="external_max_output_bytes",
        ),
    }

    external_validation_defaults = spec.get("external_validation", {})
    if not isinstance(external_validation_defaults, dict):
        raise ValueError("spec.external_validation must be an object")

    constraints = spec.get("constraints", {})
    if not isinstance(constraints, dict):
        raise ValueError("spec.constraints must be an object")
    final_validation = spec.get("final_validation", {})
    if not isinstance(final_validation, dict):
        raise ValueError("spec.final_validation must be an object")

    fill_byte = (
        fill_byte_override
        if fill_byte_override is not None
        else _parse_byte(spec.get("fill_byte", 0x41), field="fill_byte")
    )

    bytemap = ByteMap()
    labels: dict[str, int] = {}
    segment_ranges: dict[str, tuple[int, int]] = {}
    reports: list[SegmentReport] = []
    deferred_max_size_checks: list[tuple[str, Any]] = []
    cursor = 0

    for idx, raw_seg in enumerate(segments_raw):
        seg = _normalize_segment(raw_seg, index=idx)
        op = seg.get("op")
        if not isinstance(op, str):
            raise ValueError(f"segments[{idx}].op must be a string")
        name = str(seg.get("name", f"{op}_{idx}"))
        allow_overlap = bool(seg.get("allow_overlap", False))

        if op == "label":
            label_name = seg.get("name")
            if not isinstance(label_name, str) or not label_name:
                raise ValueError(f"segments[{idx}] label requires non-empty name")
            if label_name in labels:
                raise ValueError(f"duplicate label: {label_name!r}")
            labels[label_name] = cursor
            segment_ranges[label_name] = (cursor, cursor)
            reports.append(SegmentReport(name=label_name, op="label", start=cursor, end=cursor, allow_overlap=False))
            continue

        if op == "assert_offset":
            expected = _eval_expr(seg.get("offset", seg.get("assert_offset")), params=params, labels=labels)
            if cursor != expected:
                raise ValueError(
                    f"assert_offset failed for {name!r}: cursor={cursor}, expected={expected}"
                )
            reports.append(
                SegmentReport(
                    name=name,
                    op="assert_offset",
                    start=cursor,
                    end=cursor,
                    allow_overlap=False,
                )
            )
            continue

        if op == "assert_max_size":
            deferred_max_size_checks.append((name, seg.get("max_size", seg.get("assert_max_size"))))
            reports.append(
                SegmentReport(
                    name=name,
                    op="assert_max_size",
                    start=cursor,
                    end=cursor,
                    allow_overlap=False,
                )
            )
            continue

        if op == "pad_to":
            target = _eval_expr(seg.get("target", seg.get("pad_to")), params=params, labels=labels)
            if target < cursor:
                raise ValueError(
                    f"segments[{idx}] pad_to target {target} is behind cursor {cursor}"
                )
            pad_byte = _parse_byte(seg.get("byte", fill_byte), field=f"segments[{idx}].byte")
            start = cursor
            end = target
            for run_start, run_end in bytemap.unwritten_runs(start, end):
                bytemap.write(
                    start=run_start,
                    data=bytes([pad_byte]) * (run_end - run_start),
                    segment_name=name,
                    allow_overlap=allow_overlap,
                )
            cursor = target
            segment_ranges[name] = (start, end)
            reports.append(SegmentReport(name=name, op="pad_to", start=start, end=end, allow_overlap=allow_overlap))
            continue

        if op in {"append", "at"}:
            ctx = BuildContext(
                current_offset=cursor,
                segment_offsets=dict(segment_ranges),
                total_size_so_far=max(cursor, bytemap.max_end),
            )
            data = _source_bytes_for_segment(
                seg,
                params=params,
                labels=labels,
                spec_dir=spec_dir,
                external_commands_spec=external_commands_spec,
                external_commands_override=external_commands_override,
                external_defaults=external_defaults,
                external_validation_defaults=external_validation_defaults,
                build_ctx=ctx,
            )
            if op == "append":
                start = cursor
                end = bytemap.write(
                    start=start,
                    data=data,
                    segment_name=name,
                    allow_overlap=allow_overlap,
                )
                cursor = end
            else:
                start = _eval_expr(seg.get("offset", seg.get("at")), params=params, labels=labels)
                end = bytemap.write(
                    start=start,
                    data=data,
                    segment_name=name,
                    allow_overlap=allow_overlap,
                )
                if bool(seg.get("advance_cursor", False)):
                    cursor = max(cursor, end)
            segment_ranges[name] = (start, end)
            reports.append(SegmentReport(name=name, op=op, start=start, end=end, allow_overlap=allow_overlap))
            continue

        raise ValueError(f"segments[{idx}] unsupported op {op!r}")

    final_length = max(cursor, bytemap.max_end)
    payload = bytemap.materialize(length=final_length, fill_byte=fill_byte)

    for check_name, expr in deferred_max_size_checks:
        max_size = _eval_expr(expr, params=params, labels=labels)
        if len(payload) > max_size:
            raise ValueError(
                f"assert_max_size failed for {check_name!r}: payload_len={len(payload)} exceeds {max_size}"
            )

    merged_final_validators = _merge_validators(
        {
            "assert_len_max": constraints.get("assert_len_max", spec.get("assert_len_max")),
            "assert_len_exact": constraints.get(
                "assert_len_exact", spec.get("assert_len_exact")
            ),
        },
        final_validation,
    )
    validate_bytes(
        payload,
        stage="final_payload",
        badchars=_parse_badchars(merged_final_validators.get("badchars")),
        assert_len_max=_eval_optional_int_expr(
            merged_final_validators.get("assert_len_max"),
            params=params,
            labels=labels,
        ),
        assert_len_exact=_eval_optional_int_expr(
            merged_final_validators.get("assert_len_exact"),
            params=params,
            labels=labels,
        ),
        mutator=merged_final_validators.get("mutator"),
        required_copied_len_min=_eval_optional_int_expr(
            merged_final_validators.get("required_copied_len_min"),
            params=params,
            labels=labels,
        ),
    )

    report = LayoutReport(
        final_length=len(payload),
        labels=dict(labels),
        segments=reports,
        overlaps=list(bytemap.overlaps),
    )
    return LayoutBuildResult(payload=payload, report=report)

