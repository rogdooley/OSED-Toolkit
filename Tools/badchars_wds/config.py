"""Configuration loading and validation for badchars_wds."""

import copy
import difflib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import Stage
from .orchestrator import RestartPolicy


@dataclass
class ValidationIssue:
    path: str
    source: str
    message: str
    expected: Optional[str]
    actual: Any
    actual_repr: str


class ConfigValidationError(Exception):
    def __init__(self, issues):
        # type: (List[ValidationIssue]) -> None
        ordered = sorted(issues, key=lambda i: (i.path, i.source, i.message))
        self.issues = ordered
        lines = ["Configuration validation error(s):"]
        for issue in ordered:
            lines.append(
                "- {path}: {message} (expected={expected}, actual={actual_repr}, source={source})".format(
                    path=issue.path,
                    message=issue.message,
                    expected=issue.expected if issue.expected is not None else "n/a",
                    actual_repr=issue.actual_repr,
                    source=issue.source,
                )
            )
        super(ConfigValidationError, self).__init__("\n".join(lines))


@dataclass
class LoadedConfig:
    raw: Dict[str, Any]
    stage: Stage
    driver: Dict[str, Any]
    transport: Dict[str, Any]
    offset: int
    dump_dir: str
    magic: bytes
    timeout: float
    restart_delay: float
    max_iterations: int
    excluded_bytes: Set[int]
    restart_policy: RestartPolicy
    filler_byte: int = 0x41
    pad_byte: int = 0x43
    pad_len: int = 32


_ROOT_KEYS = frozenset(["driver", "stage", "orchestrator", "transport"])
_STEP_MODES = frozenset(["none", "pt", "gu", "custom"])
_TRANSPORT_TYPES = frozenset(["tcp", "udp", "callback"])

_OVERRIDE_ALIASES = {
    "offset": "orchestrator.offset",
    "breakpoint": "stage.breakpoint",
    "dump_expr": "stage.dump_expr",
    "host": "transport.host",
    "port": "transport.port",
    "timeout": "orchestrator.timeout",
    "restart_policy": "orchestrator.restart_policy",
    "max_iter": "orchestrator.max_iterations",
}


def load_config(config_path, overrides=None):
    # type: (str, Optional[Dict[str, Any]]) -> LoadedConfig
    with open(config_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    merged = apply_overrides(data, overrides or {})
    validate_config(merged, source="config.json")
    return _materialize(merged)


def apply_overrides(config, overrides):
    # type: (Dict[str, Any], Dict[str, Any]) -> Dict[str, Any]
    """
    Apply CLI-style overrides to config with strict conflict and key checks.
    """
    result = copy.deepcopy(config)
    issues = []  # type: List[ValidationIssue]
    seen_targets = {}  # type: Dict[str, str]

    for raw_key, value in overrides.items():
        normalized_raw = _normalize_key(raw_key)
        canonical_path = _to_canonical_override_path(normalized_raw)
        if canonical_path is None:
            issues.append(
                ValidationIssue(
                    path=normalized_raw,
                    source="CLI override",
                    message="unknown override key",
                    expected="known override key",
                    actual=raw_key,
                    actual_repr=repr(raw_key),
                )
            )
            continue

        previous = seen_targets.get(canonical_path)
        if previous is not None and previous != raw_key:
            issues.append(
                ValidationIssue(
                    path=canonical_path,
                    source="CLI override",
                    message="conflicting arguments: {} and {}".format(previous, raw_key),
                    expected="only one representation per key",
                    actual={"first": previous, "second": raw_key},
                    actual_repr=repr({"first": previous, "second": raw_key}),
                )
            )
            continue
        seen_targets[canonical_path] = raw_key

        if not _path_exists(result, canonical_path):
            issues.append(
                ValidationIssue(
                    path=canonical_path,
                    source="CLI override",
                    message="override key must already exist in config",
                    expected="existing config key",
                    actual=value,
                    actual_repr=repr(value),
                )
            )
            continue

        _set_path(result, canonical_path, value)

    if issues:
        raise ConfigValidationError(issues)
    return result


def validate_config(config, source="config.json"):
    # type: (Dict[str, Any], str) -> None
    issues = []  # type: List[ValidationIssue]
    if not isinstance(config, dict):
        issues.append(_issue("", "root must be an object", source, "object", config))
        raise ConfigValidationError(issues)

    _validate_schema_phase(config, source, issues)
    _validate_semantic_phase(config, source, issues)

    if issues:
        raise ConfigValidationError(issues)


def _validate_schema_phase(config, source, issues):
    # type: (Dict[str, Any], str, List[ValidationIssue]) -> None
    for key in _ROOT_KEYS:
        if key not in config:
            issues.append(_issue(key, "missing required key", source, "present", None))

    for key in config.keys():
        if key not in _ROOT_KEYS:
            message = "unknown key"
            suggestion = _nearest_key(key, _ROOT_KEYS)
            if suggestion:
                message += "; did you mean '{}' ?".format(suggestion)
            issues.append(_issue(key, message, source, "known key", config[key]))

    _validate_object(
        config, "driver", source, issues,
        required={"cdb_path": str, "target_command": list},
        optional={"log_path": str, "cwd": str, "env": dict},
    )
    _validate_object(
        config, "stage", source, issues,
        required={"breakpoint": str, "dump_expr": str, "dump_size": int},
        optional={
            "step_mode": str,
            "custom_step": (str, type(None)),
            "temp_dump_path": str,
            "final_dump_path": str,
            "quit_after_dump": bool,
        },
    )
    _validate_object(
        config, "orchestrator", source, issues,
        required={
            "offset": int,
            "dump_dir": str,
            "magic": str,
            "timeout": (int, float),
            "restart_delay": (int, float),
            "max_iterations": int,
            "excluded_bytes": list,
            "restart_policy": str,
        },
        optional={"filler_byte": int, "pad_byte": int, "pad_len": int},
    )
    _validate_object(
        config, "transport", source, issues,
        required={"type": str},
        optional={
            "host": str,
            "port": int,
            "timeout": (int, float),
            "callback_name": str,
            "prefix": str,
            "suffix": str,
            "read_banner": bool,
            "banner_size": int,
        },
    )

    driver = config.get("driver")
    if isinstance(driver, dict):
        _validate_str_list(driver, "driver.target_command", source, issues)
        env = driver.get("env")
        if env is not None:
            if not isinstance(env, dict):
                issues.append(_issue("driver.env", "expected mapping", source, "object", env))
            else:
                for key, value in env.items():
                    if not isinstance(key, str):
                        issues.append(_issue("driver.env", "env key must be str", source, "str", key))
                    if not isinstance(value, str):
                        issues.append(_issue("driver.env.{}".format(key), "env value must be str", source, "str", value))

    orch = config.get("orchestrator")
    if isinstance(orch, dict):
        _validate_int_list(orch, "orchestrator.excluded_bytes", source, issues)


def _validate_semantic_phase(config, source, issues):
    # type: (Dict[str, Any], str, List[ValidationIssue]) -> None
    stage = config.get("stage", {})
    if isinstance(stage, dict):
        step_mode = stage.get("step_mode", "none")
        if isinstance(step_mode, str) and step_mode not in _STEP_MODES:
            issues.append(_issue("stage.step_mode", "invalid step mode", source, "one of {}".format(sorted(_STEP_MODES)), step_mode))
        if step_mode == "custom" and not stage.get("custom_step"):
            issues.append(_issue("stage.custom_step", "required when step_mode=custom", source, "non-empty str", stage.get("custom_step")))
        dump_size = stage.get("dump_size")
        if isinstance(dump_size, int) and dump_size <= 0:
            issues.append(_issue("stage.dump_size", "must be > 0", source, "int > 0", dump_size))

    orch = config.get("orchestrator", {})
    if isinstance(orch, dict):
        offset = orch.get("offset")
        if isinstance(offset, int) and offset < 0:
            issues.append(_issue("orchestrator.offset", "must be >= 0", source, "int >= 0", offset))
        timeout = orch.get("timeout")
        if isinstance(timeout, (int, float)) and timeout <= 0:
            issues.append(_issue("orchestrator.timeout", "must be > 0", source, "number > 0", timeout))
        restart_delay = orch.get("restart_delay")
        if isinstance(restart_delay, (int, float)) and restart_delay < 0:
            issues.append(_issue("orchestrator.restart_delay", "must be >= 0", source, "number >= 0", restart_delay))
        max_iterations = orch.get("max_iterations")
        if isinstance(max_iterations, int) and max_iterations < 1:
            issues.append(_issue("orchestrator.max_iterations", "must be >= 1", source, "int >= 1", max_iterations))
        restart_policy = orch.get("restart_policy")
        if isinstance(restart_policy, str):
            valid = set([p.value for p in RestartPolicy])
            if restart_policy not in valid:
                issues.append(_issue("orchestrator.restart_policy", "invalid restart policy", source, "one of {}".format(sorted(valid)), restart_policy))
        magic = orch.get("magic")
        if isinstance(magic, str):
            try:
                _parse_magic_hex(magic)
            except ValueError as exc:
                issues.append(_issue("orchestrator.magic", str(exc), source, "hex string", magic))
        excluded = orch.get("excluded_bytes")
        if isinstance(excluded, list):
            for index, value in enumerate(excluded):
                if isinstance(value, int) and (value < 0 or value > 255):
                    issues.append(_issue("orchestrator.excluded_bytes[{}]".format(index), "byte out of range", source, "0..255", value))
        for byte_field in ("filler_byte", "pad_byte"):
            value = orch.get(byte_field)
            if isinstance(value, int) and (value < 0 or value > 255):
                issues.append(_issue("orchestrator.{}".format(byte_field), "byte out of range", source, "0..255", value))
        pad_len = orch.get("pad_len")
        if isinstance(pad_len, int) and pad_len < 0:
            issues.append(_issue("orchestrator.pad_len", "must be >= 0", source, "int >= 0", pad_len))

    transport = config.get("transport", {})
    if isinstance(transport, dict):
        transport_type = transport.get("type")
        if isinstance(transport_type, str):
            if transport_type not in _TRANSPORT_TYPES:
                issues.append(_issue("transport.type", "invalid transport type", source, "one of {}".format(sorted(_TRANSPORT_TYPES)), transport_type))
            if transport_type in ("tcp", "udp"):
                for field in ("host", "port"):
                    if field not in transport:
                        issues.append(_issue("transport.{}".format(field), "missing required key", source, "present", None))
                port = transport.get("port")
                if isinstance(port, int) and not (1 <= port <= 65535):
                    issues.append(_issue("transport.port", "port out of range", source, "1..65535", port))
            if transport_type == "callback":
                if "callback_name" not in transport:
                    issues.append(_issue("transport.callback_name", "missing required key", source, "present", None))


def _validate_object(config, key, source, issues, required, optional):
    # type: (Dict[str, Any], str, str, List[ValidationIssue], Dict[str, Any], Dict[str, Any]) -> None
    value = config.get(key)
    if value is None:
        return
    if not isinstance(value, dict):
        issues.append(_issue(key, "expected object", source, "object", value))
        return

    allowed = set(required.keys()) | set(optional.keys())
    for req_key, req_type in required.items():
        if req_key not in value:
            issues.append(_issue("{}.{}".format(key, req_key), "missing required key", source, "present", None))
    for obj_key, obj_value in value.items():
        if obj_key not in allowed:
            msg = "unknown key"
            suggestion = _nearest_key(obj_key, allowed)
            if suggestion:
                msg += "; did you mean '{}' ?".format(suggestion)
            issues.append(_issue("{}.{}".format(key, obj_key), msg, source, "known key", obj_value))
            continue
        expected_type = required.get(obj_key, optional.get(obj_key))
        if not isinstance(obj_value, expected_type):
            issues.append(
                _issue(
                    "{}.{}".format(key, obj_key),
                    "type mismatch",
                    source,
                    _type_name(expected_type),
                    obj_value,
                )
            )


def _validate_str_list(parent, path, source, issues):
    # type: (Dict[str, Any], str, str, List[ValidationIssue]) -> None
    items = parent.get(path.split(".")[-1])
    if items is None:
        return
    if not isinstance(items, list):
        return
    for index, item in enumerate(items):
        if not isinstance(item, str):
            issues.append(_issue("{}[{}]".format(path, index), "expected str item", source, "str", item))


def _validate_int_list(parent, path, source, issues):
    # type: (Dict[str, Any], str, str, List[ValidationIssue]) -> None
    items = parent.get(path.split(".")[-1])
    if items is None:
        return
    if not isinstance(items, list):
        return
    for index, item in enumerate(items):
        if not isinstance(item, int):
            issues.append(_issue("{}[{}]".format(path, index), "expected int item", source, "int", item))


def _path_exists(config, dotted):
    # type: (Dict[str, Any], str) -> bool
    cursor = config
    parts = dotted.split(".")
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            return False
        cursor = cursor[part]
    return True


def _set_path(config, dotted, value):
    # type: (Dict[str, Any], str, Any) -> None
    cursor = config
    parts = dotted.split(".")
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = value


def _to_canonical_override_path(key):
    # type: (str) -> Optional[str]
    if "." in key:
        return key
    return _OVERRIDE_ALIASES.get(key)


def _normalize_key(key):
    # type: (str) -> str
    return key.replace("-", "_")


def _type_name(expected):
    # type: (Any) -> str
    if isinstance(expected, tuple):
        return " | ".join(sorted([_type_name(item) for item in expected]))
    if isinstance(expected, type):
        if expected is type(None):
            return "None"
        return expected.__name__
    return str(expected)


def _nearest_key(key, candidates):
    # type: (str, Any) -> Optional[str]
    matches = difflib.get_close_matches(key, sorted(candidates), n=1, cutoff=0.75)
    return matches[0] if matches else None


def _issue(path, message, source, expected, actual):
    # type: (str, str, str, Optional[str], Any) -> ValidationIssue
    return ValidationIssue(
        path=path,
        source=source,
        message=message,
        expected=expected,
        actual=actual,
        actual_repr=repr(actual),
    )


def _parse_magic_hex(value):
    # type: (str) -> bytes
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError("magic hex string must not be empty")
    if len(cleaned) % 2 != 0:
        raise ValueError("magic hex string must have even length")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("magic must be valid hex")


def _materialize(config):
    # type: (Dict[str, Any]) -> LoadedConfig
    stage_cfg = config["stage"]
    orch_cfg = config["orchestrator"]
    stage = Stage(
        breakpoint=stage_cfg["breakpoint"],
        dump_expr=stage_cfg["dump_expr"],
        dump_size=stage_cfg["dump_size"],
        step_mode=stage_cfg.get("step_mode", "none"),
        custom_step=stage_cfg.get("custom_step"),
        temp_dump_path=stage_cfg.get("temp_dump_path", "dump.tmp.bin"),
        final_dump_path=stage_cfg.get("final_dump_path", "dump.bin"),
        quit_after_dump=stage_cfg.get("quit_after_dump", False),
    )
    return LoadedConfig(
        raw=copy.deepcopy(config),
        stage=stage,
        driver=copy.deepcopy(config["driver"]),
        transport=copy.deepcopy(config["transport"]),
        offset=orch_cfg["offset"],
        dump_dir=orch_cfg["dump_dir"],
        magic=_parse_magic_hex(orch_cfg["magic"]),
        timeout=float(orch_cfg["timeout"]),
        restart_delay=float(orch_cfg["restart_delay"]),
        max_iterations=orch_cfg["max_iterations"],
        excluded_bytes=set(orch_cfg["excluded_bytes"]),
        restart_policy=RestartPolicy(orch_cfg["restart_policy"]),
        filler_byte=orch_cfg.get("filler_byte", 0x41),
        pad_byte=orch_cfg.get("pad_byte", 0x43),
        pad_len=orch_cfg.get("pad_len", 32),
    )
