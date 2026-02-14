#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Set


@dataclass(frozen=True, slots=True)
class BadCharProfile:
    name: str
    description: str
    badchars: Set[int]


class BadCharRegistry:
    """
    Registry of context-aware bad character profiles.
    Designed for exploit development.
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, BadCharProfile] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(
            BadCharProfile(
                name="raw_tcp",
                description="Generic stack overflow over raw TCP",
                badchars={0x00},
            )
        )

        self.register(
            BadCharProfile(
                name="http_header",
                description="HTTP header value context",
                badchars={0x00, 0x0A, 0x0D},
            )
        )

        self.register(
            BadCharProfile(
                name="http_form_urlencoded",
                description="application/x-www-form-urlencoded body",
                badchars={
                    0x00,  # NULL
                    0x0A,  # LF
                    0x0D,  # CR
                    0x25,  # %
                    0x26,  # &
                    0x2B,  # +
                    0x3D,  # =
                },
            )
        )

        self.register(
            BadCharProfile(
                name="url_query",
                description="URL query parameter context",
                badchars={
                    0x00,
                    0x0A,
                    0x0D,
                    0x25,
                    0x26,
                    0x2B,
                    0x3D,
                    0x23,  # #
                    0x3F,  # ?
                },
            )
        )

    def register(self, profile: BadCharProfile) -> None:
        self._profiles[profile.name] = profile

    def get(self, name: str) -> BadCharProfile:
        if name not in self._profiles:
            raise ValueError(f"Unknown profile: {name}")
        return self._profiles[name]

    def list_profiles(self) -> Iterable[str]:
        return self._profiles.keys()


def remove_badchars(payload: bytes, badchars: Set[int]) -> bytes:
    return bytes(b for b in payload if b not in badchars)


def validate_payload(payload: bytes, badchars: Set[int]) -> Set[int]:
    return {b for b in payload if b in badchars}


# Example usage
if __name__ == "__main__":
    registry = BadCharRegistry()

    profile = registry.get("http_form_urlencoded")
    payload = bytes(range(256))

    found = validate_payload(payload, profile.badchars)

    print(f"Profile: {profile.name}")
    print(f"Bad chars found: {[hex(b) for b in sorted(found)]}")

    cleaned = remove_badchars(payload, profile.badchars)
    print(f"Original size: {len(payload)}")
    print(f"Cleaned size: {len(cleaned)}")
