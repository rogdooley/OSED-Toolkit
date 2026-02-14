from __future__ import annotations

import base64
import json
import string
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional


@dataclass(frozen=True, slots=True)
class BadCharProfile:
    """
    Defines how bytes should be treated for a specific transport/context.

    hard_forbidden:
        Bytes that should never appear unencoded in this context.
    must_encode:
        Bytes that are syntactically meaningful delimiters or ambiguous and
        should be encoded/escaped to preserve semantics.
    encoder:
        Function that converts raw bytes into a safe representation for the context.
    """

    name: str
    hard_forbidden: frozenset[int]
    must_encode: frozenset[int]
    encoder: Callable[[bytes], str]


def _pct_encode_all_nonunreserved(data: bytes) -> str:
    # RFC 3986 "unreserved" = ALPHA / DIGIT / "-" / "." / "_" / "~"
    unreserved = set((string.ascii_letters + string.digits + "-._~").encode("ascii"))
    out: list[str] = []
    for b in data:
        if b in unreserved:
            out.append(chr(b))
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def _form_urlencode_value(data: bytes) -> str:
    # application/x-www-form-urlencoded: space -> '+', then percent-encode non-alnum
    # This is the classic HTML form encoding rule-set.
    s = data.decode("latin-1")  # preserve byte values 0x00-0xFF without loss
    # quote_plus will:
    # - encode space as '+'
    # - percent-encode unsafe bytes
    return urllib.parse.quote_plus(s, safe="")


def _http_header_safe(data: bytes) -> str:
    # For headers, you typically want ASCII-safe and *no* CR/LF.
    # If data isn't clearly printable ASCII, base64 it.
    if any(b in (0x0D, 0x0A, 0x00) for b in data):
        raise ValueError("CR/LF/NUL present; refuse to serialize into header value")

    if all(0x20 <= b <= 0x7E for b in data):  # visible ASCII + space
        return data.decode("ascii")

    return "b64:" + base64.b64encode(data).decode("ascii")


def _json_string(data: bytes) -> str:
    # JSON escaping is easiest by letting json do it.
    # Decode as latin-1 to preserve bytes; if you want UTF-8 semantics, change this.
    s = data.decode("latin-1")
    return json.dumps(s)  # includes surrounding quotes


def _raw_body_passthrough(data: bytes) -> str:
    # Not encoded; this is only "safe" if you're sending bytes in the body directly.
    # Represent as latin-1 string if you need a str carrier.
    return data.decode("latin-1")


PROFILES: Mapping[str, BadCharProfile] = {
    "http_header_value": BadCharProfile(
        name="http_header_value",
        hard_forbidden=frozenset({0x00, 0x0A, 0x0D}),
        must_encode=frozenset(
            set(range(0x00, 0x20)) - {0x09} | {0x7F}
        ),  # CTLs except HTAB
        encoder=_http_header_safe,
    ),
    "url_query": BadCharProfile(
        name="url_query",
        hard_forbidden=frozenset(set(range(0x00, 0x20)) | {0x7F}),
        must_encode=frozenset(ord(c) for c in b" #%&+=?[]"),
        encoder=_pct_encode_all_nonunreserved,
    ),
    "form_urlencoded": BadCharProfile(
        name="form_urlencoded",
        hard_forbidden=frozenset(set(range(0x00, 0x20)) | {0x7F}),
        must_encode=frozenset(ord(c) for c in b"&=+%"),
        encoder=_form_urlencode_value,
    ),
    "json_string": BadCharProfile(
        name="json_string",
        hard_forbidden=frozenset(
            {0x00}
        ),  # keep strict; JSON escaping handles most others
        must_encode=frozenset({ord('"'), ord("\\"), 0x0A, 0x0D, 0x09}),
        encoder=_json_string,
    ),
    "raw_body": BadCharProfile(
        name="raw_body",
        hard_forbidden=frozenset(),
        must_encode=frozenset(),
        encoder=_raw_body_passthrough,
    ),
}


def bad_bytes(profile_name: str) -> frozenset[int]:
    p = PROFILES[profile_name]
    return p.hard_forbidden | p.must_encode


def sanitize_bytes(
    data: bytes,
    profile_name: str,
    *,
    replace_with: Optional[int] = None,
    extra_forbidden: Iterable[int] = (),
) -> bytes:
    """
    Removes (or replaces) bytes that a profile marks as unsafe.

    Use this only when you truly want deletion/replacement.
    In most HTTP contexts you should prefer encode_bytes().
    """
    p = PROFILES[profile_name]
    forbidden = set(p.hard_forbidden) | set(p.must_encode) | set(extra_forbidden)

    out = bytearray()
    for b in data:
        if b in forbidden:
            if replace_with is None:
                continue
            out.append(replace_with & 0xFF)
        else:
            out.append(b)
    return bytes(out)


def encode_bytes(data: bytes, profile_name: str) -> str:
    """
    Converts raw bytes to a safe representation for the given context.
    """
    return PROFILES[profile_name].encoder(data)
