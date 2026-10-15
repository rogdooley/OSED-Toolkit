"""Instructor-only reference models for processing-stage assertions."""

from __future__ import annotations


def _snapshots(initial: bytes, pre: bytes, post: bytes, final: bytes | None = None) -> dict[str, bytes]:
    return {
        "initial": initial,
        "pre_transform": pre,
        "post_transform": post,
        "final": post if final is None else final,
    }


def net02_stages(candidate: bytes) -> dict[str, bytes]:
    output = bytearray()
    quoted = False
    escaped = False
    for value in candidate:
        if escaped:
            output.append(value ^ 0x20)
            escaped = False
        elif value == ord("\\"):
            escaped = True
        elif value == ord('"'):
            quoted = not quoted
        elif value == ord(";") and not quoted:
            output.append(ord("|"))
        elif not quoted and ord("a") <= value <= ord("z"):
            output.append(value - 0x20)
        else:
            output.append(value)
    if escaped:
        output.append(ord("\\"))
    return _snapshots(candidate, candidate, bytes(output))


def _length_records(candidate: bytes) -> list[bytes]:
    records: list[bytes] = []
    index = 0
    while index < len(candidate):
        length = candidate[index]
        index += 1
        if length == 0:
            continue
        if index + length > len(candidate):
            raise ValueError("truncated record")
        records.append(candidate[index : index + length])
        index += length
    return records


def net03_stages(candidate: bytes) -> dict[str, bytes]:
    records = _length_records(candidate)
    pre = b"".join(records)
    post = b"".join(bytes(value ^ ((record_index + 1) * 0x11) for value in record)
                    for record_index, record in enumerate(records))
    return _snapshots(candidate, pre, post, post[:256])


def _typed_records(candidate: bytes) -> list[tuple[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    index = 0
    while index < len(candidate):
        if index + 2 > len(candidate):
            raise ValueError("truncated record header")
        kind, length = candidate[index], candidate[index + 1]
        index += 2
        if index + length > len(candidate):
            raise ValueError("truncated record")
        records.append((kind, candidate[index : index + length]))
        index += length
    return records


def file01_stages(candidate: bytes) -> dict[str, bytes]:
    records = _typed_records(candidate)
    pre = b"".join(record for _, record in records)
    post = bytearray()
    for kind, record in records:
        if kind & 1:
            for value in record:
                if value == 0x1A:
                    break
                post.append(value)
        else:
            post.extend(record)
    return _snapshots(candidate, pre, bytes(post))


def file02_stages(candidate: bytes) -> dict[str, bytes]:
    records = _length_records(candidate)
    pre = b"".join(records)
    post = b"".join(bytes(value ^ ((index + 1) * 0x11) for value in record)
                    for index, record in enumerate(records))
    return _snapshots(candidate, pre, post)


def file03_stages(candidate: bytes) -> dict[str, bytes]:
    records = _typed_records(candidate)
    pre = b"".join(record for _, record in records)
    post = bytearray()
    for kind, record in records:
        escaped = False
        for value in record:
            if kind & 1 and escaped:
                post.append(value ^ 0x20)
                escaped = False
            elif kind & 1 and value == ord("\\"):
                escaped = True
            else:
                post.append(value)
        if escaped:
            post.append(ord("\\"))
    return _snapshots(candidate, pre, bytes(post), bytes(post[:256]))
