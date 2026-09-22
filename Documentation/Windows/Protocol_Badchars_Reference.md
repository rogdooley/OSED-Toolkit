# Protocol Badchars Reference (Baseline)

These are **starting-point** badchar sets by protocol/placement.

Use them as transport-level baselines, then add target/app-specific badchars from live testing.

## Important

- These are not guaranteed final badchars for every target.
- Always confirm with badchar testing in debugger/memory.
- Keep transport badchars separate from target parser/mutator badchars.

## Baseline Profiles

| Profile | Baseline badchars (hex) | Notes |
|---|---|---|
| `raw_tcp_binary_min` | `00` | Typical binary stream minimum |
| `raw_udp_binary_min` | `00` | Typical binary datagram minimum |
| `http_get_path_min` | `00 09 0a 0d 20 25 26 2b 3d` | Your baseline for GET path delivery |
| `http_get_query_min` | `00 09 0a 0d 20 23 25 26 2b 3d` | Adds `23` (`#`) for query/URI handling |
| `http_header_value_min` | `00 0a 0d` | CR/LF and null are header-breaking |
| `http_post_body_min` | `00` | Raw octet-stream body starting point |
| `http_form_body_min` | `00 09 0a 0d 20 25 26 2b 3d` | URL-encoded form semantics |
| `ftp_command_min` | `00 09 0a 0d 20` | Line/token-based command channel |
| `smtp_command_min` | `00 09 0a 0d 20` | Line/token-based command channel |
| `pop3_command_min` | `00 09 0a 0d 20` | Line/token-based command channel |
| `imap_command_min` | `00 09 0a 0d 20` | Line/token-based command channel |
| `irc_command_min` | `00 0a 0d 20` | IRC command/message framing |
| `telnet_min` | `00 0a 0d ff` | `ff` is IAC control byte |

## Python Snippet

```python
BADCHAR_PROFILES = {
    "raw_tcp_binary_min": b"\x00",
    "raw_udp_binary_min": b"\x00",
    "http_get_path_min": b"\x00\x09\x0a\x0d\x20\x25\x26\x2b\x3d",
    "http_get_query_min": b"\x00\x09\x0a\x0d\x20\x23\x25\x26\x2b\x3d",
    "http_header_value_min": b"\x00\x0a\x0d",
    "http_post_body_min": b"\x00",
    "http_form_body_min": b"\x00\x09\x0a\x0d\x20\x25\x26\x2b\x3d",
    "ftp_command_min": b"\x00\x09\x0a\x0d\x20",
    "smtp_command_min": b"\x00\x09\x0a\x0d\x20",
    "pop3_command_min": b"\x00\x09\x0a\x0d\x20",
    "imap_command_min": b"\x00\x09\x0a\x0d\x20",
    "irc_command_min": b"\x00\x0a\x0d\x20",
    "telnet_min": b"\x00\x0a\x0d\xff",
}
```

## Workflow Suggestion

1. Pick a profile based on delivery path (for example `http_get_path_min`).
2. Generate/send badchar chunks.
3. Inspect memory and mark observed failures.
4. Append discovered app-specific badchars (for example mutator bytes like `3b`, `45`).
5. Regenerate payloads using merged badchar set.
