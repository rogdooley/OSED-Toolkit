# Lab Targets

Permanent local dev utilities for validating `badchars_wds` behavior.

## Files

- `tcp_badchar_target.py`: basic TCP target with `normal`, `truncate`, and `crash` modes.
- `tcp_badchar_protocol_target.py`: protocol-wrapped target (`AUTH ...` + `SEND ...`) for transport/preamble testing.

## Basic usage

```bash
python Tools/badchars_wds/lab_targets/tcp_badchar_target.py --host 127.0.0.1 --port 9999 --mode normal
```

```bash
python Tools/badchars_wds/lab_targets/tcp_badchar_protocol_target.py --host 127.0.0.1 --port 10000 --mode truncate --trigger-byte 0x0a
```

## Notes

- Default bind is localhost (`127.0.0.1`) to avoid unintended exposure.
- `DEST_BUFFER` is global by design for debugger visibility.
