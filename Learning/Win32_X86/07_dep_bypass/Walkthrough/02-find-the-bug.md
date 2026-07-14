## 2. Finding the bug: follow bytes, not function names

The wrong way to find this bug is to grep for `sscanf`, `strcpy`, `memcpy` and
start reading. That habit fails on real targets, where dangerous-looking calls
are usually safe and the exploitable one looks mundane. The right lens is
**attacker-controlled dataflow**:

```
Where does external input enter?
        ↓
How is it parsed / transformed?
        ↓
Where is it copied or formatted?
        ↓
What memory object receives it?
        ↓
Is the destination bounded?
        ↓
Can a valid packet actually reach that path?
```

Work it in three passes.

### 2.1 Pass 1 — reachability

Trace a packet from the socket to a handler. In `dispatch.c`:

```
recv header → validate magic → bound body_len ≤ 0x2000 → recv body → NUL-terminate
        ↓
switch (opcode):
    OP_PING/AUTH/STATUS/CONFIG_GET/CONFIG_SET/LOG_UPLOAD/COMPRESS/STATS/QUIT
```

Two reachability facts jump out:

- **`body_len` is capped at `0x2000` on the wire**, far larger than any small
  stack buffer downstream. The transport is not the guard.
- **`OP_CONFIG_SET` is reachable, but its handler checks `c->authenticated`
  first.** So the vulnerable path (whatever it is) requires a prior successful
  `OP_AUTH`. That is realistic gating, not a dead end — you can authenticate.

### 2.2 Pass 2 — taint flow

Follow the body bytes into the handlers that copy them. Three parsers in
`parser.c` all take attacker bytes:

```
body ──▶ parse_status_query()   sscanf(body, "module=%63s", module[64])
body ──▶ parse_log_upload()     memcpy(log_name[128], body, len)   [len checked]
body ──▶ parse_config_set()     sscanf(body, "%31s %63s %s", command, name, value)
```

### 2.3 Pass 3 — constraint analysis (the part that actually decides)

Do **not** stop at "sscanf → suspicious". Read the widths and checks.

```
parse_status_query   "module=%63s"  → 63-char cap into a 64-byte buffer   SAFE
parse_log_upload     memcpy(len)     → `if (len >= sizeof(log_name)) return` SAFE
parse_config_set     "%31s %63s %s"  → third token has NO WIDTH LIMIT       BUG
```

The first two are textbook dead ends: one *looks* like the classic vulnerable
`sscanf %s` but is width-limited; the other *looks* like a raw attacker-bytes
`memcpy` but is length-checked first. The third looks the most innocuous from
the dispatcher, yet its final `%s` writes into the 256-byte stack buffer `value`
with no bound.

> **Design decision — the transferable rule.** The bug is not "sscanf is
> dangerous." The bug is: *attacker-controlled input, copied into a fixed-size
> stack buffer, through an unbounded conversion, on a reachable path.* All four
> clauses must hold. `parse_config_set` is the only place they all do.

The vulnerable frame therefore belongs to `parse_config_set`. When it returns to
`handle_config_set`, the saved return address it pops is the one your long third
token overwrote.

> **Verify in disassembly (source-free skill).** Even with the source in hand,
> practise recovering this from the binary. In WinDbg:
> `x service!parse_config_set` then `uf service!parse_config_set`. Find the
> `call ... sscanf`, note the three `lea` of stack locals passed as args, and
> observe there is no `__security_check_cookie` in the epilogue (we built
> `/GS-`). No cookie means a smashed return address is used directly.

---

---

[← Previous](01-recon.md) · [Index](00-index.md) · [Next →](03-choosing-a-gadget-source.md)
