# Command Reference

All commands are invoked via `dx @$osed().<command>(...)`.
Command calls return `true`/`false` for concise `dx` output.
Use `dx @$osed().last_result()` to inspect the full structured `CommandResult`.

## help

- Syntax: `dx @$osed().help(command?)`
- Flags/options:
  - `command` (optional, string)
- Description: Lists all commands or shows one command schema.
- Example 1: `dx @$osed().help()`
  - Expected output: command table plus structured schemas in `CommandResult.findings`.
- Example 2: `dx @$osed().help("badchars")`
  - Expected output: detailed usage/examples/schema for `badchars`.

## reload

- Syntax: `dx @$osed().reload()`
- Description: Clears and re-registers command registry.
- Example 1: `dx @$osed().reload()`
  - Expected output: `Re-registered <N> commands`.
- Example 2: `dx @$osed().reload()`
  - Expected output: same as above (idempotent).

## pattern_create

- Syntax: `dx @$osed().pattern_create(length, type?)`
- Defaults: `type="msf"`
- Description: Generates copy-ready cyclic pattern text.
- Example 1: `dx @$osed().pattern_create(300, "msf")`
  - Expected output: 300-byte Metasploit-compatible pattern.
- Example 2: `dx @$osed().pattern_create(512, "cyclic")`
  - Expected output: De Bruijn-based cyclic pattern.

## pattern_offset

- Syntax: `dx @$osed().pattern_offset(value, type?)`
- Value rules:
  - number: interpreted as little-endian crash value
  - string: hex only
- Description: Finds offset in selected pattern family.
- Example 1: `dx @$osed().pattern_offset(0x39654138, "msf")`
  - Expected output: offset integer.
- Example 2: `dx @$osed().pattern_offset("41326341", "cyclic")`
  - Expected output: offset integer or not-found message.

## badchars

- Syntax: `dx @$osed().badchars(address, exclude?)`
- Defaults: `exclude=[]`
- Description: Compares memory bytes against expected 0x00..0xFF progression.
- Notes:
  - `exclude` normalized to unique sorted bytes.
  - duplicate entries produce warning.
- Example 1: `dx @$osed().badchars(0x00B8F900)`
  - Expected output: mismatch table and next expected byte if break detected.
- Example 2: `dx @$osed().badchars("00B8F900", "00 0A 0D 00")`
  - Expected output: normalized exclude plus duplicate warning.

## egghunter

- Syntax: `dx @$osed().egghunter(tag?, mode?, wow64?)`
- Defaults: `tag="W00T"`, `mode="ntaccess"`, `wow64=false`
- Description: Emits egghunter shellcode as hex and Python bytes.
- Example 1: `dx @$osed().egghunter()`
  - Expected output: default x86 NtAccess variant.
- Example 2: `dx @$osed().egghunter("B33F", "seh", true)`
  - Expected output: WoW64/SEH-formatted hunter bytes.

## seh

- Syntax: `dx @$osed().seh()`
- Description: Walks x86 SEH chain from current TEB.
- Example 1: `dx @$osed().seh()`
  - Expected output: node/handler/module table with flagged suspicious entries.
- Example 2: `dx @$osed().seh()`
  - Expected output: warning on non-x86 contexts.

## modules

- Syntax: `dx @$osed().modules(filter?)`
- Description: Lists module base/size and mitigation tri-state.
- Example 1: `dx @$osed().modules()`
  - Expected output: full module table.
- Example 2: `dx @$osed().modules("essfunc")`
  - Expected output: filtered module rows.

## rop

- Syntax: `dx @$osed().rop(module?, maxResults?, executableOnly?, mode?)`
- Defaults: `executableOnly=true`, `maxResults=50`, `mode="fast"`
- Description: Module-scope helper for subsequent gadget commands.
- Example 1: `dx @$osed().rop()`
  - Expected output: module scope table.
- Example 2: `dx @$osed().rop("essfunc")`
  - Expected output: filtered module view.

## find_bytes

- Syntax: `dx @$osed().find_bytes(module, bytes, maxResults?, executableOnly?, mode?)`
- Description: Bounded section-aware byte matching.
- Example 1: `dx @$osed().find_bytes("essfunc", "FF E4")`
  - Expected output: sorted hit addresses and python-ready values.
- Example 2: `dx @$osed().find_bytes("essfunc", "58 C3", 25, true, "fast")`
  - Expected output: up to 25 matches with scan stats.

## rop_suggest

- Syntax: `dx @$osed().rop_suggest(module?, maxResults?, executableOnly?, mode?)`
- Description: Validated common gadget suggestions.
- Example 1: `dx @$osed().rop_suggest("essfunc")`
  - Expected output: validated pop/push/xchg gadget candidates.
- Example 2: `dx @$osed().rop_suggest(undefined, 50, true, "thorough")`
  - Expected output: stricter scan with richer stats.

## pivots

- Syntax: `dx @$osed().pivots(module?, maxResults?, executableOnly?, mode?)`
- Description: Finds validated stack pivot candidates.
- Example 1: `dx @$osed().pivots("essfunc")`
  - Expected output: sorted pivot addresses and instruction sequences.
- Example 2: `dx @$osed().pivots(undefined, 100, true, "thorough")`
  - Expected output: bounded comprehensive pivot scan.
