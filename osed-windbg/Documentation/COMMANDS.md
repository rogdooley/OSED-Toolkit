# Command Reference

All user-facing entry points are invoked via `dx @$osed().<name>(...)`.
Command calls return `true`/`false` for concise `dx` output.
Use `dx @$osed().last_result()` to inspect the full structured `CommandResult`.

## Top-Level Commands

| Command | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `help` | `dx @$osed().help(command?)` | `dx @$osed().help("badchars")` | Lists all commands or one schema. |
| `reload` | `dx @$osed().reload()` | `dx @$osed().reload()` | Clears and re-registers the command registry. |
| `pattern_create` | `dx @$osed().pattern_create(length, type?)` | `dx @$osed().pattern_create(300, "msf")` | Generates cyclic pattern text. |
| `pattern_offset` | `dx @$osed().pattern_offset(value, type?)` | `dx @$osed().pattern_offset(0x39654138, "msf")` | Finds an offset in the selected pattern family. |
| `badchars` | `dx @$osed().badchars(address, exclude?)` | `dx @$osed().badchars(0x00B8F900)` | Compares memory bytes against the expected byte sequence. |
| `egghunter` | `dx @$osed().egghunter(tag?, mode?, wow64?)` | `dx @$osed().egghunter("W00T", "ntaccess", false)` | Emits egghunter shellcode as hex and Python bytes. |
| `exploit` | `dx @$osed().exploit(mode, tag?, offset?, address?)` | `dx @$osed().exploit("offset")` | Emits deterministic exploit-workflow command strings. |
| `seh` | `dx @$osed().seh()` | `dx @$osed().seh()` | Walks the current thread SEH chain. x86-only in v1. |
| `triage` | `dx @$osed().triage(patternLength?, badchars?, module?, stackBytes?)` | `dx @$osed().triage(8000, "00 0A 0D", "essfunc", 2048)` | Fast crash triage for control, SEH, stack, and gadget context. |
| `modules` | `dx @$osed().modules(filter?)` | `dx @$osed().modules("essfunc")` | Lists modules and mitigation state. |
| `rop` | `dx @$osed().rop(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().rop("essfunc")` | Sets module scope for ROP exploration. |
| `find_bytes` | `dx @$osed().find_bytes(module, bytes, maxResults?, executableOnly?, mode?)` | `dx @$osed().find_bytes("essfunc", "FF E4")` | Finds byte sequences in executable sections. |
| `rop_suggest` | `dx @$osed().rop_suggest(module?, maxResults?, executableOnly?, mode?, engine?)` | `dx @$osed().rop_suggest("essfunc", 50, true, "fast", "semantic")` | Suggests validated gadget patterns. |
| `retn` | `dx @$osed().retn(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().retn("essfunc")` | Finds `retn N` gadgets for stdcall chain adjustment. |
| `add_esp` | `dx @$osed().add_esp(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().add_esp("essfunc")` | Finds `add esp, N ; ret` gadgets. |
| `pivots` | `dx @$osed().pivots(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().pivots("essfunc")` | Finds stack pivot candidates. |
| `seh_ppr` | `dx @$osed().seh_ppr(module?, exclude?, maxResults?, executableOnly?, mode?)` | `dx @$osed().seh_ppr("libspp.dll", "00 0A 0D")` | Finds and ranks `pop ; pop ; ret` gadgets. |
| `encode` | `dx @$osed().encode(shellcode, exclude?, key?)` | `dx @$osed().encode({ shellcode: "fc e8...", exclude: [0, 10, 13] })` | XOR-encodes shellcode to avoid bad characters. |
| `nop` | `dx @$osed().nop(length, byte?)` | `dx @$osed().nop(16)` | Generates a NOP sled. |
| `rop_template` | `dx @$osed().rop_template(api?, module?)` | `dx @$osed().rop_template("VirtualProtect", "essfunc")` | Prints a commented ROP chain skeleton. |

## Command Shortcuts

These are aliases backed by top-level commands.

| Shortcut | Underlying command | Example |
| --- | --- | --- |
| `pattern.create` | `pattern_create` | `dx @$osed().pattern.create(300, "msf")` |
| `pattern.offset` | `pattern_offset` | `dx @$osed().pattern.offset(0x39654138, "msf")` |
| `seh.visualize` | `seh` | `dx @$osed().seh.visualize()` |

## Shellcode Helpers

The `sc` namespace exposes module, PE, export, hash, and IAT helpers.

### Module and PE helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.peb` | `dx @$osed().sc.peb()` | `dx @$osed().sc.peb()` | Dumps the current PEB. |
| `sc.modules` | `dx @$osed().sc.modules()` | `dx @$osed().sc.modules()` | Lists loaded modules. |
| `sc.module_pages` | `dx @$osed().sc.module_pages(name)` | `dx @$osed().sc.module_pages("kernel32")` | Reports size and estimated 4 KiB page count. |
| `sc.page_summary` | `dx @$osed().sc.page_summary(name)` | `dx @$osed().sc.page_summary("kernel32")` | Buckets pages by `!vprot` protection value. |
| `sc.base` | `dx @$osed().sc.base(name)` | `dx @$osed().sc.base("kernel32")` | Resolves the module base address. |
| `sc.pe` | `dx @$osed().sc.pe(name)` | `dx @$osed().sc.pe("kernel32")` | Prints PE header fields for the module. |

### Export and hash helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.exports` | `dx @$osed().sc.exports(name, filter?)` | `dx @$osed().sc.exports("kernel32", "Virtual")` | Enumerates exported symbols. |
| `sc.resolve` | `dx @$osed().sc.resolve(module, symbol)` | `dx @$osed().sc.resolve("kernel32", "WinExec")` | Resolves one export to an address. |
| `sc.hashes` | `dx @$osed().sc.hashes(module, algorithm?)` | `dx @$osed().sc.hashes("kernel32", "crc32")` | Hashes named exports. |
| `sc.hash` | `dx @$osed().sc.hash(name, algorithm?)` | `dx @$osed().sc.hash("WinExec", "ROR13")` | Hashes one string. |
| `sc.hashresolve` | `dx @$osed().sc.hashresolve(module, hashValue, algorithm?)` | `dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")` | Resolves a hash back to a symbol. |
| `sc.algorithms` | `dx @$osed().sc.algorithms()` | `dx @$osed().sc.algorithms()` | Lists supported hash algorithms. |
| `sc.exportdir` | `dx @$osed().sc.exportdir(module)` | `dx @$osed().sc.exportdir("kernel32")` | Shows the export directory location and metadata. |
| `sc.export` | `dx @$osed().sc.export(module, symbol)` | `dx @$osed().sc.export("kernel32", "GetProcAddress")` | Shows export address and forwarder data. |
| `sc.exportat` | `dx @$osed().sc.exportat(module, ordinalIndex)` | `dx @$osed().sc.exportat("kernel32", 842)` | Resolves an export by ordinal index. |
| `sc.exportwalk` | `dx @$osed().sc.exportwalk(module, symbol?, verbose?)` | `dx @$osed().sc.exportwalk("kernel32", "GetProcAddress", true)` | Walks the export tables step by step. |

### IAT helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.iat` | `dx @$osed().sc.iat(module?)` | `dx @$osed().sc.iat("app.exe")` | Enumerates imported addresses for a module. |
| `sc.iat_find` | `dx @$osed().sc.iat_find(symbol)` | `dx @$osed().sc.iat_find("VirtualAlloc")` | Searches all loaded modules for matching IAT entries. |
| `sc.iat_ptr` | `dx @$osed().sc.iat_ptr(module, symbol)` | `dx @$osed().sc.iat_ptr("app.exe", "VirtualAlloc")` | Resolves an IAT slot and target pointer for one symbol. |

## Runtime Helpers

These are exposed on `osed` for inspection and cleanup, but they are not part of the command registry.

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `last_result` | `dx @$osed().last_result()` | `dx @$osed().last_result()` | Returns the full structured result from the last command. |
| `last_summary` | `dx @$osed().last_summary()` | `dx @$osed().last_summary()` | Returns a compact summary of the last command result. |
| `clear_last_result` | `dx @$osed().clear_last_result()` | `dx @$osed().clear_last_result()` | Clears the stored result snapshot. |
