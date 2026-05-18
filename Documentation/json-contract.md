# Shellforge JSON Contract

## 1. Envelope schema
Every JSON response has the same top-level envelope:

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_at": "2026-04-26T20:00:00Z",
  "request_id": "8d6b4a43-7c90-49b7-b2a1-3f8f6d0bdb72",
  "command": "pe.list",
  "ok": true,
  "result": {}
}
```

Rules:
- `generated_at` is RFC3339 UTC with trailing `Z`.
- `request_id` is UUIDv4.
- Exactly one payload node is present:
  - success: `result`
  - failure: `error`

## 2. Success schema

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_at": "2026-04-26T20:00:00Z",
  "request_id": "uuid",
  "command": "hash.compute",
  "ok": true,
  "result": {
    "algorithm": "ror13",
    "symbol": "GetProcAddress",
    "hash": { "value": 2081291434, "hex": "0x7c0dfcaa" }
  }
}
```

## 3. Error schema

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_at": "2026-04-26T20:00:00Z",
  "request_id": "uuid",
  "command": "pe.list",
  "ok": false,
  "error": {
    "code": "invalid_pe_signature",
    "message": "Missing MZ header",
    "details": {
      "exception_type": "ShellforgeError",
      "offset": 0
    }
  }
}
```

## 4. Command schemas

### Canonical command registry

| command_id | description | result schema |
|---|---|---|
| `build.demo` | build non-operational demo payload artifact | `BuildResult` |
| `build.calc` | invoke calc payload provider (currently intentionally non-operational/stubbed) | `BuildResult` |
| `hash.compute` | compute a hash for a symbol string | `HashResult` |
| `hash.resolve` | resolve a hash against PE export names | `HashResolveResult` |
| `check.badchars` | scan input bytes for configured bad characters | `BadcharCheckResult` |
| `encode.xor` | XOR-encode bytes with automatic/manual keying | `EncodeResult` |
| `encode.decode` | XOR-decode bytes with provided key | `EncodeResult` |
| `pe.list` | enumerate PE sections and exports | `PeListResult` |
| `pe.resolve_name` | resolve an export by symbol name | `ResolveResult` |
| `pe.resolve_hash` | resolve an export by hash algorithm/value | `ResolveResult` |
| `pe.imports` | enumerate PE import descriptors/thunks | `PeImportsResult` |
| `pe.rva_to_file` | map RVA to file offset | `PeAddressMapResult` |
| `pe.file_to_rva` | map file offset to RVA | `PeAddressMapResult` |
| `pe.rva_to_va` | map RVA to virtual address | `PeAddressMapResult` |
| `pe.va_to_rva` | map virtual address to RVA | `PeAddressMapResult` |
| `disasm.analyze` | offline disassembly analysis of raw bytes | `DisasmResult` |
| `analyze.static` | static shellcode-oriented signature analysis | `AnalyzeResult` |
| `cli.parse` | parser-level CLI failures before command dispatch | `ErrorEnvelope` |

### `hash`
`result` keys:
- `algorithm`
- `symbol`
- `hash` (`value`, `hex`)

### `hash.resolve`
`result` keys:
- `algorithm`
- `file`
- `hash` (`value`, `hex`)
- `format`
- `result` (export object)

### `check.badchars`
`result` keys:
- `file`
- `badchars` (hex byte strings)
- `offsets`
- `match_count`
- `size`

### `encode.xor` and `encode.decode`
`result` keys:
- `encoder`
- `mode`
- `file`
- `input_size`
- `output_size`
- `key` (`value`, `hex`)
- `badchars` (encode mode)
- `output_path`

### `build.<payload>`
`result` keys:
- `payload`
- `arch`
- `format`
- `payload_size`
- `output_path`
- `nasm_path`
- `metadata`

### `pe.list`
`result` keys:
- `file`
- `count`
- `machine` (`value`, `hex`, `name`)
- `format` (`PE32` or `PE32+`)
- `image_base`
- `image_base_hex`
- `entrypoint_rva`
- `entrypoint_rva_hex`
- `sections[]`
- `exports[]`

Section object keys:
- `name`
- `virtual_address`, `virtual_address_hex`
- `virtual_size`
- `pointer_to_raw_data`, `pointer_to_raw_data_hex`
- `size_of_raw_data`

Export object keys:
- `ordinal`
- `name`
- `rva`, `rva_hex`

### `pe.resolve_name`
`result` keys:
- `file`
- `query`
- `format`
- `result` (export object)

### `pe.resolve_hash`
`result` keys:
- `file`
- `algorithm`
- `hash` (`value`, `hex`)
- `format`
- `result` (export object)

### `pe.imports`
`result` keys:
- `file`
- `format`
- `count`
- `imports[]`

Import object keys:
- `dll`
- `name` (nullable for ordinal-only import)
- `ordinal` (nullable for name import)
- `hint` (nullable for ordinal import)
- `thunk_rva`, `thunk_rva_hex`
- `iat_rva`, `iat_rva_hex`

### `pe.rva_to_file`
`result` keys:
- `file`
- `rva`, `rva_hex`
- `file_offset`, `file_offset_hex`
- `section` (nullable)

### `pe.file_to_rva`
`result` keys:
- `file`
- `file_offset`, `file_offset_hex`
- `rva`, `rva_hex`
- `section` (nullable)

### `pe.rva_to_va`
`result` keys:
- `file`
- `image_base`, `image_base_hex`
- `rva`, `rva_hex`
- `va`, `va_hex`
- `section` (nullable)

### `pe.va_to_rva`
`result` keys:
- `file`
- `image_base`, `image_base_hex`
- `va`, `va_hex`
- `rva`, `rva_hex`
- `section` (nullable)

### `disasm.analyze`
`result` keys:
- `file`
- `arch` (`x86` or `x64`)
- `base`, `base_hex`
- `instruction_count`
- `metadata`
- `instructions[]`

Metadata keys:
- `entropy`
- `printable_ratio`
- `null_byte_count`
- `size`

Instruction object keys:
- `address`, `address_hex`
- `bytes`
- `mnemonic`
- `operands`

### `analyze.static`
`result` keys:
- `file`
- `detected_arch` (`x86` or `x64`)
- `detection_confidence` (`0.0..1.0`)
- `size`
- `metadata` (`entropy`, `printable_ratio`, `null_byte_count`)
- `heuristics[]` (`name`, `matched`, `confidence`, `offsets`)
- `peb_walk_signatures[]`
- `segment_access_signatures[]`
- `egg_markers[]`
- `nop_regions[]`
- `decoder_loop_signatures[]`
- `hash_candidates[]`
- `entropy_profile[]` (`offset`, `size`, `entropy`)
- `strings[]`
- `strings_min_len`
- `max_strings`
- `strings_truncated`
- `max_hits`
- `summary_only` (full mode always false)

Heuristic object keys:
- `name`
- `matched`
- `confidence`
- `offsets` (capped by `max_hits`)
- `total_hits`
- `truncated`

Summary-only mode (`--summary-only`) emits a compact `result`:
- `file`
- `size`
- `detected_arch`
- `detection_confidence`
- `entropy`
- `printable_ratio`
- `null_byte_count`
- `heuristic_hits`
- `likely_decoder`

Signature object keys:
- `offset`
- `kind`
- `detail`

## 5. Error-code matrix

| code | meaning | exception_type |
|---|---|---|
| `file_not_found` | input path missing | `FileNotFoundError` |
| `file_read_error` | read/access failure | `OSError` / `PermissionError` |
| `invalid_pe_signature` | missing DOS MZ header | `ShellforgeError` |
| `invalid_nt_signature` | missing PE signature | `ShellforgeError` |
| `unsupported_pe_format` | unsupported optional-header type/format | `ShellforgeError` |
| `invalid_optional_header` | malformed optional header | `ShellforgeError` |
| `invalid_rva` | RVA mapping outside sections | `ShellforgeError` |
| `parse_error` | malformed binary structure | `ShellforgeError` |
| `invalid_argument` | invalid CLI argument or lookup miss | `ValueError` / `ShellforgeError` |
| `internal_error` | unexpected unhandled failure | `Exception` |

## 6. Examples

### Success (`pe.list`)
```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_at": "2026-04-26T20:00:00Z",
  "request_id": "8d6b4a43-7c90-49b7-b2a1-3f8f6d0bdb72",
  "command": "pe.list",
  "ok": true,
  "result": {
    "file": "/tmp/fixture.dll",
    "count": 1,
    "machine": { "value": 34404, "hex": "0x8664", "name": "AMD64" },
    "format": "PE32+",
    "image_base": 5368709120,
    "image_base_hex": "0x140000000",
    "entrypoint_rva": 4096,
    "entrypoint_rva_hex": "0x00001000",
    "sections": [],
    "exports": []
  }
}
```

### Error (`pe.list`)
```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_at": "2026-04-26T20:00:00Z",
  "request_id": "8d6b4a43-7c90-49b7-b2a1-3f8f6d0bdb72",
  "command": "pe.list",
  "ok": false,
  "error": {
    "code": "invalid_pe_signature",
    "message": "Missing MZ header",
    "details": { "exception_type": "ShellforgeError", "offset": 0 }
  }
}
```

## 7. Schema evolution policy
- Changes are additive-only within a schema version.
- Existing keys and semantic meaning are stable.
- `schema_version` increments only for breaking changes.
- Consumers should branch on `ok` and then read either `result` or `error`.
- Command identifiers are namespaced and dotted (examples: `build.demo`, `hash.compute`, `hash.resolve`, `check.badchars`, `encode.xor`, `encode.decode`, `pe.list`, `pe.resolve_name`, `pe.resolve_hash`, `pe.imports`, `pe.rva_to_file`, `pe.file_to_rva`, `pe.rva_to_va`, `pe.va_to_rva`, `disasm.analyze`, `analyze.static`).
- Top-level envelope keys are strict:
  - success: `schema_version`, `tool_version`, `generated_at`, `request_id`, `command`, `ok`, `result`
  - failure: `schema_version`, `tool_version`, `generated_at`, `request_id`, `command`, `ok`, `error`

## 8. Exit code contract

| exit | meaning |
|---|---|
| `0` | success |
| `2` | invalid arguments / invalid lookup |
| `3` | file error |
| `4` | parse error |
| `5` | unsupported format |
| `10` | internal error |
