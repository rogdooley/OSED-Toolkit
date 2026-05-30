# Gadget JSON Schema (User-Maintained)

This lab does not ship gadget addresses. Users populate gadget metadata after debugger analysis.

## File Location

- Recommended: `gadgets/gadgets_template.json`

## Structure

Top-level object keys:

- `modules`: object keyed by module filename.
- `gadgets`: object keyed by logical gadget name.

## modules Entry

Each module entry:

- `base`: string hex (`"0x10000000"`) or integer.
- `aslr`: boolean.
- `rebase`: boolean.
- `safeseh`: boolean.
- `nxcompat`: boolean.

Example:

```json
"modules": {
  "osedhelper.dll": {
    "base": "0x10000000",
    "aslr": false,
    "rebase": false,
    "safeseh": false,
    "nxcompat": false
  }
}
```

## gadgets Entry

Each gadget entry:

- `address`: string hex (`"0x10012345"`) or integer.
- `module`: module name string.
- `bytes`: optional disassembly/byte annotation string.

Example:

```json
"gadgets": {
  "pop_eax": {
    "address": "0x10012345",
    "module": "osedhelper.dll",
    "bytes": "58 C3"
  }
}
```

## Validation Rules

- Every gadget must reference a module present in `modules`.
- Hex values should be 32-bit address compatible for x86.
- Do not use placeholder `0x00000000` in active runs.
- Revalidate all addresses after process restart when ASLR is enabled.

## Safety Scope

- Use only in isolated local VM training.
- Keep payload outcomes benign and user-controlled.
