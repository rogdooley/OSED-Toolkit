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

- `base`: string hex (`"0x62500000"`) or integer.
- `aslr`: boolean.
- `rebase`: boolean.
- `safeseh`: boolean.
- `nxcompat`: boolean.

Example:

```json
"modules": {
  "osedhelper.dll": {
    "base": "0x62500000",
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
- `instruction`: disassembly or symbol annotation string.

Example:

```json
"gadgets": {
  "pop_eax_ret": {
    "address": "0x10012345",
    "module": "osedhelper.dll",
    "instruction": "pop eax; ret"
  }
}
```

## Validation Rules

- Every gadget must reference a module present in `modules`.
- Hex values should be 32-bit address compatible for x86.
- Do not use placeholder `0x00000000` in active runs.
- Revalidate all addresses after process restart when ASLR is enabled.
- `Tools.rop.GadgetDB` accepts this `modules`/`gadgets` envelope directly and
  ignores `modules` while resolving chain entries.
- `virtualprotect_ptr` must be executable: use a callable import thunk, wrapper,
  or resolved function address, not the address of a data-only IAT slot.

## Safety Scope

- Use only in isolated local VM training.
- Keep payload outcomes benign and user-controlled.
