Egghunter Syscall Strategy (Windows x86)

This module leverages specific Windows Native API (Nt*) system calls as
safe memory probes when implementing egghunters.

Background
----------
An egghunter is a small first-stage payload that scans the process virtual
address space (VAS) to locate a marker (the "egg"), typically a repeated
4-byte tag (e.g., W00TW00T). The primary challenge is safely traversing
memory pages without triggering an access violation that would terminate
the process.

To solve this, egghunters intentionally invoke certain Nt* system calls
that internally validate user-supplied pointers and return error codes
instead of crashing when invalid memory is accessed.

Core Mechanism
--------------
The egghunter performs:

    mov eax, <syscall_id>
    int 0x2e

This transitions execution from user mode to kernel mode, invoking a
function from the System Service Dispatch Table (SSDT). The syscall
returns a status code in EAX (or AL), which is checked to determine
whether the probed memory address is valid.

If the page is invalid:
    STATUS_ACCESS_VIOLATION (0xC0000005)
    → AL == 0x05

The egghunter uses this to skip inaccessible memory safely.

Supported Syscalls
------------------

NtAccessCheckAndAuditAlarm (syscall # varies by OS)
    - Primary egghunter syscall.
    - Used because it reliably probes memory and returns an error code
      when encountering invalid pages.
    - Classic choice in most public egghunter implementations.

NtDisplayString
    - Alternative syscall with similar behavior.
    - Useful when bad characters prevent use of NtAccessCheckAndAuditAlarm.
    - Only differs in syscall number; egghunter structure remains identical.

NtQueryVirtualMemory
    - More advanced alternative.
    - Can be used to query memory region metadata (state, protection).
    - Requires more complex argument setup, increasing shellcode size.
    - Typically not used in minimal egghunters but useful in extended designs.

Design Considerations
---------------------

1. Syscall Number Variability
   Syscall IDs are not stable across Windows versions. They are resolved
   dynamically at runtime by extracting the `mov eax, <id>` instruction
   from ntdll.dll stubs.

2. Safety Requirement
   Only syscalls that safely validate memory access without crashing
   are suitable for egghunting.

3. Size Constraints
   Egghunters must remain extremely small (typically 32–40 bytes).
   Simpler syscalls are preferred to minimize instruction footprint.

4. WoW64 Compatibility
   On 64-bit systems running 32-bit processes, `int 0x2e` is handled by
   the WoW64 layer, which translates the call to the native 64-bit syscall.

Summary
-------
These syscalls are not used for their intended functionality, but rather
as controlled fault-generating probes. The egghunter abuses their pointer
validation logic to safely traverse memory and locate the tagged payload.
