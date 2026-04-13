import ctypes
import ctypes.wintypes as wintypes

### Returns syscalls for various nt functions
### Python 3.7 safe for OSED labs


def extract_syscall_id(addr):
    buf = (ctypes.c_ubyte * 32).from_address(addr)

    for i in range(len(buf) - 4):
        if buf[i] == 0xB8:  # mov eax, imm32
            return int.from_bytes(bytes(buf[i + 1 : i + 5]), "little")

    return None


def get_all_syscalls():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    GetModuleHandleA = kernel32.GetModuleHandleA
    GetProcAddress = kernel32.GetProcAddress

    GetModuleHandleA.argtypes = [wintypes.LPCSTR]
    GetModuleHandleA.restype = wintypes.HMODULE

    GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    GetProcAddress.restype = wintypes.LPVOID

    h_ntdll = GetModuleHandleA(b"ntdll.dll")

    # Hardcoded list of common Nt* functions (clean + portable)
    nt_functions = [
        b"NtAccessCheckAndAuditAlarm",
        b"NtDisplayString",
        b"NtReadVirtualMemory",
        b"NtWriteVirtualMemory",
        b"NtProtectVirtualMemory",
        b"NtAllocateVirtualMemory",
        b"NtFreeVirtualMemory",
        b"NtQueryInformationProcess",
        b"NtOpenProcess",
        b"NtClose",
        b"NtQueryVirtualMemory",
        b"NtReadVirtualMemory",
        b"NtProtectVirtualMemory",
    ]

    syscalls = {}

    for name in nt_functions:
        addr = GetProcAddress(h_ntdll, name)
        if not addr:
            continue

        syscall_id = extract_syscall_id(addr)
        if syscall_id is not None:
            syscalls[name.decode()] = syscall_id

    return syscalls


if __name__ == "__main__":
    syscalls = get_all_syscalls()

    for name in sorted(syscalls):
        print(f"{name:<40} {syscalls[name]:#04x}")
