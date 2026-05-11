import ctypes
from typing import Generator, Iterable, Optional, Union

from keystone import *

CODE = (
    "xor ecx, ecx;"  #
    "mov eax, fs:[ecx+0x30];"
    "mov eax, [eax+0x0c];"
    "mov eax, [eax+0x1c];"
    "sub eax, 0x10;"
    "next_module:"
    "mov esi, [eax+0x30];"
    "cmp word ptr [esi], 0x004b;"
    "jne next;"
    "cmp word ptr [esi+2], 0x0045;"
    "jne next;"
    "cmp word ptr [esi+12], 0x0033;"
    "jne next;"
    "jmp found_kernel32;"
    "next:"
    "mov eax, [eax+0x10];"
    "sub eax, 0x10;"
    "jmp next_module;"
    "found_kernel32:"
    "mov ebx, [eax+0x18];"
    "mov eax, [ebx+0x3c];"
    "add eax, ebx;"
    "mov eax, [eax+0x78]   ;"  # Export Directory RVA
    "add eax, ebx          ;"  # Export Directory VA"
    "mov ecx, [eax+0x18]   ;"  # ECX = NumberOfNames
    "mov edi, [eax+0x20]   ;"  # EDI = AddressOfNames RVA
    "add edi, ebx          ;"  # EDI = AddressOfNames VA
    "loop_here:"
    "jmp loop_here;"
)


def read_u32(addr: int) -> int:
    return ctypes.c_uint32.from_address(addr).value


## https://www.bordergate.co.uk/function-name-hashing/
def ror(value: int, bits: int) -> int:
    return (value >> bits | value << (32 - bits)) & 0xFFFFFFFF


def iter_utf16le_null(name: str, uppercase: bool = True) -> Generator[int, None, None]:
    if uppercase:
        name = name.upper()
    for char in name:
        yield ord(char) & 0xFF
        yield 0

    yield 0
    yield 0


def iter_ascii_null(name: str) -> Generator[int, None, None]:
    for char in name:
        yield ord(char)

    yield 0


def hash_bytes(stream: Iterable[int], bits: int = 13) -> int:
    hash = 0
    for byte in stream:
        hash = ror(hash, bits)
        hash += byte
        hash &= 0xFFFFFFFF

    return hash


def hash_api(module: str, function: str, bits: int = 13) -> int:
    module_hash = hash_bytes(iter_utf16le_null(module))
    function_hash = hash_bytes(iter_ascii_null(function))
    return (module_hash + function_hash) & 0xFFFFFFFF


def resolve_export_by_name(
    module_base: int, target_name: str
) -> Optional[Union[int, str]]:

    e_magic = ctypes.c_ushort.from_address(module_base).value
    e_lfanew = read_u32(module_base + 0x3C)

    print(f"e_magic: {e_magic:08x}")
    print(f"e_lfanew: {e_lfanew:08x}")

    nt_headers = module_base + e_lfanew

    print(f"nt headers: {nt_headers:08x}")
    pe_sig = read_u32(nt_headers)
    print(f"PE Signature: {pe_sig:08x}")

    optional_header = nt_headers + 0x18
    export_rva = read_u32(optional_header + 0x60)
    export_size = read_u32(optional_header + 0x64)

    print(f"Export RVA : {export_rva:08x}")
    print(f"Export Size: {export_size:08x}")

    export_dir_va = module_base + export_rva
    print(f"Export DIR VA: {export_dir_va:08x}")

    number_of_names = read_u32(export_dir_va + 0x18)

    addr_functions_rva = read_u32(export_dir_va + 0x1C)
    addr_names_rva = read_u32(export_dir_va + 0x20)
    addr_ordinals_rva = read_u32(export_dir_va + 0x24)

    addr_functions = module_base + addr_functions_rva
    addr_names = module_base + addr_names_rva
    addr_ordinals = module_base + addr_ordinals_rva

    print(f"NumberOfNames        : {number_of_names:08x} : {number_of_names}")
    print(f"AddressOfFunctions   : {addr_functions:08x}")
    print(f"AddressOfNames       : {addr_names:08x}")
    print(f"AddressOfNameOrdinals: {addr_ordinals:08x}")

    for i in range(number_of_names):
        name_rva = read_u32(addr_names + (i * 4))
        name_va = module_base + name_rva
        name = ctypes.string_at(name_va).decode()

        if name == target_name:
            ordinal = ctypes.c_ushort.from_address(addr_ordinals + (i * 2)).value
            function_rva = read_u32(addr_functions + (ordinal * 4))

            if export_rva <= function_rva < export_rva + export_size:
                return ctypes.string_at(module_base + function_rva).decode("ascii")

            return module_base + function_rva

    return None


def main():

    ntdll = ctypes.WinDLL("ntdll")
    teb_addr = ctypes.cast(ntdll.NtCurrentTeb(), ctypes.c_void_p).value
    peb_addr = read_u32(teb_addr + 0x30)
    ldr_addr = read_u32(peb_addr + 0x0C)
    head = ldr_addr + 0x1C
    node = read_u32(head)

    print(f"TEB Adrress: 0x{teb_addr:08x}")
    print(f"PEB Address: 0x{peb_addr:08x}")
    print(
        f"LDR Address: 0x{ldr_addr:08x}"
    )  # head == &PEB_LDR_DATA.InInitializationOrderModuleList

    idx = 0
    ntdll_base = None
    kernel32_base = None

    while node != head:
        entry = node - 0x10
        dll_base = read_u32(entry + 0x18)
        # name_len = read_u32(entry + 0x2C) & 0xFFFF
        name_len = ctypes.c_ushort.from_address(entry + 0x2C).value
        name_ptr = read_u32(entry + 0x30)
        name = ctypes.wstring_at(
            name_ptr, name_len // 2
        )  # unicode string is length in bytes and not characters (2 bytes/char)

        api_hash = hash_api(name, "WinExec")

        print(f"[{idx}] {name:<30} base=0x{dll_base:08x} api_hash=0x{api_hash:08x}")
        if name.lower() == "ntdll.dll":
            print(f"[+] Found ntdll.dll at ox{dll_base:08x}")
            ntdll_base = dll_base
        if name.lower() == "kernel32.dll":
            print(f"[+] Found kernel32.dll at 0x{dll_base:08x}")
            print(f"[+] KERNEL32.DLL!WinExec hash: 0x{hash_api(name, 'WinExec'):08x}")
            kernel32_base = dll_base

        if ntdll_base and kernel32_base:
            break

        idx += 1

        node = read_u32(node)

    if kernel32_base is None:
        raise RuntimeError("kernel32.dll not found")

    if ntdll_base is None:
        raise RuntimeError("ntdll.dll not found")

    winexec_va = resolve_export_by_name(kernel32_base, "WinExec")
    loadlibrarya_va = resolve_export_by_name(kernel32_base, "LoadLibraryA")
    getprocaddress_va = resolve_export_by_name(kernel32_base, "GetProcAddress")
    ntallocvm_va = resolve_export_by_name(ntdll_base, "NtAllocateVirtualMemory")

    print(f"WinExec:                 {winexec_va}")
    print(f"LoadLibraryA:            {loadlibrarya_va}")
    print(f"GetProcAddress:          {getprocaddress_va}")
    print(f"NtAllocateVirtualMemory: {ntallocvm_va}")

    # Initialize Keystone
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, _ = ks.asm(CODE)

    shellcode = bytearray(encoding)

    kernel32 = ctypes.windll.kernel32

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]

    kernel32.RtlMoveMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]

    kernel32.CreateThread.restype = ctypes.c_void_p

    ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    print(f"Shellcode at: 0x{ptr:08x}")

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    input("Attach WinDbg and press Enter...")

    ht = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not ht:
        raise RuntimeError("CreateThread failed")

    ctypes.windll.kernel32.WaitForSingleObject(ht, -1)


if __name__ == "__main__":
    main()
