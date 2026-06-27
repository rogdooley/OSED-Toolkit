/*
 * manual_getprocaddr.c
 *
 * Manual API resolution via PEB traversal and PE export directory parsing.
 * 32-bit x86 only. Mirrors the technique used in position-independent
 * shellcode when the import table is not available.
 *
 * Build (MinGW/GCC):
 *   gcc -m32 -Wall -o manual_getprocaddr.exe manual_getprocaddr.c
 *
 * Expected output (addresses will differ per run/machine):
 *   kernel32.dll hash  : 0x________
 *   WinExec hash       : 0x________
 *   Manual resolution  : 0x________
 *   Real GetProcAddr   : 0x________
 *   MATCH
 */

#include <windows.h>
#include <stddef.h>   /* offsetof */
#include <stdio.h>
#include <wchar.h>    /* wcslen   */

/* ------------------------------------------------------------------
 * Minimal structure definitions
 *
 * winternl.h exposes some of these but with reserved fields that
 * obscure the layout. Defining them explicitly maps directly onto
 * the memory we will observe in WinDbg. Comments show 32-bit offsets.
 * ------------------------------------------------------------------ */

typedef struct _UNICODE_STR {
    USHORT Length;          /* byte length — NOT character count */
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;            /* 0x00 */
    LIST_ENTRY  InMemoryOrderModuleList;          /* 0x08 */
    LIST_ENTRY  InInitializationOrderModuleList;  /* 0x10 */
    PVOID       DllBase;                          /* 0x18 */
    PVOID       EntryPoint;                       /* 0x1C */
    ULONG       SizeOfImage;                      /* 0x20 */
    UNICODE_STR FullDllName;                      /* 0x24 */
    UNICODE_STR BaseDllName;                      /* 0x2C */
} MY_LDR_ENTRY, *PMY_LDR_ENTRY;

typedef struct _MY_PEB_LDR {
    ULONG      Length;                            /* 0x00 */
    ULONG      Initialized;                       /* 0x04 */
    PVOID      SsHandle;                          /* 0x08 */
    LIST_ENTRY InLoadOrderModuleList;             /* 0x0C */
    LIST_ENTRY InMemoryOrderModuleList;           /* 0x14 */
    LIST_ENTRY InInitializationOrderModuleList;   /* 0x1C */
} MY_PEB_LDR, *PMY_PEB_LDR;

typedef struct _MY_PEB {
    BYTE        InheritedAddressSpace;            /* 0x00 */
    BYTE        ReadImageFileExecOptions;         /* 0x01 */
    BYTE        BeingDebugged;                    /* 0x02 */
    BYTE        Spare;                            /* 0x03 */
    PVOID       Mutant;                           /* 0x04 */
    PVOID       ImageBaseAddress;                 /* 0x08 */
    PMY_PEB_LDR Ldr;                             /* 0x0C */
} MY_PEB, *PMY_PEB;

/* ------------------------------------------------------------------
 * ror13_hash
 *
 * Rotate-right-13 over each byte of an ASCII string.
 * Used to identify API names without embedding plaintext in shellcode.
 * ------------------------------------------------------------------ */
static DWORD ror13_hash(const char *name) {
    DWORD hash = 0;
    while (*name) {
        hash = ((hash >> 13) | (hash << 19)) + (BYTE)*name;
        name++;
    }
    return hash;
}

/* ------------------------------------------------------------------
 * ror13_hash_unicode
 *
 * Same algorithm over a UTF-16 string. Module names in the PEB are
 * stored as Unicode. Lowercases A-Z so that "KERNEL32.DLL" and
 * "kernel32.dll" hash identically.
 *
 * byte_len: the Length field from UNICODE_STR (bytes, not chars).
 * ------------------------------------------------------------------ */
static DWORD ror13_hash_unicode(PWSTR name, USHORT byte_len) {
    DWORD  hash      = 0;
    USHORT charcount = byte_len / sizeof(WCHAR);
    for (USHORT i = 0; i < charcount; i++) {
        WCHAR c = name[i];
        if (c >= L'A' && c <= L'Z') c |= 0x20;   /* to lowercase */
        hash = ((hash >> 13) | (hash << 19)) + (BYTE)c;
    }
    return hash;
}

/* ------------------------------------------------------------------
 * find_module_by_hash
 *
 * Reads PEB from FS:[0x30], walks Ldr->InMemoryOrderModuleList.
 * Returns DllBase of the first module whose BaseDllName hashes
 * to target_hash, or NULL if not found.
 * ------------------------------------------------------------------ */
static PVOID find_module_by_hash(DWORD target_hash) {
    PMY_PEB peb;

    /* FS:[0x30] holds the PEB address on 32-bit Windows */
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur != head) {
        /*
         * cur points at the InMemoryOrderModuleList LIST_ENTRY
         * inside a MY_LDR_ENTRY. Subtract the field's offset to
         * recover the base address of the enclosing struct.
         */
        PMY_LDR_ENTRY entry = (PMY_LDR_ENTRY)(
            (BYTE *)cur - offsetof(MY_LDR_ENTRY, InMemoryOrderModuleList));

        if (entry->BaseDllName.Length > 0) {
            DWORD h = ror13_hash_unicode(entry->BaseDllName.Buffer,
                                          entry->BaseDllName.Length);
            if (h == target_hash)
                return entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* ------------------------------------------------------------------
 * resolve_export
 *
 * Parses the PE export directory at module_base. Returns the VA of
 * the export whose ASCII name hashes to target_hash, or NULL.
 *
 * Export directory layout:
 *   AddressOfNames[i]         -> RVA of name string
 *   AddressOfNameOrdinals[i]  -> ordinal index into AddressOfFunctions
 *   AddressOfFunctions[ord]   -> RVA of function
 *   function VA = module_base + RVA
 * ------------------------------------------------------------------ */
static PVOID resolve_export(PVOID module_base, DWORD target_hash) {
    BYTE *base = (BYTE *)module_base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (dir->VirtualAddress == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);

    DWORD *names    = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *func_name = (const char *)(base + names[i]);
        if (ror13_hash(func_name) == target_hash) {
            WORD  ord = ordinals[i];
            DWORD rva = funcs[ord];
            return (PVOID)(base + rva);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------
 * manual_getprocaddr
 *
 * Public entry point. Takes pre-computed ROR13 hashes for the module
 * name (lowercase, e.g. "kernel32.dll") and function name.
 * Returns the function's virtual address or NULL.
 * ------------------------------------------------------------------ */
PVOID manual_getprocaddr(DWORD module_hash, DWORD func_hash) {
    PVOID base = find_module_by_hash(module_hash);
    if (!base)
        return NULL;
    return resolve_export(base, func_hash);
}

/* ------------------------------------------------------------------
 * main — verification harness
 *
 * Computes hashes at runtime (avoids counting errors), resolves
 * WinExec manually, then compares against GetProcAddress.
 * ------------------------------------------------------------------ */
int main(void) {
    /* Compute module hash — lowercase to match ror13_hash_unicode */
    WCHAR k32[] = L"kernel32.dll";
    DWORD k32_hash = ror13_hash_unicode(k32,
                         (USHORT)(wcslen(k32) * sizeof(WCHAR)));

    DWORD winexec_hash = ror13_hash("WinExec");

    printf("kernel32.dll hash  : 0x%08X\n", k32_hash);
    printf("WinExec hash       : 0x%08X\n", winexec_hash);

    PVOID manual = manual_getprocaddr(k32_hash, winexec_hash);
    printf("Manual resolution  : %p\n", manual);

    PVOID real = (PVOID)GetProcAddress(
                     GetModuleHandleA("kernel32.dll"), "WinExec");
    printf("Real GetProcAddr   : %p\n", real);

    printf("%s\n", manual == real ? "MATCH" : "MISMATCH");
    return 0;
}