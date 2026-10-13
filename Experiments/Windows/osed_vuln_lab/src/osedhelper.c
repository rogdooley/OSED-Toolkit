#define OSEDHELPER_EXPORTS
#include "osedhelper.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
#define OSED_STAGE_BYTES 8192u

static unsigned char helper_rop_stage[OSED_STAGE_BYTES];
static FARPROC helper_cached_virtualprotect;
static volatile DWORD helper_proof_status;

OSEDHELPER_API int __stdcall helper_prepare_rop_runtime(void) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32 == NULL) {
        return 0;
    }
    helper_cached_virtualprotect = GetProcAddress(kernel32, "VirtualProtect");
    return helper_cached_virtualprotect != NULL;
}

OSEDHELPER_API int __stdcall helper_stage_record(const unsigned char *data, DWORD length) {
    if (length > OSED_STAGE_BYTES || (data == NULL && length != 0)) {
        return 0;
    }
    memset(helper_rop_stage, 0, sizeof(helper_rop_stage));
    helper_proof_status = 0;
    if (length != 0) {
        memcpy(helper_rop_stage, data, length);
    }
    return 1;
}
#endif

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}

OSEDHELPER_API int __stdcall helper_add(int a, int b) {
    return a + b;
}

OSEDHELPER_API int __stdcall helper_xor_fold(const unsigned char *data, int len) {
    int acc = 0;
    if (!data || len <= 0) {
        return 0;
    }
    for (int i = 0; i < len; ++i) {
        acc ^= data[i];
        acc = (acc << 1) | ((acc >> 31) & 1);
    }
    return acc;
}

OSEDHELPER_API void * __stdcall helper_get_anchor(void) {
    return (void *)&helper_get_anchor;
}

OSEDHELPER_API int __stdcall helper_probe(int value) {
    volatile int x = value;
    volatile int y = 0x12345678;
    return (int)(x ^ y);
}

#if defined(OSED_PROFILE_ASLR_DEP)
OSEDHELPER_API void __stdcall helper_aslr_proof(void) {
    puts("[success] ASLR-derived control flow reached osedhelper!helper_aslr_proof.");
    fflush(stdout);
    ExitProcess(0);
}
#endif

/*
 * Lab note:
 * - osedgadgets.c provides the deterministic instruction sequences.
 * - No embedded payload logic is provided here.
 */
