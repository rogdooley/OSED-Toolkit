#define OSEDHELPER_EXPORTS
#include "osedhelper.h"

#include <stdint.h>
#include <stdio.h>

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

OSEDHELPER_API void __stdcall helper_aslr_proof(void) {
    puts("[success] ASLR-derived control flow reached osedhelper!helper_aslr_proof.");
    fflush(stdout);
    ExitProcess(0);
}

/*
 * Lab note:
 * - osedgadgets.c provides the deterministic instruction sequences.
 * - No embedded payload logic is provided here.
 */
