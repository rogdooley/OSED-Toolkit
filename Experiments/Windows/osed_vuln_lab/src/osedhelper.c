#define OSEDHELPER_EXPORTS
#include "osedhelper.h"

#include <stdint.h>

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

/*
 * Lab note:
 * - Build variants intentionally keep ordinary code sequences for gadget hunting.
 * - No embedded payload logic is provided here.
 */
