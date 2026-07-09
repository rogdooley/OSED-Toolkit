#define OSEDTP_HELPER_EXPORTS

#include "osedtp_helper.h"

#include <ctype.h>
#include <string.h>
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}

void * __stdcall helper_get_anchor(void)
{
    return (void *)&helper_get_anchor;
}

uint32_t __stdcall helper_checksum32(const unsigned char *data, size_t len)
{
    uint32_t acc = 0x811C9DC5u;
    size_t i;

    if (!data) {
        return acc;
    }

    for (i = 0; i < len; ++i) {
        acc ^= data[i];
        acc *= 16777619u;
        acc = (acc << 5) | (acc >> 27);
    }

    return acc;
}

int __stdcall helper_copy_bounded(const unsigned char *src, size_t src_len, char *dst, size_t dst_size)
{
    size_t i;

    if (!dst || dst_size == 0U) {
        return -1;
    }

    if (!src && src_len != 0U) {
        return -1;
    }

    if (src_len >= dst_size) {
        return -1;
    }

    for (i = 0; i < src_len; ++i) {
        dst[i] = (char)src[i];
    }
    dst[src_len] = '\0';
    return 0;
}

int __stdcall helper_normalize_name(const char *src, char *dst, size_t dst_size)
{
    size_t i;
    size_t out = 0;

    if (!src || !dst || dst_size == 0U) {
        return -1;
    }

    for (i = 0; src[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)src[i];
        if (out + 1U >= dst_size) {
            return -1;
        }

        if (ch < 0x20U || ch > 0x7EU) {
            dst[out++] = '_';
        } else {
            dst[out++] = (char)tolower(ch);
        }
    }

    dst[out] = '\0';
    return 0;
}

int __stdcall helper_token_accept(uint32_t token)
{
    return token == 0xC0FFEE11u;
}

int __stdcall helper_probe(int value)
{
    volatile int a = value;
    volatile int b = 0x13579BDF;
    return (int)(a ^ b);
}
