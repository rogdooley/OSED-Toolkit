#define GADGETLIB_EXPORTS

#include "gadgetlib.h"

#include <windows.h>

static uint32_t rotate_left32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32U - count));
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}

void * __stdcall gadgetlib_get_anchor(void)
{
    return (void *)&gadgetlib_get_anchor;
}

uint32_t __stdcall gadgetlib_score_buffer(const unsigned char *data, size_t len)
{
    uint32_t score = 0xA5A5A5A5u;
    size_t i;

    if (!data) {
        return score;
    }

    for (i = 0; i < len; ++i) {
        score ^= (uint32_t)data[i] + (uint32_t)(i * 17U);
        score = rotate_left32(score, 3U);
    }

    return score;
}

int __stdcall gadgetlib_fold_flags(uint16_t flags)
{
    int result = 0;

    if (flags & 0x0001u) {
        result ^= 1;
    }
    if (flags & 0x0002u) {
        result ^= 2;
    }
    if (flags & 0x0004u) {
        result ^= 4;
    }
    if (flags & 0x8000u) {
        result ^= 8;
    }

    return result;
}

int __stdcall gadgetlib_probe_layout(uint32_t opcode, uint32_t total_length)
{
    uint32_t mixed = opcode ^ (total_length << 1);
    mixed = rotate_left32(mixed, 7U);
    return (int)(mixed & 0x7FFFFFFFu);
}
