/*
 * compression.c - a plausible compression / packet-utility library.
 *
 * Everything in here is real, working code. The reason it matters to the
 * exploit is incidental:
 *
 *   1. It is compiled /O2, so MSVC emits dense, gadget-rich instruction
 *      sequences (byte loops -> mov/inc/add/ret, buffer stores -> mov [reg],
 *      reg/ret, arithmetic -> add/sub/neg/ret, register shuffles -> push/pop).
 *   2. It is linked /DYNAMICBASE:NO at a fixed base with no NUL in the high
 *      byte, so its gadget addresses are stable and bad-char-free.
 *   3. It legitimately calls VirtualAlloc and VirtualProtect during worker
 *      setup, so BOTH appear in its Import Address Table - giving the exploit a
 *      fixed IAT slot to dereference for either API.
 *
 * None of that is a trick. It is what a normal optimized Win32 DLL looks like.
 */

#define COMPRESSION_EXPORTS
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "compression.h"

/* ==================================================================== */
/* CRC32 (IEEE) - classic table-driven byte loop.                        */
/* Optimized, this loop is a reliable source of:                         */
/*     movzx eax, byte ptr [reg] ; ... ; ret        (load-from-pointer)  */
/*     xor / shr / and eax                          (arithmetic)         */
/* ==================================================================== */
static unsigned long g_crc_table[256];
static int           g_crc_ready = 0;

static void crc32_init(void)
{
    unsigned long c;
    int n, k;
    if (g_crc_ready)
        return;
    for (n = 0; n < 256; n++) {
        c = (unsigned long)n;
        for (k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        g_crc_table[n] = c;
    }
    g_crc_ready = 1;
}

CMP_API unsigned long Crc32(const unsigned char *data, unsigned long len)
{
    unsigned long crc = 0xFFFFFFFFUL;
    unsigned long i;
    if (!g_crc_ready)
        crc32_init();
    for (i = 0; i < len; i++)
        crc = g_crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFUL;
}

/* ==================================================================== */
/* Adler-ish rolling checksum - another dense accumulate loop.           */
/*     mov eax,[esi] ; inc esi ; add ecx,eax ; ...                       */
/* ==================================================================== */
CMP_API unsigned long ComputeChecksum(const unsigned char *data, unsigned long len)
{
    unsigned long a = 1, b = 0;
    unsigned long i;
    for (i = 0; i < len; i++) {
        a = (a + data[i]) % 65521UL;
        b = (b + a) % 65521UL;
    }
    return (b << 16) | a;
}

/* ==================================================================== */
/* Minimal LZ77-style codec.                                             */
/* Format: a stream of tags. High bit of tag byte = literal run, else a  */
/* (distance,length) back-reference. Not efficient - just realistic.     */
/*                                                                       */
/* The copy loops here are prime gadget territory:                       */
/*     mov al,[esi] ; mov [edi],al ; inc esi ; inc edi ; ...             */
/*     the tail alignment code emits pop/pop/ret and add reg,imm/ret.    */
/* ==================================================================== */
#define LZ_WINDOW   4096
#define LZ_MINMATCH 3
#define LZ_MAXMATCH 18

static unsigned long lz_find_match(const unsigned char *buf, unsigned long pos,
                                   unsigned long len, unsigned long *dist_out)
{
    unsigned long best_len = 0, best_dist = 0;
    unsigned long start = (pos > LZ_WINDOW) ? pos - LZ_WINDOW : 0;
    unsigned long j;

    for (j = start; j < pos; j++) {
        unsigned long k = 0;
        while (k < LZ_MAXMATCH && pos + k < len && buf[j + k] == buf[pos + k])
            k++;
        if (k > best_len) {
            best_len  = k;
            best_dist = pos - j;
        }
    }
    *dist_out = best_dist;
    return best_len;
}

CMP_API int Compress(const unsigned char *in, unsigned long in_len,
                     unsigned char *out, unsigned long *out_len)
{
    unsigned long pos = 0, op = 0;
    unsigned long cap = *out_len;

    if (!in || !out || !out_len)
        return -1;

    while (pos < in_len) {
        unsigned long dist = 0;
        unsigned long mlen = lz_find_match(in, pos, in_len, &dist);

        if (mlen >= LZ_MINMATCH) {
            if (op + 3 > cap)
                return -1;
            out[op++] = (unsigned char)(0x00 | ((mlen - LZ_MINMATCH) & 0x0F));
            out[op++] = (unsigned char)(dist & 0xFF);
            out[op++] = (unsigned char)((dist >> 8) & 0x0F);
            pos += mlen;
        } else {
            if (op + 2 > cap)
                return -1;
            out[op++] = (unsigned char)(0x80);           /* literal tag */
            out[op++] = in[pos++];
        }
    }
    *out_len = op;
    return 0;
}

CMP_API int Decompress(const unsigned char *in, unsigned long in_len,
                       unsigned char *out, unsigned long *out_len)
{
    unsigned long ip = 0, op = 0;
    unsigned long cap = *out_len;

    if (!in || !out || !out_len)
        return -1;

    while (ip < in_len) {
        unsigned char tag = in[ip++];
        if (tag & 0x80) {
            if (ip >= in_len || op >= cap)
                return -1;
            out[op++] = in[ip++];                        /* literal */
        } else {
            unsigned long mlen, dist, i;
            if (ip + 2 > in_len)
                return -1;
            mlen = (unsigned long)(tag & 0x0F) + LZ_MINMATCH;
            dist = (unsigned long)in[ip] | ((unsigned long)(in[ip + 1] & 0x0F) << 8);
            ip += 2;
            if (dist == 0 || dist > op)
                return -1;
            for (i = 0; i < mlen; i++) {
                if (op >= cap)
                    return -1;
                out[op] = out[op - dist];
                op++;
            }
        }
    }
    *out_len = op;
    return 0;
}

/* ==================================================================== */
/* Packet helpers - byte-swapping and field extraction. Endian shuffles  */
/* optimize into bswap / rol / shl+or, and the struct stores into        */
/*     mov [reg+imm], eax ; ret     - useful memory-write gadgets.       */
/* ==================================================================== */
#pragma pack(push, 1)
typedef struct _CmpHeader {
    unsigned long  magic;
    unsigned short version;
    unsigned short type;
    unsigned long  length;
    unsigned long  checksum;
} CmpHeader;
#pragma pack(pop)

CMP_API int PacketParse(const unsigned char *buf, unsigned long len, void *out_hdr)
{
    CmpHeader *h = (CmpHeader *)out_hdr;
    if (len < sizeof(CmpHeader) || !h)
        return -1;
    memcpy(h, buf, sizeof(CmpHeader));
    if (h->checksum != Crc32(buf + sizeof(CmpHeader),
                             (len > sizeof(CmpHeader)) ? len - sizeof(CmpHeader) : 0))
        return -2;
    return 0;
}

CMP_API int PacketSerialize(const void *hdr, unsigned char *out, unsigned long *out_len)
{
    if (*out_len < sizeof(CmpHeader))
        return -1;
    memcpy(out, hdr, sizeof(CmpHeader));
    *out_len = sizeof(CmpHeader);
    return 0;
}

/* ==================================================================== */
/* A tiny INI-ish config reader/writer over an in-memory text buffer.    */
/* String scanning loops give more load/compare/branch gadgets and the   */
/* occasional  xchg / lea / pop ebp ; ret  in the epilogues.             */
/* ==================================================================== */
CMP_API int ConfigRead(const char *text, const char *key, char *out, unsigned long cap)
{
    const char *p = text;
    size_t klen = strlen(key);

    while (p && *p) {
        const char *eol = strchr(p, '\n');
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            unsigned long n = 0;
            while (v[n] && v[n] != '\n' && n < cap - 1) {
                out[n] = v[n];
                n++;
            }
            out[n] = '\0';
            return 0;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return -1;
}

CMP_API int ConfigWrite(char *text, unsigned long cap, const char *key, const char *value)
{
    size_t cur = strlen(text);
    int written = _snprintf(text + cur, cap - cur - 1, "%s=%s\n", key, value);
    if (written < 0)
        return -1;
    return 0;
}

/* ==================================================================== */
/* Worker/arena setup. This is the LEGITIMATE reason VirtualAlloc and    */
/* VirtualProtect are imported: the DLL allocates a scratch arena and     */
/* marks a guard page. An exploit later borrows these IAT entries.        */
/* ==================================================================== */
static void         *g_arena     = NULL;
static unsigned long g_arena_size = 0;
static HANDLE        g_worker    = NULL;
static volatile LONG g_worker_run = 0;

static DWORD WINAPI worker_main(LPVOID arg)
{
    (void)arg;
    while (InterlockedCompareExchange(&g_worker_run, 1, 1) == 1) {
        /* touch the arena so the pages stay resident; do nothing useful */
        if (g_arena && g_arena_size >= 4)
            *((volatile unsigned long *)g_arena) += 1;
        Sleep(50);
    }
    return 0;
}

CMP_API void StartWorker(void)
{
    DWORD old = 0;

    crc32_init();

    /* Reserve+commit a scratch arena. -> imports VirtualAlloc. */
    g_arena_size = 0x4000;
    g_arena = VirtualAlloc(NULL, g_arena_size, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
    if (!g_arena)
        return;

    /* Mark the first page read-only as a cheap canary. -> imports
     * VirtualProtect. Then restore it so the worker can write. */
    VirtualProtect(g_arena, 0x1000, PAGE_READONLY, &old);
    VirtualProtect(g_arena, 0x1000, PAGE_READWRITE, &old);

    InterlockedExchange(&g_worker_run, 1);
    g_worker = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
}

CMP_API void StopWorker(void)
{
    InterlockedExchange(&g_worker_run, 0);
    if (g_worker) {
        WaitForSingleObject(g_worker, 1000);
        CloseHandle(g_worker);
        g_worker = NULL;
    }
    if (g_arena) {
        VirtualFree(g_arena, 0, MEM_RELEASE);
        g_arena = NULL;
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        crc32_init();
        StartWorker();          /* ensures VA/VP imports are exercised */
        break;
    case DLL_PROCESS_DETACH:
        StopWorker();
        break;
    }
    return TRUE;
}
