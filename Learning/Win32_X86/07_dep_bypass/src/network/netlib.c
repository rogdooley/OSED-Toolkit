/*
 * netlib.c -> network.dll  (triage noise)
 *
 * URL/host string helpers and a base16 codec. Built WITHOUT ASLR at a fixed
 * base with /O2, so it genuinely has decent gadgets AND a predictable base.
 * On the surface it looks like a viable gadget source.
 *
 * The catch you must discover for yourself: check its import table. network.dll
 * imports ws2_32 (recv/send/htons) and a bit of kernel32, but NOT VirtualAlloc
 * or VirtualProtect. You could still use it purely for gadgets and borrow the
 * IAT slot from a DIFFERENT module - but mixing modules for gadgets vs. IAT is
 * extra complexity. compression.dll gives you both in one place.
 *
 * The lesson: "no ASLR + good gadgets" is necessary but not sufficient. The
 * ideal gadget source ALSO imports the API you want to resolve.
 *
 * Build target: 32-bit, /O2, /DYNAMICBASE:NO, base 0x64000000.
 */

#include <winsock2.h>
#include <windows.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

__declspec(dllexport) void NetlibInit(void);

__declspec(dllexport) int NetHexEncode(const unsigned char *in, unsigned long len,
                                       char *out, unsigned long cap)
{
    static const char *hex = "0123456789abcdef";
    unsigned long i, o = 0;
    for (i = 0; i < len && o + 2 < cap; i++) {
        out[o++] = hex[(in[i] >> 4) & 0xF];
        out[o++] = hex[in[i] & 0xF];
    }
    out[o] = '\0';
    return (int)o;
}

__declspec(dllexport) int NetSplitHostPort(const char *hostport, char *host,
                                           unsigned long host_cap, unsigned short *port)
{
    const char *colon = strchr(hostport, ':');
    unsigned long n;
    if (!colon)
        return -1;
    n = (unsigned long)(colon - hostport);
    if (n >= host_cap)
        n = host_cap - 1;
    memcpy(host, hostport, n);
    host[n] = '\0';
    *port = (unsigned short)atoi(colon + 1);
    return 0;
}

__declspec(dllexport) unsigned short NetHtons(unsigned short v)
{
    return htons(v);
}

void NetlibInit(void)
{
    char h[64];
    unsigned short p = 0;
    NetSplitHostPort("127.0.0.1:9999", h, sizeof(h), &p);
    (void)NetHtons(p);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        NetlibInit();
    return TRUE;
}
