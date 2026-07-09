/*
 * crypto.c -> crypto.dll  (triage noise)
 *
 * A toy "crypto" module: XOR keystream, rotate, a weak hash. It is built
 * WITHOUT ASLR at a fixed base, so a hurried student might consider it as a
 * gadget source. Reject it for a more subtle reason:
 *
 *   - It is small and compiled without heavy optimization, so gadget density
 *     is poor.
 *   - It imports nothing useful (no VirtualAlloc / VirtualProtect), so it
 *     offers no IAT slot for API resolution.
 *
 * It is not wrong because of its base; it is wrong because it does not carry
 * the primitives you need. Part of module selection is asking "does this
 * module even import the API I intend to call?"
 *
 * Build target: 32-bit, /Od, /DYNAMICBASE:NO, base 0x63000000.
 */

#include <windows.h>

__declspec(dllexport) void CryptoInit(void);

__declspec(dllexport) void CryptoXor(unsigned char *buf, unsigned long len, unsigned char key)
{
    unsigned long i;
    for (i = 0; i < len; i++)
        buf[i] ^= key;
}

__declspec(dllexport) unsigned long CryptoRotl(unsigned long v, int n)
{
    return (v << n) | (v >> (32 - n));
}

__declspec(dllexport) unsigned long CryptoHash(const unsigned char *data, unsigned long len)
{
    unsigned long h = 0x811C9DC5UL;    /* FNV-ish */
    unsigned long i;
    for (i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193UL;
    }
    return h;
}

void CryptoInit(void)
{
    /* touch the routines so they are not stripped */
    unsigned char b[4] = { 'a', 'b', 'c', 'd' };
    CryptoXor(b, 4, 0x5a);
    (void)CryptoHash(b, 4);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        CryptoInit();
    return TRUE;
}
