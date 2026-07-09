/*
 * helper.c  ->  helper.dll   *** THE TRAP ***
 *
 * This DLL is built WITH ASLR ( /DYNAMICBASE ). It is deliberately full of
 * clean, beautiful gadgets - the kind you wish every module had:
 *
 *     pop eax ; ret
 *     pop ecx ; ret
 *     mov [esi], eax ; ret
 *     xchg eax, ebp ; ret
 *     add eax, ecx ; ret
 *
 * A student hunting gadgets will find helper.dll first and be delighted. Then
 * they reboot (or just relaunch the service) and every address has moved,
 * because helper.dll is randomized. The chain built against it breaks.
 *
 * The lesson: gadget QUALITY is worthless if the module's base is not
 * predictable. Reject helper.dll not because its gadgets are bad, but because
 * you cannot rely on its addresses. compression.dll, with uglier gadgets but a
 * fixed non-ASLR base, is the correct choice.
 *
 * Build target: 32-bit, /O2, /DYNAMICBASE (ASLR ON), /NXCOMPAT.
 */

#include <windows.h>

__declspec(dllexport) void HelperInit(void);

/* A few functions written so /O2 emits especially clean gadget tails. These
 * are real (if pointless) routines - the optimizer does the rest. */

__declspec(dllexport) unsigned int helper_accumulate(const unsigned int *v, unsigned int n)
{
    unsigned int i, acc = 0;
    for (i = 0; i < n; i++)
        acc += v[i];                 /* add eax, ecx ; ... patterns        */
    return acc;
}

__declspec(dllexport) void helper_store(unsigned int *dst, unsigned int val)
{
    *dst = val;                      /* mov [reg], eax ; ret               */
}

__declspec(dllexport) unsigned int helper_swap(unsigned int a, unsigned int b)
{
    unsigned int t = a; a = b; b = t;   /* xchg-ish shuffles              */
    return a ^ b;
}

__declspec(dllexport) int helper_scan(const char *s)
{
    int n = 0;
    while (*s++) n++;                 /* inc/loop/ret                       */
    return n;
}

void HelperInit(void)
{
    /* nothing meaningful; existence is the point */
    volatile unsigned int x[4] = { 1, 2, 3, 4 };
    (void)helper_accumulate((const unsigned int *)x, 4);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        HelperInit();
    return TRUE;
}
