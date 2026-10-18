#define OSEDHELPER_EXPORTS
#include "osedhelper.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct EVENT_RUNTIME_INFO {
    DWORD abi_version;
    DWORD capabilities;
} EVENT_RUNTIME_INFO;

static const EVENT_RUNTIME_INFO event_runtime_info = {7u, 1u};

#if defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
#define OSED_STAGE_BYTES 8192u

static unsigned char helper_rop_stage[OSED_STAGE_BYTES];
static FARPROC helper_cached_virtualprotect;
static volatile DWORD helper_proof_status;

OSEDHELPER_API int __stdcall event_runtime_initialize(void) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32 == NULL) {
        return 0;
    }
    helper_cached_virtualprotect = GetProcAddress(kernel32, "VirtualProtect");
    return helper_cached_virtualprotect != NULL;
}

OSEDHELPER_API int __stdcall event_runtime_submit(const unsigned char *data, DWORD length) {
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

OSEDHELPER_API int __stdcall event_counter_add(int current, int increment) {
    return current + increment;
}

OSEDHELPER_API int __stdcall event_record_checksum(const unsigned char *data, int len) {
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

OSEDHELPER_API const void * __stdcall event_runtime_get_info(void) {
    return &event_runtime_info;
}

OSEDHELPER_API int __stdcall event_runtime_check_compatibility(int version) {
    return version == 7;
}

#if defined(OSED_PROFILE_ASLR_DEP)
OSEDHELPER_API void __stdcall event_runtime_report_status(void) {
    puts("[event] runtime status report completed.");
    fflush(stdout);
    ExitProcess(0);
}
#endif

/*
 * Lab note:
 * - Legacy profiles may add deterministic instruction sequences at link time.
 * - No embedded payload logic is provided here.
 */
