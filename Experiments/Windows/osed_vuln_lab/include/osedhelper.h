#pragma once

#include <Windows.h>

#ifdef OSEDHELPER_EXPORTS
#define OSEDHELPER_API __declspec(dllexport)
#else
#define OSEDHELPER_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

OSEDHELPER_API int __stdcall event_counter_add(int current, int increment);
OSEDHELPER_API int __stdcall event_record_checksum(const unsigned char *data, int len);
OSEDHELPER_API const void * __stdcall event_runtime_get_info(void);
OSEDHELPER_API int __stdcall event_runtime_check_compatibility(int version);
OSEDHELPER_API void __stdcall event_runtime_report_status(void);
OSEDHELPER_API int __stdcall event_runtime_initialize(void);
OSEDHELPER_API int __stdcall event_runtime_submit(const unsigned char *data, DWORD length);

#ifdef __cplusplus
}
#endif
