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

OSEDHELPER_API int __stdcall helper_add(int a, int b);
OSEDHELPER_API int __stdcall helper_xor_fold(const unsigned char *data, int len);
OSEDHELPER_API void * __stdcall helper_get_anchor(void);
OSEDHELPER_API int __stdcall helper_probe(int value);

#ifdef __cplusplus
}
#endif
