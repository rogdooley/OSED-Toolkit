#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef GADGETLIB_EXPORTS
#define GADGETLIB_API __declspec(dllexport)
#else
#define GADGETLIB_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

GADGETLIB_API void * __stdcall gadgetlib_get_anchor(void);
GADGETLIB_API uint32_t __stdcall gadgetlib_score_buffer(const unsigned char *data, size_t len);
GADGETLIB_API int __stdcall gadgetlib_fold_flags(uint16_t flags);
GADGETLIB_API int __stdcall gadgetlib_probe_layout(uint32_t opcode, uint32_t total_length);

#ifdef __cplusplus
}
#endif
