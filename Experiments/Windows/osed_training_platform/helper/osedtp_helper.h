#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef OSEDTP_HELPER_EXPORTS
#define OSEDTP_HELPER_API __declspec(dllexport)
#else
#define OSEDTP_HELPER_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

OSEDTP_HELPER_API void * __stdcall helper_get_anchor(void);
OSEDTP_HELPER_API uint32_t __stdcall helper_checksum32(const unsigned char *data, size_t len);
OSEDTP_HELPER_API int __stdcall helper_normalize_name(const char *src, char *dst, size_t dst_size);
OSEDTP_HELPER_API int __stdcall helper_copy_bounded(const unsigned char *src, size_t src_len, char *dst, size_t dst_size);
OSEDTP_HELPER_API int __stdcall helper_token_accept(uint32_t token);
OSEDTP_HELPER_API int __stdcall helper_probe(int value);

#ifdef __cplusplus
}
#endif
