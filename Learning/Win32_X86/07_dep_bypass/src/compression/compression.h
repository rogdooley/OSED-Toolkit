/*
 * compression.h - public surface of compression.dll
 *
 * This DLL is the intended ROP gadget source. It is NOT special-cased for the
 * exploit: it is ordinary optimized library code (checksums, an LZ77-style
 * codec, packet helpers, config, logging). The gadgets exist because /O2 emits
 * them, not because we planted them.
 *
 * Build target: 32-bit, /O2, /DYNAMICBASE:NO (no ASLR), base 0x61500000.
 */
#ifndef COMPRESSION_H
#define COMPRESSION_H

#ifdef COMPRESSION_EXPORTS
#  define CMP_API __declspec(dllexport)
#else
#  define CMP_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

CMP_API unsigned long ComputeChecksum(const unsigned char *data, unsigned long len);
CMP_API unsigned long Crc32(const unsigned char *data, unsigned long len);

CMP_API int  Compress  (const unsigned char *in, unsigned long in_len,
                        unsigned char *out, unsigned long *out_len);
CMP_API int  Decompress(const unsigned char *in, unsigned long in_len,
                        unsigned char *out, unsigned long *out_len);

CMP_API int  PacketParse    (const unsigned char *buf, unsigned long len, void *out_hdr);
CMP_API int  PacketSerialize(const void *hdr, unsigned char *out, unsigned long *out_len);

CMP_API int  ConfigRead (const char *text, const char *key, char *out, unsigned long cap);
CMP_API int  ConfigWrite(char *text, unsigned long cap, const char *key, const char *value);

CMP_API void StartWorker(void);
CMP_API void StopWorker(void);

#ifdef __cplusplus
}
#endif

#endif /* COMPRESSION_H */
