/*
 * protocol.h - VulnSvc wire protocol definitions
 *
 * VulnSvc is a deliberately vulnerable 32-bit Windows TCP service used as a
 * training target for stack-overflow / DEP-bypass exploit development.
 *
 * DO NOT run this on a network you do not control. It is intentionally
 * insecure. It exists only to be exploited in a lab.
 *
 * Wire format (all multi-byte integers little-endian):
 *
 *   +----------------+--------+-------------------------------------------+
 *   | field          | bytes  | meaning                                   |
 *   +----------------+--------+-------------------------------------------+
 *   | magic          | 4      | 0x53564C56 ("VLVS" on the wire)           |
 *   | opcode         | 2      | selects a handler (see OP_* below)        |
 *   | flags          | 2      | per-request flags (see FLAG_* below)      |
 *   | body_len       | 4      | number of body bytes that follow header   |
 *   +----------------+--------+-------------------------------------------+
 *   | body           | body_len (opcode-specific payload)              |
 *   +----------------+--------+-------------------------------------------+
 *
 * A single TCP connection may carry many requests back to back.
 */

#ifndef VULNSVC_PROTOCOL_H
#define VULNSVC_PROTOCOL_H

#include <stdint.h>

#define VULNSVC_PORT            9999
#define VULNSVC_MAGIC           0x53564C56u   /* 'V''L''V''S' little-endian  */
#define VULNSVC_MAX_BODY        0x2000        /* 8 KiB cap on a single body  */
#define VULNSVC_HEADER_SIZE     12

/* ------------------------------------------------------------------ */
/* Opcodes. Only a handful reach interesting code; most are noise.     */
/* ------------------------------------------------------------------ */
enum {
    OP_PING        = 0x0001,   /* liveness check, no body                  */
    OP_AUTH        = 0x0002,   /* establish an authenticated session       */
    OP_STATUS      = 0x0010,   /* query a module's status (bounded parse)  */
    OP_CONFIG_GET  = 0x0020,   /* read a config key (bounded)              */
    OP_CONFIG_SET  = 0x0021,   /* write a config key/value  <-- VULNERABLE */
    OP_LOG_UPLOAD  = 0x0030,   /* upload a log blob (length-checked memcpy)*/
    OP_COMPRESS    = 0x0040,   /* round-trip a blob through compression.dll*/
    OP_CONFIG_IMPORT = 0x0022, /* batch config import  <-- VULNERABLE (SEH) */
    OP_STATS       = 0x0050,   /* server counters, no attacker input       */
    OP_QUIT        = 0x00FF    /* close the connection                     */
};

/* ------------------------------------------------------------------ */
/* Per-request flags.                                                  */
/* ------------------------------------------------------------------ */
enum {
    FLAG_NONE       = 0x0000,
    FLAG_COMPRESSED = 0x0001,  /* body is LZ-compressed (compression.dll)  */
    FLAG_URGENT     = 0x0002,  /* unused; reserved                         */
    FLAG_TRACE      = 0x0004   /* verbose logging for this request         */
};

/* Response status codes echoed back to the client. */
enum {
    ST_OK           = 0x0000,
    ST_BAD_REQUEST  = 0x0001,
    ST_NOAUTH       = 0x0002,
    ST_NOT_FOUND    = 0x0003,
    ST_TOO_LARGE    = 0x0004,
    ST_INTERNAL     = 0x0005
};

#pragma pack(push, 1)
typedef struct _PACKET_HEADER {
    uint32_t magic;
    uint16_t opcode;
    uint16_t flags;
    uint32_t body_len;
} PACKET_HEADER;
#pragma pack(pop)

#endif /* VULNSVC_PROTOCOL_H */
