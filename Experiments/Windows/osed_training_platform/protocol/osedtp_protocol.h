#pragma once

#include <stddef.h>
#include <stdint.h>

#define OSEDTP_MAGIC 0x4445534Fu /* "OSED" */
#define OSEDTP_VERSION 1u
#define OSEDTP_MAX_RECORDS 8u
#define OSEDTP_MAX_FRAME 4096u

enum OSEDTP_OPCODE {
    OSEDTP_OP_HELLO   = 0x1101,
    OSEDTP_OP_AUTH    = 0x1102,
    OSEDTP_OP_STATUS  = 0x1103,
    OSEDTP_OP_CONFIG  = 0x1104,
    OSEDTP_OP_DIAG    = 0x1105,
    OSEDTP_OP_ANALYZE = 0x11F0
};

enum OSEDTP_RECORD_TYPE {
    OSEDTP_RECORD_CLIENT  = 1,
    OSEDTP_RECORD_AUTH    = 2,
    OSEDTP_RECORD_CONFIG  = 3,
    OSEDTP_RECORD_COMMAND = 4,
    OSEDTP_RECORD_DIAG    = 5
};

#pragma pack(push, 1)
typedef struct OSEDTP_FRAME_HEADER {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint16_t opcode;
    uint16_t session_id;
    uint32_t total_length;
    uint16_t record_count;
    uint16_t reserved;
} OSEDTP_FRAME_HEADER;

typedef struct OSEDTP_RECORD_HEADER {
    uint16_t type;
    uint16_t flags;
    uint32_t length;
} OSEDTP_RECORD_HEADER;
#pragma pack(pop)

typedef struct OSEDTP_RECORD_VIEW {
    OSEDTP_RECORD_HEADER header;
    const unsigned char *body;
} OSEDTP_RECORD_VIEW;

typedef struct OSEDTP_PARSED_FRAME {
    OSEDTP_FRAME_HEADER header;
    const unsigned char *buffer;
    size_t buffer_len;
    const unsigned char *body;
    size_t body_len;
    OSEDTP_RECORD_VIEW records[OSEDTP_MAX_RECORDS];
    size_t record_count;
} OSEDTP_PARSED_FRAME;

const char *osedtp_opcode_name(uint16_t opcode);
const char *osedtp_record_name(uint16_t record_type);
int osedtp_parse_frame(const unsigned char *buffer,
                       size_t buffer_len,
                       OSEDTP_PARSED_FRAME *frame,
                       char *reason,
                       size_t reason_size);
int osedtp_copy_text(const unsigned char *src,
                     uint32_t src_len,
                     char *dst,
                     size_t dst_size);
const OSEDTP_RECORD_VIEW *osedtp_find_record(const OSEDTP_PARSED_FRAME *frame, uint16_t record_type);
