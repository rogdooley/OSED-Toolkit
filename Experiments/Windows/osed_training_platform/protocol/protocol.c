#include "osedtp_protocol.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_u16_le(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_u32_le(const unsigned char *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static void set_reason(char *reason, size_t reason_size, const char *text)
{
    if (!reason || reason_size == 0) {
        return;
    }

    strncpy(reason, text, reason_size - 1U);
    reason[reason_size - 1U] = '\0';
}

const char *osedtp_opcode_name(uint16_t opcode)
{
    switch (opcode) {
    case OSEDTP_OP_HELLO:   return "HELLO";
    case OSEDTP_OP_AUTH:    return "AUTH";
    case OSEDTP_OP_STATUS:  return "STATUS";
    case OSEDTP_OP_CONFIG:  return "CONFIG";
    case OSEDTP_OP_DIAG:    return "DIAG";
    case OSEDTP_OP_ANALYZE: return "ANALYZE";
    default:                return "UNKNOWN";
    }
}

const char *osedtp_record_name(uint16_t record_type)
{
    switch (record_type) {
    case OSEDTP_RECORD_CLIENT:  return "CLIENT";
    case OSEDTP_RECORD_AUTH:    return "AUTH";
    case OSEDTP_RECORD_CONFIG:  return "CONFIG";
    case OSEDTP_RECORD_COMMAND: return "COMMAND";
    case OSEDTP_RECORD_DIAG:    return "DIAG";
    default:                    return "UNKNOWN";
    }
}

int osedtp_copy_text(const unsigned char *src,
                     uint32_t src_len,
                     char *dst,
                     size_t dst_size)
{
    size_t copy_len;

    if (!dst || dst_size == 0) {
        return -1;
    }

    if (!src && src_len != 0) {
        return -1;
    }

    if (src_len >= dst_size) {
        return -1;
    }

    copy_len = (size_t)src_len;
    if (copy_len != 0U) {
        memcpy(dst, src, copy_len);
    }
    dst[copy_len] = '\0';
    return 0;
}

const OSEDTP_RECORD_VIEW *osedtp_find_record(const OSEDTP_PARSED_FRAME *frame, uint16_t record_type)
{
    size_t i;

    if (!frame) {
        return NULL;
    }

    for (i = 0; i < frame->record_count; ++i) {
        if (frame->records[i].header.type == record_type) {
            return &frame->records[i];
        }
    }

    return NULL;
}

int osedtp_parse_frame(const unsigned char *buffer,
                       size_t buffer_len,
                       OSEDTP_PARSED_FRAME *frame,
                       char *reason,
                       size_t reason_size)
{
    size_t cursor;
    size_t i;

    if (!buffer || !frame) {
        set_reason(reason, reason_size, "null input");
        return -1;
    }

    if (buffer_len < sizeof(OSEDTP_FRAME_HEADER)) {
        set_reason(reason, reason_size, "short frame header");
        return -1;
    }

    memset(frame, 0, sizeof(*frame));
    frame->buffer = buffer;
    frame->buffer_len = buffer_len;
    memcpy(&frame->header, buffer, sizeof(OSEDTP_FRAME_HEADER));

    if (frame->header.magic != OSEDTP_MAGIC) {
        set_reason(reason, reason_size, "bad magic");
        return -1;
    }

    if (frame->header.version != OSEDTP_VERSION) {
        set_reason(reason, reason_size, "bad version");
        return -1;
    }

    if (frame->header.total_length < sizeof(OSEDTP_FRAME_HEADER)) {
        set_reason(reason, reason_size, "invalid total length");
        return -1;
    }

    if (frame->header.total_length > buffer_len) {
        set_reason(reason, reason_size, "truncated frame");
        return -1;
    }

    if (frame->header.record_count > OSEDTP_MAX_RECORDS) {
        set_reason(reason, reason_size, "too many records");
        return -1;
    }

    frame->body = buffer + sizeof(OSEDTP_FRAME_HEADER);
    frame->body_len = frame->header.total_length - sizeof(OSEDTP_FRAME_HEADER);

    cursor = 0;
    for (i = 0; i < frame->header.record_count; ++i) {
        const unsigned char *record_base;
        size_t remaining;
        uint32_t record_len;

        remaining = frame->body_len - cursor;
        if (remaining < sizeof(OSEDTP_RECORD_HEADER)) {
            set_reason(reason, reason_size, "short record header");
            return -1;
        }

        record_base = frame->body + cursor;
        frame->records[i].header.type = read_u16_le(record_base);
        frame->records[i].header.flags = read_u16_le(record_base + 2U);
        frame->records[i].header.length = read_u32_le(record_base + 4U);

        record_len = frame->records[i].header.length;
        if (record_len > remaining - sizeof(OSEDTP_RECORD_HEADER)) {
            set_reason(reason, reason_size, "record overrun");
            return -1;
        }

        frame->records[i].body = record_base + sizeof(OSEDTP_RECORD_HEADER);
        cursor += sizeof(OSEDTP_RECORD_HEADER) + record_len;
    }

    if (cursor != frame->body_len) {
        set_reason(reason, reason_size, "trailing bytes");
        return -1;
    }

    frame->record_count = frame->header.record_count;
    set_reason(reason, reason_size, "ok");
    return 0;
}
