#include "mini_proto_vuln.h"

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

static int parse_record(const unsigned char *cursor,
                        size_t remaining,
                        RecordHeader *header,
                        const unsigned char **body)
{
    if (remaining < sizeof(RecordHeader)) {
        return -1;
    }

    header->type = read_u16_le(cursor);
    header->flags = read_u16_le(cursor + 2);
    header->length = read_u32_le(cursor + 4);

    if (header->length > remaining - sizeof(RecordHeader)) {
        return -1;
    }

    *body = cursor + sizeof(RecordHeader);
    return 0;
}

int copy_header(const PacketContext *ctx, PacketHeader *out)
{
    if (ctx->raw_length < sizeof(PacketHeader)) {
        return -1;
    }

    memcpy(out, ctx->raw, sizeof(PacketHeader));
    return 0;
}

int parse_protocol(PacketContext *ctx)
{
    PacketHeader header;

    if (copy_header(ctx, &header) != 0) {
        puts("[protocol] short header");
        return -1;
    }

    ctx->header = header;

    printf("[protocol] magic=0x%08lx version=%u opcode=0x%04x total=%lu records=%lu\n",
           (unsigned long)ctx->header.magic,
           (unsigned)ctx->header.version,
           (unsigned)ctx->header.opcode,
           (unsigned long)ctx->header.total_length,
           (unsigned long)ctx->header.record_count);

    if (ctx->header.magic != MINI_PROTO_MAGIC) {
        puts("[protocol] bad magic");
        return -1;
    }

    if (ctx->header.version != MINI_PROTO_VERSION) {
        puts("[protocol] bad version");
        return -1;
    }

    if (ctx->header.total_length < sizeof(PacketHeader)) {
        puts("[protocol] invalid total length");
        return -1;
    }

    if (ctx->header.total_length > ctx->raw_length) {
        puts("[protocol] packet truncated");
        return -1;
    }

    ctx->body = ctx->raw + sizeof(PacketHeader);
    ctx->body_length = ctx->header.total_length - sizeof(PacketHeader);

    return validate_records(ctx);
}

int validate_records(PacketContext *ctx)
{
    const unsigned char *cursor;
    const unsigned char *end;
    uint32_t index;
    int seen_metadata;
    int seen_command;
    int seen_payload;

    cursor = ctx->body;
    end = ctx->body + ctx->body_length;
    seen_metadata = 0;
    seen_command = 0;
    seen_payload = 0;

    for (index = 0; index < ctx->header.record_count; ++index) {
        RecordHeader header;
        const unsigned char *body;
        size_t remaining;
        char name_buf[64];
        char note_buf[128];

        remaining = (size_t)(end - cursor);
        if (parse_record(cursor, remaining, &header, &body) != 0) {
            puts("[protocol] malformed record");
            return -1;
        }

        printf("[protocol] record %lu type=%s flags=0x%04x len=%lu\n",
               (unsigned long)index,
               record_name(header.type),
               (unsigned)header.flags,
               (unsigned long)header.length);

        cursor = body + header.length;

        switch (header.type) {
        case RECORD_METADATA:
            if (seen_metadata) {
                puts("[protocol] duplicate metadata record");
                return -1;
            }
            ctx->metadata_body = body;
            ctx->metadata_length = header.length;
            if (copy_metadata(body, header.length, note_buf, sizeof(note_buf)) != 0) {
                puts("[protocol] metadata copy rejected");
                return -1;
            }
            if (copy_client_name(body, header.length, name_buf, sizeof(name_buf)) != 0) {
                puts("[protocol] client name copy rejected");
                return -1;
            }
            printf("[protocol] metadata client='%s'\n", name_buf);
            seen_metadata = 1;
            break;

        case RECORD_COMMAND:
            if (seen_command) {
                puts("[protocol] duplicate command record");
                return -1;
            }
            ctx->command_body = body;
            ctx->command_length = header.length;
            if (copy_command_note(body, header.length, note_buf, sizeof(note_buf)) != 0) {
                puts("[protocol] command note copy rejected");
                return -1;
            }
            printf("[protocol] command note='%s'\n", note_buf);
            seen_command = 1;
            break;

        case RECORD_PAYLOAD:
            if (seen_payload) {
                puts("[protocol] duplicate payload record");
                return -1;
            }
            if (header.length < sizeof(uint32_t)) {
                puts("[protocol] payload record too short");
                return -1;
            }
            ctx->payload_copy_length = read_u32_le(body);
            ctx->payload_body = body + sizeof(uint32_t);
            ctx->payload_length = header.length - sizeof(uint32_t);

            if (ctx->payload_copy_length > ctx->payload_length) {
                puts("[protocol] copy length exceeds payload length");
                return -1;
            }

            printf("[protocol] payload copy_len=%lu body_len=%lu\n",
                   (unsigned long)ctx->payload_copy_length,
                   (unsigned long)ctx->payload_length);
            seen_payload = 1;
            break;

        default:
            puts("[protocol] unknown record type");
            return -1;
        }
    }

    if (cursor != end) {
        puts("[protocol] trailing bytes after records");
        return -1;
    }

    if (!seen_metadata || !seen_command) {
        puts("[protocol] missing required metadata or command record");
        return -1;
    }

    if (ctx->header.opcode == OPCODE_ECHO || ctx->header.opcode == OPCODE_COPY_PAYLOAD) {
        if (!seen_payload) {
            puts("[protocol] missing payload record for opcode");
            return -1;
        }
    }

    return 0;
}
