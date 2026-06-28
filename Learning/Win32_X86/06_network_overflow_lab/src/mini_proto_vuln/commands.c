#include "mini_proto_vuln.h"

#include <stdio.h>
#include <string.h>

static NOINLINE int handle_ping(SOCKET client, const PacketContext *ctx)
{
    const char *resp = "PONG\r\n";
    (void)ctx;

    printf("[commands] ping\n");
    send(client, resp, (int)strlen(resp), 0);
    return 0;
}

static NOINLINE int handle_echo(SOCKET client, const PacketContext *ctx)
{
    PacketHeader header_copy;
    char metadata_copy[128];
    char client_name[64];
    char command_note[128];
    char payload_copy[256];

    if (copy_header(ctx, &header_copy) != 0) {
        return -1;
    }

    if (copy_metadata(ctx->metadata_body, ctx->metadata_length, metadata_copy, sizeof(metadata_copy)) != 0) {
        return -1;
    }

    if (copy_client_name(ctx->metadata_body, ctx->metadata_length, client_name, sizeof(client_name)) != 0) {
        return -1;
    }

    if (copy_command_note(ctx->command_body, ctx->command_length, command_note, sizeof(command_note)) != 0) {
        return -1;
    }

    if (copy_echo_payload(ctx->payload_body,
                          ctx->payload_length,
                          ctx->payload_copy_length,
                          payload_copy,
                          sizeof(payload_copy)) != 0) {
        puts("[commands] echo payload rejected");
        return -1;
    }

    printf("[commands] echo opcode=0x%04x client='%s' metadata='%s' command='%s' payload_len=%lu\n",
           (unsigned)header_copy.opcode,
           client_name,
           metadata_copy,
           command_note,
           (unsigned long)ctx->payload_copy_length);
    send(client, payload_copy, (int)ctx->payload_copy_length, 0);
    send(client, "\r\n", 2, 0);
    return 0;
}

static NOINLINE int process_client_message(SOCKET client, const PacketContext *ctx)
{
    PacketHeader header_copy;
    char metadata_copy[128];
    char client_name[64];
    char command_note[128];

    (void)client;

    if (copy_header(ctx, &header_copy) != 0) {
        return -1;
    }

    if (copy_metadata(ctx->metadata_body, ctx->metadata_length, metadata_copy, sizeof(metadata_copy)) != 0) {
        return -1;
    }

    if (copy_client_name(ctx->metadata_body, ctx->metadata_length, client_name, sizeof(client_name)) != 0) {
        return -1;
    }

    if (copy_command_note(ctx->command_body, ctx->command_length, command_note, sizeof(command_note)) != 0) {
        return -1;
    }

    printf("[commands] process_client_message opcode=0x%04x client='%s' metadata='%s' command='%s'\n",
           (unsigned)header_copy.opcode,
           client_name,
           metadata_copy,
           command_note);

    copy_record_payload(ctx->payload_body, ctx->payload_copy_length);
    send(client, "OK\r\n", 4, 0);
    return 0;
}

int copy_metadata(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size)
{
    size_t copy_len;

    if (dst_size == 0) {
        return -1;
    }

    if (src_len >= dst_size) {
        return -1;
    }

    copy_len = (size_t)src_len;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return 0;
}

int copy_client_name(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size)
{
    size_t copy_len;

    if (dst_size == 0) {
        return -1;
    }

    if (src_len >= dst_size) {
        return -1;
    }

    copy_len = (size_t)src_len;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return 0;
}

int copy_command_note(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size)
{
    size_t copy_len;

    if (dst_size == 0) {
        return -1;
    }

    if (src_len >= dst_size) {
        return -1;
    }

    copy_len = (size_t)src_len;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return 0;
}

int copy_echo_payload(const unsigned char *src, uint32_t src_len, uint32_t copy_len, char *dst, size_t dst_size)
{
    if (dst_size == 0) {
        return -1;
    }

    if (copy_len > src_len) {
        return -1;
    }

    if ((size_t)copy_len >= dst_size) {
        return -1;
    }

    memcpy(dst, src, (size_t)copy_len);
    dst[copy_len] = '\0';
    return 0;
}

void copy_record_payload(const unsigned char *src, uint32_t copy_len)
{
    unsigned char local_buffer[128];

    /* WinDbg checkpoint:
       compare &local_buffer to the saved return address after bp mini_proto_vuln!copy_record_payload. */
    printf("[commands] copy_record_payload local_buffer=%p copy_len=%lu payload=%p\n",
           (void *)local_buffer,
           (unsigned long)copy_len,
           (const void *)src);

    memcpy(local_buffer, src, (size_t)copy_len);

    if (copy_len > 0 && local_buffer[0] == 0x90) {
        puts("[commands] unlikely branch");
    }
}

int dispatch_command(SOCKET client, const PacketContext *ctx)
{
    printf("[commands] dispatch opcode=%s\n", opcode_name(ctx->header.opcode));

    switch (ctx->header.opcode) {
    case OPCODE_PING:
        return handle_ping(client, ctx);

    case OPCODE_ECHO:
        return handle_echo(client, ctx);

    case OPCODE_COPY_PAYLOAD:
        return process_client_message(client, ctx);

    default:
        puts("[commands] unsupported opcode");
        return -1;
    }
}
