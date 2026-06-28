#ifndef MINI_PROTO_VULN_H
#define MINI_PROTO_VULN_H

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdint.h>
#include <stddef.h>

#include <winsock2.h>

#define MINI_PROTO_BIND_IP "127.0.0.1"
#define MINI_PROTO_BIND_PORT 11460
#define MINI_PROTO_RECEIVE_MAX 4096U

#define MINI_PROTO_MAGIC 0x4445534FUL /* "OSED" little-endian */
#define MINI_PROTO_VERSION 1U

enum {
    OPCODE_PING = 0x1001,
    OPCODE_ECHO = 0x1002,
    OPCODE_COPY_PAYLOAD = 0x1337
};

enum {
    RECORD_METADATA = 1,
    RECORD_COMMAND = 2,
    RECORD_PAYLOAD = 3
};

typedef struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t opcode;
    uint32_t total_length;
    uint32_t record_count;
} PacketHeader;

typedef struct RecordHeader {
    uint16_t type;
    uint16_t flags;
    uint32_t length;
} RecordHeader;

typedef struct PacketContext {
    unsigned char raw[MINI_PROTO_RECEIVE_MAX];
    size_t raw_length;

    PacketHeader header;
    const unsigned char *body;
    size_t body_length;

    const unsigned char *metadata_body;
    uint32_t metadata_length;
    const unsigned char *command_body;
    uint32_t command_length;
    const unsigned char *payload_body;
    uint32_t payload_length;
    uint32_t payload_copy_length;
} PacketContext;

const char *opcode_name(uint16_t opcode);
const char *record_name(uint16_t type);
void hexdump(const unsigned char *data, size_t length, size_t limit);

int start_server(void);
int receive_packet(SOCKET client, PacketContext *ctx);
int parse_protocol(PacketContext *ctx);
int validate_records(PacketContext *ctx);
int dispatch_command(SOCKET client, const PacketContext *ctx);

int copy_header(const PacketContext *ctx, PacketHeader *out);
int copy_metadata(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size);
int copy_client_name(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size);
int copy_command_note(const unsigned char *src, uint32_t src_len, char *dst, size_t dst_size);
int copy_echo_payload(const unsigned char *src, uint32_t src_len, uint32_t copy_len, char *dst, size_t dst_size);
void copy_record_payload(const unsigned char *src, uint32_t copy_len);

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

#endif
