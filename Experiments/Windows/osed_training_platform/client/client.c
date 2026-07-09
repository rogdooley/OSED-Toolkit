#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "osedtp_protocol.h"

#pragma comment(lib, "ws2_32.lib")

#define CLIENT_DEFAULT_PORT 11460u

typedef struct CLIENT_OPTIONS {
    const char *host;
    unsigned short port;
    uint16_t opcode;
    const char *name;
    const char *command;
    uint32_t token;
    const char *diag;
} CLIENT_OPTIONS;

static int append_bytes(unsigned char *buffer, size_t capacity, size_t *offset, const void *src, size_t len)
{
    if (*offset + len > capacity) {
        return -1;
    }

    memcpy(buffer + *offset, src, len);
    *offset += len;
    return 0;
}

static int append_record(unsigned char *buffer,
                         size_t capacity,
                         size_t *offset,
                         uint16_t type,
                         uint16_t flags,
                         const void *body,
                         uint32_t body_len)
{
    OSEDTP_RECORD_HEADER rec;

    rec.type = type;
    rec.flags = flags;
    rec.length = body_len;
    if (append_bytes(buffer, capacity, offset, &rec, sizeof(rec)) != 0) {
        return -1;
    }
    if (append_bytes(buffer, capacity, offset, body, body_len) != 0) {
        return -1;
    }
    return 0;
}

static int build_packet(const CLIENT_OPTIONS *opt, unsigned char *buffer, size_t capacity, size_t *packet_len)
{
    OSEDTP_FRAME_HEADER hdr;
    unsigned char body[1024];
    size_t body_off = 0;
    char token_text[16];

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = OSEDTP_MAGIC;
    hdr.version = OSEDTP_VERSION;
    hdr.flags = 0x0001u;
    hdr.opcode = opt->opcode;
    hdr.session_id = 0x0101u;

    if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_CLIENT, 0, opt->name, (uint32_t)strlen(opt->name)) != 0) {
        return -1;
    }

    switch (opt->opcode) {
    case OSEDTP_OP_HELLO:
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_COMMAND, 0, opt->command, (uint32_t)strlen(opt->command)) != 0) {
            return -1;
        }
        break;
    case OSEDTP_OP_AUTH:
        snprintf(token_text, sizeof(token_text), "%08x", (unsigned)opt->token);
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_AUTH, 0, &opt->token, sizeof(opt->token)) != 0) {
            return -1;
        }
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_COMMAND, 0, token_text, (uint32_t)strlen(token_text)) != 0) {
            return -1;
        }
        break;
    case OSEDTP_OP_STATUS:
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_COMMAND, 0, opt->command, (uint32_t)strlen(opt->command)) != 0) {
            return -1;
        }
        break;
    case OSEDTP_OP_CONFIG:
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_CONFIG, 0, opt->command, (uint32_t)strlen(opt->command)) != 0) {
            return -1;
        }
        break;
    case OSEDTP_OP_DIAG:
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_COMMAND, 0, opt->command, (uint32_t)strlen(opt->command)) != 0) {
            return -1;
        }
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_DIAG, 0, opt->diag, (uint32_t)strlen(opt->diag)) != 0) {
            return -1;
        }
        break;
    case OSEDTP_OP_ANALYZE:
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_COMMAND, 0, opt->command, (uint32_t)strlen(opt->command)) != 0) {
            return -1;
        }
        if (append_record(body, sizeof(body), &body_off, OSEDTP_RECORD_DIAG, 0, opt->diag, (uint32_t)strlen(opt->diag)) != 0) {
            return -1;
        }
        break;
    default:
        return -1;
    }

    hdr.total_length = (uint32_t)(sizeof(hdr) + body_off);
    hdr.record_count = 0;
    if (opt->opcode == OSEDTP_OP_AUTH || opt->opcode == OSEDTP_OP_DIAG || opt->opcode == OSEDTP_OP_ANALYZE) {
        hdr.record_count = 3;
    } else if (opt->opcode == OSEDTP_OP_HELLO || opt->opcode == OSEDTP_OP_STATUS || opt->opcode == OSEDTP_OP_CONFIG) {
        hdr.record_count = 2;
    }

    if (sizeof(hdr) + body_off > capacity) {
        return -1;
    }

    memcpy(buffer, &hdr, sizeof(hdr));
    memcpy(buffer + sizeof(hdr), body, body_off);
    *packet_len = sizeof(hdr) + body_off;
    return 0;
}

static int send_all(SOCKET s, const unsigned char *buffer, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int rc = send(s, (const char *)buffer + sent, (int)(len - sent), 0);
        if (rc <= 0) {
            return -1;
        }
        sent += (size_t)rc;
    }
    return 0;
}

static uint16_t parse_opcode(const char *text)
{
    if (strcmp(text, "hello") == 0) return OSEDTP_OP_HELLO;
    if (strcmp(text, "auth") == 0) return OSEDTP_OP_AUTH;
    if (strcmp(text, "status") == 0) return OSEDTP_OP_STATUS;
    if (strcmp(text, "config") == 0) return OSEDTP_OP_CONFIG;
    if (strcmp(text, "diag") == 0) return OSEDTP_OP_DIAG;
    if (strcmp(text, "analyze") == 0) return OSEDTP_OP_ANALYZE;
    return (uint16_t)strtoul(text, NULL, 0);
}

int main(int argc, char **argv)
{
    CLIENT_OPTIONS opt;
    WSADATA wsa;
    SOCKET s;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    unsigned char packet[1280];
    size_t packet_len = 0;
    const char *mode = "hello";
    char reply[256];
    int reply_len;

    opt.host = "127.0.0.1";
    opt.port = CLIENT_DEFAULT_PORT;
    opt.opcode = OSEDTP_OP_HELLO;
    opt.name = "student";
    opt.command = "baseline";
    opt.token = 0xC0FFEE11u;
    opt.diag = "diagnostic bundle";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            opt.host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            opt.port = (unsigned short)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            opt.name = argv[++i];
        } else if (strcmp(argv[i], "--command") == 0 && i + 1 < argc) {
            opt.command = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            opt.token = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--diag") == 0 && i + 1 < argc) {
            opt.diag = argv[++i];
        }
    }

    opt.opcode = parse_opcode(mode);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(opt.host, NULL, &hints, &result) != 0) {
        fprintf(stderr, "getaddrinfo failed\n");
        WSACleanup();
        return 1;
    }

    s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "socket failed\n");
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    {
        struct sockaddr_in addr;
        memcpy(&addr, result->ai_addr, sizeof(addr));
        addr.sin_port = htons(opt.port);

        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            fprintf(stderr, "connect failed\n");
            closesocket(s);
            freeaddrinfo(result);
            WSACleanup();
            return 1;
        }
    }

    freeaddrinfo(result);

    if (build_packet(&opt, packet, sizeof(packet), &packet_len) != 0) {
        fprintf(stderr, "packet build failed\n");
        closesocket(s);
        WSACleanup();
        return 1;
    }

    if (send_all(s, packet, packet_len) != 0) {
        fprintf(stderr, "send failed\n");
        closesocket(s);
        WSACleanup();
        return 1;
    }

    reply_len = recv(s, reply, (int)(sizeof(reply) - 1U), 0);
    if (reply_len > 0) {
        reply[reply_len] = '\0';
        printf("%s", reply);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
