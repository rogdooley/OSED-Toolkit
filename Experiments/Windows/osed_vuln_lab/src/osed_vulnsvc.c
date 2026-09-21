#include <Winsock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "osed_protocol.h"
#include "osedhelper.h"

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "9999"
#define MAX_PACKET 8192

static int __declspec(noinline) recv_exact(SOCKET s, char *buf, int need) {
    int got = 0;
    while (got < need) {
        int r = recv(s, buf + got, need - got, 0);
        if (r <= 0) {
            return -1;
        }
        got += r;
    }
    return got;
}

static int __declspec(noinline) send_exact(SOCKET s, const char *buf, int length) {
    int sent = 0;
    while (sent < length) {
        int result = send(s, buf + sent, length - sent, 0);
        if (result <= 0) {
            return -1;
        }
        sent += result;
    }
    return sent;
}

static void __declspec(noinline) handler_ping(SOCKET client) {
    static const char response[] = "PONG\n";
    send_exact(client, response, (int)(sizeof(response) - 1));
}

#if defined(OSED_PROFILE_EASY)
static void __declspec(noinline) handler_stack(const uint8_t *data, uint32_t len) {
    char stackbuf[256];

    /* INTENTIONAL VULNERABILITY: classic stack overflow for EIP control practice. */
    memcpy(stackbuf, data, len);

    if (stackbuf[0] == '\0') {
        puts("request contained a leading NUL");
    }
}

static void __declspec(noinline) handler_smallbuf(const uint8_t *data, uint32_t len) {
    char tiny[64];

    /* INTENTIONAL VULNERABILITY: constrained overwrite for staged-payload practice. */
    memcpy(tiny, data, len);

    if (tiny[1] == 'Z') {
        puts("request marker observed");
    }
}
#endif

#if defined(OSED_PROFILE_SEH)
static LONG WINAPI lab_exception_filter(EXCEPTION_POINTERS *ep) {
    printf("[seh] exception code=0x%08lX eip=0x%08lX\n",
           (unsigned long)ep->ExceptionRecord->ExceptionCode,
           (unsigned long)ep->ContextRecord->Eip);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void __declspec(noinline) handler_seh(const uint8_t *data, uint32_t len) {
    char sehbuf[512];

    __try {
        /* INTENTIONAL VULNERABILITY: overwrite beyond local frame toward SEH chain. */
        memcpy(sehbuf, data, len);

        /* Deterministic exception path for SEH training once overwrite is staged. */
        *(volatile int *)0 = 0x41414141;
    } __except (lab_exception_filter(GetExceptionInformation())) {
        puts("[seh] handler reached");
    }
}

static int __declspec(noinline) dispatch_seh_record(
    const OSED_PACKET_HEADER *packet,
    const uint8_t *body) {
    const OSED_SEH_RECORD *record;
    uint32_t data_offset;

    if (packet->control != OSED_CONTROL_STRUCTURED ||
        packet->length < sizeof(OSED_SEH_RECORD)) {
        return -1;
    }

    record = (const OSED_SEH_RECORD *)body;
    if (record->type != OSED_RECORD_DATA) {
        return -1;
    }

    data_offset = (uint32_t)sizeof(OSED_SEH_RECORD) + record->name_length;
    if (data_offset > packet->length ||
        record->data_length != packet->length - data_offset) {
        return -1;
    }

    handler_seh(body + data_offset, record->data_length);
    return 0;
}
#endif

#if defined(OSED_PROFILE_ASLR_DEP)
static int __declspec(noinline) handler_leak(SOCKET client) {
    void *fp = (void *)&helper_get_anchor;
    uintptr_t leak = (uintptr_t)fp;
    OSED_PACKET_HEADER response_header;
    OSED_V2_RESULT result;

    response_header.magic = OSED_MAGIC;
    response_header.opcode = OP_LEAK;
    response_header.control = OSED_CONTROL_V2_RECORD;
    response_header.length = (uint32_t)sizeof(result);
    result.status = 0;
    result.kind = OSED_RECORD_QUERY;
    result.value = (uint32_t)leak;

    if (send_exact(client, (const char *)&response_header, (int)sizeof(response_header)) < 0) {
        return -1;
    }
    return send_exact(client, (const char *)&result, (int)sizeof(result)) < 0 ? -1 : 0;
}
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
static void __declspec(noinline) rop_target_marker(void) {
    puts("ROP target marker reached");
}

static void __declspec(noinline) handler_rop(const uint8_t *data, uint32_t len) {
    char ropbuf[300];

    /*
     * INTENTIONAL VULNERABILITY: stack overwrite in DEP-aware profile.
     * Intended for VirtualProtect-based ROP chain practice.
     */
    memcpy(ropbuf, data, len);

    if (ropbuf[2] == 'R') {
        rop_target_marker();
    }
}

static int __declspec(noinline) parse_v2_record(
    const OSED_PACKET_HEADER *packet,
    const uint8_t *body,
    uint16_t expected_kind,
    const uint8_t **data,
    uint32_t *data_length) {
    const OSED_V2_RECORD *record;

    if (packet->control != OSED_CONTROL_V2_RECORD ||
        packet->length < sizeof(OSED_V2_RECORD)) {
        return -1;
    }

    record = (const OSED_V2_RECORD *)body;
    if (record->kind != expected_kind ||
        record->options != 0 ||
        record->data_offset < sizeof(OSED_V2_RECORD) ||
        record->data_offset > packet->length ||
        record->data_length != packet->length - record->data_offset) {
        return -1;
    }

    *data = body + record->data_offset;
    *data_length = record->data_length;
    return 0;
}
#endif

static int __declspec(noinline) dispatch_packet(
    SOCKET client,
    const OSED_PACKET_HEADER *hdr,
    const uint8_t *body) {
    switch (hdr->opcode) {
    case OP_PING:
        if (hdr->control != OSED_CONTROL_V1 || hdr->length != 0) {
            return -1;
        }
        handler_ping(client);
        return 0;
#if defined(OSED_PROFILE_EASY)
    case OP_STACK:
        if (hdr->control != OSED_CONTROL_V1) {
            return -1;
        }
        handler_stack(body, hdr->length);
        return 0;
    case OP_SMALLBUF:
        if (hdr->control != OSED_CONTROL_V1) {
            return -1;
        }
        handler_smallbuf(body, hdr->length);
        return 0;
#endif
#if defined(OSED_PROFILE_SEH)
    case OP_SEH:
        return dispatch_seh_record(hdr, body);
#endif
#if defined(OSED_PROFILE_ASLR_DEP)
    case OP_LEAK: {
        const uint8_t *query_data;
        uint32_t query_length;
        if (parse_v2_record(
                hdr,
                body,
                OSED_RECORD_QUERY,
                &query_data,
                &query_length) != 0 ||
            query_length != 0) {
            return -1;
        }
        (void)query_data;
        return handler_leak(client);
    }
#endif
#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
    case OP_ROP: {
        const uint8_t *record_data;
        uint32_t record_length;
        if (parse_v2_record(
                hdr,
                body,
                OSED_RECORD_DATA,
                &record_data,
                &record_length) != 0) {
            return -1;
        }
        handler_rop(record_data, record_length);
        return 0;
    }
#endif
    default:
        puts("Unknown opcode");
        return -1;
    }
}

static int __declspec(noinline) run_server(const char *port) {
    WSADATA wsa;
    SOCKET listen_sock = INVALID_SOCKET;
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        puts("WSAStartup failed");
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &result) != 0) {
        puts("getaddrinfo failed");
        WSACleanup();
        return 1;
    }

    listen_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listen_sock == INVALID_SOCKET) {
        puts("socket failed");
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    if (bind(listen_sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        puts("bind failed");
        closesocket(listen_sock);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        puts("listen failed");
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    printf("osed_vulnsvc listening on %s\n", port);
    fflush(stdout);

    for (;;) {
        SOCKET client = accept(listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) {
            puts("accept failed");
            continue;
        }

        for (;;) {
            OSED_PACKET_HEADER hdr;
            uint8_t body[MAX_PACKET];
            memset(&hdr, 0, sizeof(hdr));
            memset(body, 0, sizeof(body));

            if (recv_exact(client, (char *)&hdr, (int)sizeof(hdr)) < 0) {
                break;
            }

            if (hdr.magic != OSED_MAGIC) {
                puts("bad magic");
                break;
            }

            if (hdr.length > MAX_PACKET) {
                puts("length too large");
                break;
            }

            if (hdr.length > 0) {
                if (recv_exact(client, (char *)body, (int)hdr.length) < 0) {
                    break;
                }
            }

            if (dispatch_packet(client, &hdr, body) != 0) {
                break;
            }
        }

        closesocket(client);
    }

    closesocket(listen_sock);
    WSACleanup();
    return 0;
}

int main(int argc, char **argv) {
    const char *port = DEFAULT_PORT;
    if (argc > 1) {
        port = argv[1];
    }

    if (helper_probe(7) == 0) {
        return 1;
    }

    return run_server(port);
}
