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

typedef struct DEBUG_CTX {
    const char *handler;
    uint16_t opcode;
    uint32_t declared_length;
    size_t copied_length;
} DEBUG_CTX;

static void debug_log(const DEBUG_CTX *ctx) {
    printf("[dbg] handler=%s opcode=0x%04X declared=%lu copied=%llu\n",
           ctx->handler,
           ctx->opcode,
           (unsigned long)ctx->declared_length,
           (unsigned long long)ctx->copied_length);
    fflush(stdout);
}

static int recv_exact(SOCKET s, char *buf, int need) {
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

static void __declspec(noinline) handler_stack(const uint8_t *data, uint32_t len) {
    char stackbuf[256];
    DEBUG_CTX ctx = { "OP_STACK", OP_STACK, len, (size_t)len };

    /* INTENTIONAL VULNERABILITY: classic stack overflow for EIP control practice. */
    memcpy(stackbuf, data, len);
    debug_log(&ctx);

    if (stackbuf[0] == '\0') {
        puts("stackbuf starts with NUL");
    }
}

static LONG WINAPI lab_exception_filter(EXCEPTION_POINTERS *ep) {
    printf("[seh] exception code=0x%08lX eip=0x%08lX\n",
           (unsigned long)ep->ExceptionRecord->ExceptionCode,
           (unsigned long)ep->ContextRecord->Eip);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void __declspec(noinline) handler_seh(const uint8_t *data, uint32_t len) {
    char sehbuf[512];
    DEBUG_CTX ctx = { "OP_SEH", OP_SEH, len, (size_t)len };

    __try {
        /* INTENTIONAL VULNERABILITY: overwrite beyond local frame toward SEH chain. */
        memcpy(sehbuf, data, len);
        debug_log(&ctx);

        /* Deterministic exception path for SEH training once overwrite is staged. */
        *(volatile int *)0 = 0x41414141;
    } __except (lab_exception_filter(GetExceptionInformation())) {
        puts("[seh] handler reached");
    }
}

static void __declspec(noinline) handler_smallbuf(const uint8_t *data, uint32_t len) {
    char tiny[64];
    DEBUG_CTX ctx = { "OP_SMALLBUF", OP_SMALLBUF, len, (size_t)len };

    /* INTENTIONAL VULNERABILITY: constrained overwrite for egghunter staging practice. */
    memcpy(tiny, data, len);
    debug_log(&ctx);

    if (tiny[1] == 'Z') {
        puts("tiny[1] == Z");
    }
}

static void __declspec(noinline) handler_leak(const uint8_t *data, uint32_t len, SOCKET client) {
    (void)data;
    DEBUG_CTX ctx = { "OP_LEAK", OP_LEAK, len, 0 };

    void *fp = (void *)&helper_get_anchor;
    uintptr_t leak = (uintptr_t)fp;
    debug_log(&ctx);

    char out[64];
    int n = _snprintf(out, sizeof(out), "LEAK:%p\n", (void *)leak);
    if (n > 0) {
        send(client, out, n, 0);
    }
}

static void __declspec(noinline) rop_target_marker(void) {
    puts("ROP target marker reached");
}

static void __declspec(noinline) handler_rop(const uint8_t *data, uint32_t len) {
    char ropbuf[300];
    DEBUG_CTX ctx = { "OP_ROP", OP_ROP, len, (size_t)len };

    /*
     * INTENTIONAL VULNERABILITY: stack overwrite in DEP-aware profile.
     * Intended for VirtualProtect-based ROP chain practice.
     */
    memcpy(ropbuf, data, len);
    debug_log(&ctx);

    if (ropbuf[2] == 'R') {
        rop_target_marker();
    }
}

static int dispatch_packet(SOCKET client, const OSED_PACKET_HEADER *hdr, const uint8_t *body) {
    switch (hdr->opcode) {
    case OP_STACK:
        handler_stack(body, hdr->length);
        return 0;
    case OP_SEH:
        handler_seh(body, hdr->length);
        return 0;
    case OP_SMALLBUF:
        handler_smallbuf(body, hdr->length);
        return 0;
    case OP_LEAK:
        handler_leak(body, hdr->length, client);
        return 0;
    case OP_ROP:
        handler_rop(body, hdr->length);
        return 0;
    default:
        puts("Unknown opcode");
        return -1;
    }
}

static int run_server(const char *port) {
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

    printf("helper anchor: %p helper_probe=%d\n", helper_get_anchor(), helper_probe(7));
    fflush(stdout);

    return run_server(port);
}
