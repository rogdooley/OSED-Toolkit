#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define BACKLOG 5
#define MAX_TRIGGER_BYTES 32

char g_src[BUFFER_SIZE];
char g_dst[BUFFER_SIZE];

typedef enum Mode {
    MODE_NORMAL = 0,
    MODE_TRUNCATE = 1,
    MODE_CRASH = 2
} Mode;

typedef struct Options {
    const char *host;
    int port;
    Mode mode;
    unsigned char trigger_bytes[MAX_TRIGGER_BYTES];
    int trigger_count;
    int oneshot;
} Options;

/* Wrapper kept non-inline so cdb can set a reliable breakpoint on it.
 * At the ret instruction:
 *   eax        = return value of strcpy = dst
 *   poi(esp+4) = first argument         = dst
 * Either expression locates the destination buffer in the dump command. */
__declspec(noinline) char *call_strcpy(char *dst, const char *src) {
    return strcpy(dst, src);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--host <ip>] [--port <n>]\n"
        "          [--mode normal|truncate|crash]\n"
        "          [--trigger-byte <hex>]  (repeat for multiple bad chars)\n"
        "          [--oneshot]\n",
        prog);
}

static int parse_u8(const char *text, unsigned char *out) {
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 0);
    if (end == text || *end != '\0' || value > 255UL) {
        return 0;
    }
    *out = (unsigned char)value;
    return 1;
}

static int parse_i32(const char *text, int *out) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < 1 || value > 65535) {
        return 0;
    }
    *out = (int)value;
    return 1;
}

static int parse_args(int argc, char **argv, Options *opt) {
    int i = 1;
    opt->host = "127.0.0.1";
    opt->port = 9999;
    opt->mode = MODE_NORMAL;
    opt->trigger_count = 0;
    memset(opt->trigger_bytes, 0, sizeof(opt->trigger_bytes));
    opt->oneshot = 0;

    while (i < argc) {
        if (strcmp(argv[i], "--host") == 0) {
            if (i + 1 >= argc) return 0;
            opt->host = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc || !parse_i32(argv[i + 1], &opt->port)) return 0;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--mode") == 0) {
            if (i + 1 >= argc) return 0;
            if (strcmp(argv[i + 1], "normal") == 0)        opt->mode = MODE_NORMAL;
            else if (strcmp(argv[i + 1], "truncate") == 0) opt->mode = MODE_TRUNCATE;
            else if (strcmp(argv[i + 1], "crash") == 0)    opt->mode = MODE_CRASH;
            else return 0;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--trigger-byte") == 0) {
            if (i + 1 >= argc) return 0;
            if (opt->trigger_count >= MAX_TRIGGER_BYTES) {
                fprintf(stderr, "[-] too many --trigger-byte values (max %d)\n",
                        MAX_TRIGGER_BYTES);
                return 0;
            }
            if (!parse_u8(argv[i + 1], &opt->trigger_bytes[opt->trigger_count])) return 0;
            opt->trigger_count++;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--oneshot") == 0) {
            opt->oneshot = 1;
            i += 1;
            continue;
        }
        return 0;
    }
    return 1;
}

/* Return 1 if byte b is in the trigger list. */
static int is_trigger(const Options *opt, unsigned char b) {
    int j;
    for (j = 0; j < opt->trigger_count; ++j) {
        if (opt->trigger_bytes[j] == b) return 1;
    }
    return 0;
}

static int run_server(const Options *opt) {
    WSADATA wsa = {0};
    SOCKET listen_sock = INVALID_SOCKET;
    int rc = 1;
    struct sockaddr_in addr;
    int j;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[-] WSAStartup failed\n");
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "[-] socket failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    {
        int one = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)opt->port);
    addr.sin_addr.s_addr = inet_addr(opt->host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "[-] invalid host address: %s\n", opt->host);
        goto cleanup;
    }

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[-] bind failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    if (listen(listen_sock, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "[-] listen failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    /* Print the trigger byte list. */
    printf("[+] Listening on %s:%d mode=%s triggers=[",
           opt->host, opt->port,
           opt->mode == MODE_NORMAL   ? "normal"   :
           opt->mode == MODE_TRUNCATE ? "truncate" : "crash");
    for (j = 0; j < opt->trigger_count; ++j) {
        if (j > 0) printf(",");
        printf("0x%02x", opt->trigger_bytes[j]);
    }
    printf("] oneshot=%d\n", opt->oneshot);
    fflush(stdout);

    for (;;) {
        SOCKET client = INVALID_SOCKET;
        struct sockaddr_in client_addr;
        int client_len = (int)sizeof(client_addr);
        int recv_len = 0;
        int copied = 0;

        client = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            fprintf(stderr, "[-] accept failed: %d\n", WSAGetLastError());
            goto cleanup;
        }

        printf("[+] Connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        fflush(stdout);

        memset(g_src, 0, sizeof(g_src));
        memset(g_dst, 0, sizeof(g_dst));

        recv_len = recv(client, g_src, BUFFER_SIZE - 1, 0);
        if (recv_len <= 0) {
            closesocket(client);
            if (opt->oneshot) break;
            continue;
        }

        g_src[recv_len] = '\0';

        if (opt->mode == MODE_TRUNCATE) {
            /* Truncate at the first occurrence of any trigger byte. */
            int k;
            for (k = 0; k < recv_len; ++k) {
                if (is_trigger(opt, (unsigned char)g_src[k])) {
                    g_src[k] = '\0';
                    recv_len = k;
                    break;
                }
            }
        } else if (opt->mode == MODE_CRASH) {
            int k;
            for (k = 0; k < recv_len; ++k) {
                if (is_trigger(opt, (unsigned char)g_src[k])) {
                    printf("[!] Crash trigger encountered: 0x%02x\n",
                           (unsigned char)g_src[k]);
                    fflush(stdout);
                    /* Intentional crash for debugger classification path. */
                    *((volatile int *)0) = 1;
                }
            }
        }

        call_strcpy(g_dst, g_src);
        copied = (int)strlen(g_dst);

        printf("[+] Received=%d Copied=%d\n", recv_len, copied);
        fflush(stdout);

        send(client, "OK", 2, 0);
        /* Keep process alive long enough for post-breakpoint dump workflows. */
        Sleep(5000);

        closesocket(client);
        if (opt->oneshot) break;
    }

    rc = 0;

cleanup:
    if (listen_sock != INVALID_SOCKET) {
        closesocket(listen_sock);
    }
    WSACleanup();
    return rc;
}

int main(int argc, char **argv) {
    Options opt;
    if (!parse_args(argc, argv, &opt)) {
        print_usage(argv[0]);
        return 1;
    }
    return run_server(&opt);
}
