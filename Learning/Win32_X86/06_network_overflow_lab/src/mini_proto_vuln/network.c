#include "mini_proto_vuln.h"

#include <stdio.h>
#include <string.h>

static int serve_client(SOCKET client)
{
    PacketContext ctx;
    int recv_len;

    memset(&ctx, 0, sizeof(ctx));

    recv_len = receive_packet(client, &ctx);
    if (recv_len <= 0) {
        return -1;
    }

    if (parse_protocol(&ctx) != 0) {
        return -1;
    }

    return dispatch_command(client, &ctx);
}

int receive_packet(SOCKET client, PacketContext *ctx)
{
    int recv_len;

    /* WinDbg first stop: break on ws2_32!recv and inspect the raw buffer. */
    recv_len = recv(client, (char *)ctx->raw, (int)sizeof(ctx->raw), 0);
    if (recv_len <= 0) {
        printf("[network] recv failed or connection closed (%d)\n", recv_len);
        return recv_len;
    }

    ctx->raw_length = (size_t)recv_len;
    printf("[network] received %d bytes\n", recv_len);
    hexdump(ctx->raw, ctx->raw_length, 128U);
    return recv_len;
}

int start_server(void)
{
    WSADATA wsa;
    SOCKET server = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        puts("[server] WSAStartup failed");
        return 1;
    }

    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        puts("[server] socket failed");
        WSACleanup();
        return 1;
    }

    {
        int reuse = 1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(MINI_PROTO_BIND_PORT);
        addr.sin_addr.s_addr = inet_addr(MINI_PROTO_BIND_IP);

        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

        if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            puts("[server] bind failed");
            closesocket(server);
            WSACleanup();
            return 1;
        }
    }

    if (listen(server, 1) == SOCKET_ERROR) {
        puts("[server] listen failed");
        closesocket(server);
        WSACleanup();
        return 1;
    }

    printf("[server] listening on %s:%u\n", MINI_PROTO_BIND_IP, (unsigned)MINI_PROTO_BIND_PORT);

    for (;;) {
        SOCKET client;

        client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET) {
            puts("[server] accept failed");
            break;
        }

        printf("[server] client connected\n");
        serve_client(client);
        closesocket(client);
        printf("[server] client closed\n");
    }

    closesocket(server);
    WSACleanup();
    return 0;
}
