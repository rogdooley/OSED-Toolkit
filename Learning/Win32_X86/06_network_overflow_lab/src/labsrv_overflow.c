// Win32/x86 training service: classic stack overflow via a simple TCP command.
//
// Build (x86):
//   cl /nologo /W3 /Od /Zi /MT labsrv_overflow.c ws2_32.lib /link /OUT:labsrv_overflow_x86.exe
//
// Protocol (ASCII):
//   "PING\r\n"                -> replies "PONG\r\n"
//   "OVER " + <data> + "\r\n" -> copies <data> into a fixed stack buffer unsafely
//
// This is intentionally unsafe and meant only for an authorized lab VM.

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>

static const char *BIND_IP = "127.0.0.1";
static const unsigned short BIND_PORT = 9001;

static int recv_line(SOCKET s, char *out, int out_len)
{
    int total = 0;
    while (total < out_len - 1) {
        char c = 0;
        int n = recv(s, &c, 1, 0);
        if (n <= 0) {
            break;
        }
        out[total++] = c;
        if (c == '\n') {
            break;
        }
    }
    out[total] = '\0';
    return total;
}

__declspec(noinline) static void handle_over(const char *user)
{
    // This is the controlled overflow primitive.
    // The goal is to reproduce crashes and study them in WinDbg/IDA.
    char buf[256];

    // Deliberately unsafe: unbounded copy.
    strcpy(buf, user);

    // Touch it so it stays in the frame.
    if (buf[0] == 'Z') {
        puts("unlikely");
    }
}

__declspec(noinline) static void handle_client(SOCKET client)
{
    char line[2048];
    int n = recv_line(client, line, (int)sizeof(line));
    if (n <= 0) {
        return;
    }

    if (_strnicmp(line, "PING", 4) == 0) {
        const char *resp = "PONG\r\n";
        send(client, resp, (int)strlen(resp), 0);
        return;
    }

    if (_strnicmp(line, "OVER ", 5) == 0) {
        // Strip trailing CRLF if present.
        char *p = line + 5;
        char *cr = strchr(p, '\r');
        if (cr) {
            *cr = '\0';
        } else {
            char *lf = strchr(p, '\n');
            if (lf) {
                *lf = '\0';
            }
        }

        handle_over(p);
        const char *resp = "OK\r\n";
        send(client, resp, (int)strlen(resp), 0);
        return;
    }

    {
        const char *resp = "ERR\r\n";
        send(client, resp, (int)strlen(resp), 0);
    }
}

int main(void)
{
    WSADATA wsa;
    SOCKET server = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        puts("WSAStartup failed");
        return 1;
    }

    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        puts("socket failed");
        WSACleanup();
        return 1;
    }

    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(BIND_PORT);
        addr.sin_addr.s_addr = inet_addr(BIND_IP);

        if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            puts("bind failed");
            closesocket(server);
            WSACleanup();
            return 1;
        }
    }

    if (listen(server, 1) == SOCKET_ERROR) {
        puts("listen failed");
        closesocket(server);
        WSACleanup();
        return 1;
    }

    printf("listening on %s:%u\n", BIND_IP, (unsigned)BIND_PORT);

    for (;;) {
        client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET) {
            puts("accept failed");
            break;
        }

        handle_client(client);
        closesocket(client);
    }

    closesocket(server);
    WSACleanup();
    return 0;
}

