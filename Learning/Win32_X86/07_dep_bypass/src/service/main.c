/*
 * main.c - VulnSvc entry point and per-connection accept loop.
 *
 * Boring on purpose. The service sets up Winsock, forces the noise DLLs to
 * load (so they are present in the process for gadget hunting), binds a
 * listener, and spins a thread per client. The interesting code is downstream
 * in dispatch.c / handlers.c / parser.c.
 *
 * Build target: 32-bit, /GS- /DYNAMICBASE:NO /NXCOMPAT /SAFESEH:NO, base
 * 0x00400000. See BUILD.md.
 */

#define WIN32_LEAN_AND_MEAN   /* stop windows.h pulling in Winsock 1 (winsock.h) */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>

#include "service.h"
#include "protocol.h"

#pragma comment(lib, "ws2_32.lib")

/* These imports pull the companion DLLs into the process address space so a
 * student can enumerate them with `lm` / Narly and reason about gadget
 * sources. The functions themselves are legitimately used below. */
__declspec(dllimport) unsigned long ComputeChecksum(const unsigned char *data, unsigned long len);
__declspec(dllimport) int           Decompress(const unsigned char *in, unsigned long in_len,
                                                unsigned char *out, unsigned long *out_len);
__declspec(dllimport) void           CryptoInit(void);       /* crypto.dll  */
__declspec(dllimport) void           NetlibInit(void);       /* network.dll */
__declspec(dllimport) void           HelperInit(void);       /* helper.dll  */

volatile long g_total_requests    = 0;
volatile long g_total_connections = 0;

static unsigned __stdcall client_thread(void *arg)
{
    Client *c = (Client *)arg;
    InterlockedIncrement(&g_total_connections);
    log_msg("INFO", "connection accepted (fd=%d)", (int)c->sock);

    connection_loop(c);

    closesocket(c->sock);
    log_msg("INFO", "connection closed (handled=%u)", c->requests_handled);
    free(c);
    return 0;
}

static SOCKET make_listener(unsigned short port)
{
    SOCKET s;
    struct sockaddr_in addr;
    int yes = 1;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);   /* lab only - bind all ifaces */
    addr.sin_port        = htons(port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET listener, client_sock;
    unsigned short port = VULNSVC_PORT;

    if (argc > 1)
        port = (unsigned short)atoi(argv[1]);

    log_init("vulnsvc.log");
    log_msg("INFO", "VulnSvc starting on port %u (PID %lu)", port, GetCurrentProcessId());

    /* Force companion modules to initialize (and thus load). */
    CryptoInit();
    NetlibInit();
    HelperInit();
    config_init();

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_msg("FATAL", "WSAStartup failed");
        return 1;
    }

    listener = make_listener(port);
    if (listener == INVALID_SOCKET) {
        log_msg("FATAL", "listener setup failed: %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    log_msg("INFO", "listening. checksum-of-banner=%08lx",
            ComputeChecksum((const unsigned char *)"VulnSvc/1.0", 11));

    for (;;) {
        struct sockaddr_in peer;
        int peerlen = sizeof(peer);
        HANDLE th;

        client_sock = accept(listener, (struct sockaddr *)&peer, &peerlen);
        if (client_sock == INVALID_SOCKET)
            continue;

        Client *c = (Client *)calloc(1, sizeof(Client));
        if (!c) {
            closesocket(client_sock);
            continue;
        }
        c->sock          = client_sock;
        c->authenticated = 0;

        th = (HANDLE)_beginthreadex(NULL, 0, client_thread, c, 0, NULL);
        if (th)
            CloseHandle(th);
        else {
            closesocket(client_sock);
            free(c);
        }
    }

    /* not reached */
    closesocket(listener);
    WSACleanup();
    return 0;
}
