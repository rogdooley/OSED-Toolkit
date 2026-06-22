/*
 * vulnserver_lab.c - deliberately vulnerable TCP server for WinDbg / IDA practice.
 *
 * Bug chain:  recv() -> copy (strncpy) -> strcmp (magic gate) -> memcpy (overflow) -> crash
 *
 * Build (x86, mitigations OFF - analysis target only, do NOT ship):
 *   cl /Od /GS- /Zi vulnserver_lab.c /link /SUBSYSTEM:CONSOLE /DYNAMICBASE:NO ws2_32.lib
 *     /Od            no opt -> predictable frame, copy not elided
 *     /GS-           no stack cookie -> control reaches 'ret' cleanly
 *     /Zi            full symbols for WinDbg/IDA
 *     /DYNAMICBASE:NO  fixed image base while learning (pick a jmp esp from this module)
 *
 * Run:  vulnserver_lab.exe        (listens 0.0.0.0:4444)
 *
 * Wire format (little-endian, single recv):
 *   [0  .. 7 ]  magic   : 8 bytes, NUL-terminated string, must equal "OSEDLAB"
 *   [8  .. 11]  length  : uint32, attacker-controlled payload length (NO bound check)
 *   [12 ..  N]  payload : 'length' bytes blindly memcpy'd into a 64-byte stack buffer
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT    4444
#define MAGIC          "OSEDLAB"   /* 7 chars + NUL = 8 bytes */
#define HDR_MAGIC_OFF  0
#define HDR_LEN_OFF    8
#define HDR_PAYLOAD    12

static void handle_client(SOCKET cs)
{
    unsigned char netbuf[2048];

    /* (1) recv -------------------------------------------------------- *
     * Single-shot read. On localhost/LAN with a small PoC the whole     *
     * request arrives in one segment; a real client would need a loop.  */
    int n = recv(cs, (char *)netbuf, (int)sizeof(netbuf), 0);
    if (n < HDR_PAYLOAD) {
        const char *e = "short request\n";
        send(cs, e, (int)strlen(e), 0);
        return;
    }

    /* (2) copy - lift the magic token into a local string ------------- */
    char magic_local[8];
    strncpy(magic_local, (char *)(netbuf + HDR_MAGIC_OFF), sizeof(magic_local));
    magic_local[sizeof(magic_local) - 1] = '\0';

    /* (3) strcmp - magic / auth gate ---------------------------------- */
    if (strcmp(magic_local, MAGIC) != 0) {
        const char *e = "bad magic\n";
        send(cs, e, (int)strlen(e), 0);
        return;
    }

    /* parse attacker-controlled length - this is the missing check ---- */
    uint32_t length;
    memcpy(&length, netbuf + HDR_LEN_OFF, sizeof(length));

    /* (4) memcpy - the bug: 'length' may far exceed sizeof(stage) ----- *
     * Writes past stage[], over saved EBP, then the saved return addr.  */
    char stage[64];
    memcpy(stage, netbuf + HDR_PAYLOAD, length);   /* <-- vulnerable copy */

    /* (5) touch the buffer so the copy survives /Od, then return ------ *
     * On 'ret', EIP is loaded from the attacker-controlled saved slot.  */
    send(cs, stage, (int)(length > sizeof(stage) ? sizeof(stage) : length), 0);
}

int main(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons(LISTEN_PORT);

    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(ls); WSACleanup(); return 1;
    }
    if (listen(ls, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(ls); WSACleanup(); return 1;
    }

    printf("[*] vulnserver_lab listening on 0.0.0.0:%d\n", LISTEN_PORT);
    printf("[*] magic=\"%s\"  stage buffer=64 bytes\n", MAGIC);

    for (;;) {
        SOCKET cs = accept(ls, NULL, NULL);
        if (cs == INVALID_SOCKET) continue;
        handle_client(cs);     /* overflow lives in this frame */
        closesocket(cs);
    }
    /* not reached */
}