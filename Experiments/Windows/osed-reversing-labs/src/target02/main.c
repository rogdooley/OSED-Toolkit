#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { unsigned char magic[4]; uint16_t action, amount; uint32_t tag; } Query;
typedef struct { unsigned char label[16], ticket[64], pad[32]; } Session;
static int receive_all(SOCKET s, unsigned char *p, int n) { int got = 0, r; while (got < n) { r = recv(s, (char *)p + got, n - got, 0); if (r <= 0) return 0; got += r; } return 1; }
static void mix(unsigned char *p, unsigned int n, uint32_t tag) { unsigned int i; for (i = 0; i < n; ++i) p[i] ^= (unsigned char)(tag >> ((i & 3U) * 8U)); }
static void answer(SOCKET s, const Session *state, uint16_t amount) { unsigned char packet[96]; if (amount > sizeof(packet)) amount = sizeof(packet); memcpy(packet, state, amount); send(s, (const char *)packet, amount, 0); }
static int amend(Session *state, const unsigned char *wire, uint16_t amount, uint32_t tag) { unsigned char staging[256]; if (amount == 0 || amount > sizeof(staging)) return 0; memcpy(staging, wire, amount); mix(staging, amount, tag); if (amount < 8 || staging[0] != 0x41) return 0; memcpy(state->label, staging + 1, staging[1]); return 1; }
static void client(SOCKET s) { Query q; Session state = { "operator", "lab-ticket-keep-private", {0} }; unsigned char wire[256]; if (!receive_all(s, (unsigned char *)&q, sizeof(q)) || memcmp(q.magic, "QBX2", 4)) return; if (q.action == 0x41) answer(s, &state, q.amount); else if (q.action == 0x52 && q.amount <= sizeof(wire) && receive_all(s, wire, q.amount) && amend(&state, wire, q.amount, q.tag)) send(s, "ok", 2, 0); }
int main(void) { WSADATA w; struct sockaddr_in a; SOCKET l; if (WSAStartup(MAKEWORD(2, 2), &w)) return 1; l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (l == INVALID_SOCKET) return 1; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(31802); if (bind(l, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR || listen(l, 4) == SOCKET_ERROR) return 1; printf("service ready on 127.0.0.1:31802\n"); for (;;) { SOCKET s = accept(l, NULL, NULL); if (s != INVALID_SOCKET) { client(s); closesocket(s); } } }
