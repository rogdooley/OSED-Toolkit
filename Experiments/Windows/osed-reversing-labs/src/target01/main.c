#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { unsigned char magic[4]; uint16_t command, key, wire_size, clear_size; } Frame;
static int receive_all(SOCKET s, unsigned char *p, int n) { int got = 0, r; while (got < n) { r = recv(s, (char *)p + got, n - got, 0); if (r <= 0) return 0; got += r; } return 1; }
static void unmask(unsigned char *p, unsigned int n, uint16_t key) { unsigned int i; for (i = 0; i < n; ++i) p[i] ^= (unsigned char)(key + i * 13U); }
static int relay(const unsigned char *input, uint16_t claimed, unsigned char response[32]) { unsigned char local[192]; if (claimed == 0 || claimed > 384) return 0; memcpy(local, input, claimed); _snprintf((char *)response, 32, "stored:%u", (unsigned int)local[0]); return 1; }
static void handle_client(SOCKET client) { Frame f; unsigned char encoded[384], reply[32] = "invalid"; if (!receive_all(client, (unsigned char *)&f, sizeof(f)) || memcmp(f.magic, "RVP1", 4) || f.command != 0x213 || f.wire_size == 0 || f.wire_size > sizeof(encoded)) return; if (!receive_all(client, encoded, f.wire_size)) return; unmask(encoded, f.wire_size, f.key); if (relay(encoded, f.clear_size, reply)) send(client, (const char *)reply, (int)strlen((const char *)reply), 0); }
int main(void) { WSADATA w; struct sockaddr_in a; SOCKET l; if (WSAStartup(MAKEWORD(2, 2), &w)) return 1; l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (l == INVALID_SOCKET) return 1; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(31801); if (bind(l, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR || listen(l, 4) == SOCKET_ERROR) return 1; printf("service ready on 127.0.0.1:31801\n"); for (;;) { SOCKET s = accept(l, NULL, NULL); if (s != INVALID_SOCKET) { handle_client(s); closesocket(s); } } }
