/*
Build with MinGW x86:
  gcc -m32 -g -gcodeview -fno-stack-protector -o mini_proto_vuln.exe mini_proto_vuln.c -lws2_32

Run:
  mini_proto_vuln.exe

Debug:
  bp ws2_32!recv
  bp mini_proto_vuln!parse_packet
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 11460
#define RECV_MAX 0x4400

typedef struct _PACKET_HEADER {
    uint32_t magic;
    uint32_t opcode;
    uint32_t declared_len;
    uint32_t copy_len;
} PACKET_HEADER;

static void vulnerable_copy(const char *src, uint32_t len) {
    char stack_buffer[128];

    printf("[vulnerable_copy] copying %lu bytes into 128-byte stack buffer\n",
           (unsigned long)len);

    /*
     * Intentional vulnerability:
     * len is attacker-controlled and not bounded against stack_buffer.
     */
    memcpy(stack_buffer, src, len);

    printf("[vulnerable_copy] first bytes: %.16s\n", stack_buffer);
}

static int handle_opcode(const PACKET_HEADER *hdr, const char *body) {
    if (hdr->opcode == 0x1001) {
        puts("[handle_opcode] opcode 0x1001: benign path");
        return 1;
    }

    if (hdr->opcode == 0x1337) {
        puts("[handle_opcode] opcode 0x1337: vulnerable path");
        vulnerable_copy(body, hdr->copy_len);
        return 1;
    }

    puts("[handle_opcode] unknown opcode");
    return 0;
}

static int parse_packet(char *buf, int received) {
    PACKET_HEADER hdr;
    char *body;

    if (received < (int)sizeof(PACKET_HEADER)) {
        puts("[parse_packet] packet too small");
        return 0;
    }

    memcpy(&hdr, buf, sizeof(PACKET_HEADER));

    printf("[parse_packet] magic        = 0x%08lx\n", (unsigned long)hdr.magic);
    printf("[parse_packet] opcode       = 0x%08lx\n", (unsigned long)hdr.opcode);
    printf("[parse_packet] declared_len = 0x%08lx\n", (unsigned long)hdr.declared_len);
    printf("[parse_packet] copy_len     = 0x%08lx\n", (unsigned long)hdr.copy_len);

    if (hdr.magic != 0x4f534544) { /* "OSED" little-endian */
        puts("[parse_packet] bad magic");
        return 0;
    }

    if (hdr.declared_len != (uint32_t)(received - sizeof(PACKET_HEADER))) {
        puts("[parse_packet] declared length mismatch");
        return 0;
    }

    body = buf + sizeof(PACKET_HEADER);
    return handle_opcode(&hdr, body);
}

int main(void) {
    WSADATA wsa;
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in addr;
    char recv_buf[RECV_MAX];
    int received;

    WSAStartup(MAKEWORD(2, 2), &wsa);

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    bind(listener, (struct sockaddr *)&addr, sizeof(addr));
    listen(listener, 1);

    printf("[main] listening on TCP %d\n", PORT);

    client = accept(listener, NULL, NULL);
    puts("[main] client connected");

    received = recv(client, recv_buf, sizeof(recv_buf), 0);
    printf("[main] recv returned %d\n", received);

    if (received > 0) {
        parse_packet(recv_buf, received);
    }

    closesocket(client);
    closesocket(listener);
    WSACleanup();

    return 0;
}