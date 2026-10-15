#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "io_helpers.h"
#include "stage_trace.h"

typedef struct net03_header {
    char magic[4];
    uint8_t version;
    uint8_t kind;
    uint16_t length;
} net03_header;

/* Heap input is decoded in place, then staged onto the stack. */
static void net03_decode_and_stage(uint8_t *heap_bytes, size_t length) {
    uint8_t stack_stage[256];
    size_t copy_length = length < sizeof(stack_stage) ? length : sizeof(stack_stage);
    size_t index;

    stage_trace_capture(STAGE_PRE_TRANSFORM, heap_bytes, length);
    for (index = 0; index < length; ++index) {
        heap_bytes[index] ^= 0x55;
    }
    stage_trace_capture(STAGE_POST_TRANSFORM, heap_bytes, length);
    memcpy(stack_stage, heap_bytes, copy_length);
    stage_trace_capture(STAGE_FINAL_DESTINATION, stack_stage, copy_length);
}

int main(int argc, char **argv) {
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in address;
    net03_header header;
    uint8_t *candidate = NULL;
    int port = argc > 1 ? atoi(argv[1]) : 32103;
    int result = 1;

    if (port <= 0 || port > 65535 || common_winsock_startup() != COMMON_OK) {
        return 1;
    }
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        goto cleanup;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((u_short)port);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        goto cleanup;
    }
    client = accept(listener, NULL, NULL);
    if (client == INVALID_SOCKET ||
        common_recv_exact(client, (uint8_t *)&header, sizeof(header), 3000) != COMMON_OK ||
        memcmp(header.magic, "BCN3", sizeof(header.magic)) != 0 || header.version != 1 ||
        header.kind != 1 || header.length == 0 || header.length > 4096) {
        goto cleanup;
    }
    candidate = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, header.length);
    if (candidate == NULL ||
        common_recv_exact(client, candidate, header.length, 3000) != COMMON_OK) {
        goto cleanup;
    }
    stage_trace_capture(STAGE_INITIAL_INPUT, candidate, header.length);
    net03_decode_and_stage(candidate, header.length);
    result = 0;

cleanup:
    if (candidate != NULL) {
        HeapFree(GetProcessHeap(), 0, candidate);
    }
    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
    }
    common_winsock_cleanup();
    return result;
}
