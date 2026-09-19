#include <WinSock2.h>
#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define FMT_MAGIC 0x324D5446u
#define FMT_PORT 31337
#define OP_FORMAT 1u
#define OP_EXECUTE 2u

#pragma pack(push, 1)
typedef struct format_request {
    uint32_t magic;
    uint32_t opcode;
    uint32_t arguments[8];
    char format[256];
} format_request;
#pragma pack(pop)

typedef void (__cdecl *action_fn)(void);

static void normal_action(void)
{
    puts("[state] Normal action executed.");
}

static void proof_action(void)
{
    puts("[success] Format-string write redirected the persistent function pointer.");
    fflush(stdout);
    ExitProcess(0);
}

static void module_anchor(void)
{
    volatile uint32_t marker = 0xA5A55A5Au;
    (void)marker;
}

static action_fn selected_action = normal_action;
static volatile uint32_t scratch_dword = 0;
static const char protected_record[] = "INTEGRATED_SECRET=read_then_write_then_redirect";

static int recv_exact(SOCKET client, void *buffer, int length)
{
    char *cursor = (char *)buffer;
    int received = 0;

    while (received < length) {
        int result = recv(client, cursor + received, length - received, 0);
        if (result <= 0) {
            return 0;
        }
        received += result;
    }
    return 1;
}

static int send_exact(SOCKET client, const void *buffer, int length)
{
    const char *cursor = (const char *)buffer;
    int sent = 0;

    while (sent < length) {
        int result = send(client, cursor + sent, length - sent, 0);
        if (result == SOCKET_ERROR) {
            return 0;
        }
        sent += result;
    }
    return 1;
}

__declspec(noinline) static void process_format(SOCKET client, format_request *request)
{
    char output[512];
    int result;
    uint32_t output_length;

    request->format[sizeof(request->format) - 1] = '\0';
    memset(output, 0, sizeof(output));

    result = _snprintf(output, sizeof(output) - 1, request->format,
        request->arguments[0], request->arguments[1],
        request->arguments[2], request->arguments[3],
        request->arguments[4], request->arguments[5],
        request->arguments[6], request->arguments[7],
        (uintptr_t)&module_anchor, (uintptr_t)request,
        (uintptr_t)protected_record);

    output[sizeof(output) - 1] = '\0';
    output_length = (uint32_t)strnlen(output, sizeof(output));
    if (result < 0) {
        output_length = (uint32_t)strnlen(output, sizeof(output));
    }

    send_exact(client, &output_length, (int)sizeof(output_length));
    if (output_length > 0) {
        send_exact(client, output, (int)output_length);
    }
}

static void process_client(SOCKET client)
{
    format_request request;

    memset(&request, 0, sizeof(request));
    if (!recv_exact(client, &request, (int)sizeof(request))) {
        return;
    }
    if (request.magic != FMT_MAGIC) {
        return;
    }

    if (request.opcode == OP_FORMAT) {
        process_format(client, &request);
    } else if (request.opcode == OP_EXECUTE) {
        selected_action();
    }
}

int main(void)
{
    WSADATA wsa;
    SOCKET listener;
    struct sockaddr_in address;

    _set_printf_count_output(1);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(FMT_PORT);

    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR ||
        listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    printf("fmt05_service listening on 127.0.0.1:%u\n", FMT_PORT);
    printf("scratch state initialized to %u\n", (unsigned int)scratch_dword);
    fflush(stdout);

    for (;;) {
        SOCKET client = accept(listener, NULL, NULL);
        if (client == INVALID_SOCKET) {
            continue;
        }
        process_client(client);
        closesocket(client);
    }
}
