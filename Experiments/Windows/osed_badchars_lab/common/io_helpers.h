#pragma once

#include <stddef.h>
#include <stdint.h>

#include <winsock2.h>
#include <windows.h>

enum common_status {
    COMMON_OK = 0,
    COMMON_INVALID_ARGUMENT = 1,
    COMMON_TIMEOUT = 2,
    COMMON_IO_ERROR = 3,
    COMMON_LIMIT_EXCEEDED = 4,
};

int common_winsock_startup(void);
void common_winsock_cleanup(void);
int common_recv_exact(SOCKET socket_fd, uint8_t *buffer, size_t length, DWORD timeout_ms);
int common_send_all(SOCKET socket_fd, const uint8_t *buffer, size_t length, DWORD timeout_ms);
int common_read_file_all(const wchar_t *path, uint8_t **out, size_t *out_len, size_t max_len);
void common_free_file_buffer(uint8_t *buffer);
