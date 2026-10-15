#include "io_helpers.h"

#include <limits.h>

static int common_set_timeout(SOCKET socket_fd, DWORD timeout_ms) {
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   sizeof(timeout_ms)) == SOCKET_ERROR) {
        return COMMON_IO_ERROR;
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   sizeof(timeout_ms)) == SOCKET_ERROR) {
        return COMMON_IO_ERROR;
    }
    return COMMON_OK;
}

int common_winsock_startup(void) {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? COMMON_OK : COMMON_IO_ERROR;
}

void common_winsock_cleanup(void) {
    WSACleanup();
}

int common_recv_exact(SOCKET socket_fd, uint8_t *buffer, size_t length, DWORD timeout_ms) {
    size_t received = 0;
    int result;

    if ((buffer == NULL && length != 0) || common_set_timeout(socket_fd, timeout_ms) != COMMON_OK) {
        return COMMON_INVALID_ARGUMENT;
    }
    while (received < length) {
        size_t remaining = length - received;
        int request = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        result = recv(socket_fd, (char *)buffer + received, request, 0);
        if (result == 0) {
            return COMMON_IO_ERROR;
        }
        if (result == SOCKET_ERROR) {
            return WSAGetLastError() == WSAETIMEDOUT ? COMMON_TIMEOUT : COMMON_IO_ERROR;
        }
        received += (size_t)result;
    }
    return COMMON_OK;
}

int common_send_all(SOCKET socket_fd, const uint8_t *buffer, size_t length, DWORD timeout_ms) {
    size_t sent = 0;
    int result;

    if ((buffer == NULL && length != 0) || common_set_timeout(socket_fd, timeout_ms) != COMMON_OK) {
        return COMMON_INVALID_ARGUMENT;
    }
    while (sent < length) {
        size_t remaining = length - sent;
        int request = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        result = send(socket_fd, (const char *)buffer + sent, request, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return WSAGetLastError() == WSAETIMEDOUT ? COMMON_TIMEOUT : COMMON_IO_ERROR;
        }
        sent += (size_t)result;
    }
    return COMMON_OK;
}

int common_read_file_all(const wchar_t *path, uint8_t **out, size_t *out_len, size_t max_len) {
    HANDLE file;
    LARGE_INTEGER file_size;
    DWORD bytes_read = 0;
    uint8_t *buffer;

    if (path == NULL || out == NULL || out_len == NULL) {
        return COMMON_INVALID_ARGUMENT;
    }
    *out = NULL;
    *out_len = 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return COMMON_IO_ERROR;
    }
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)max_len ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)MAXDWORD) {
        CloseHandle(file);
        return COMMON_LIMIT_EXCEEDED;
    }
    buffer = (uint8_t *)HeapAlloc(GetProcessHeap(), 0,
                                  file_size.QuadPart == 0 ? 1 : (SIZE_T)file_size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        return COMMON_IO_ERROR;
    }
    if (file_size.QuadPart != 0 &&
        (!ReadFile(file, buffer, (DWORD)file_size.QuadPart, &bytes_read, NULL) ||
         bytes_read != (DWORD)file_size.QuadPart)) {
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(file);
        return COMMON_IO_ERROR;
    }
    CloseHandle(file);
    *out = buffer;
    *out_len = (size_t)file_size.QuadPart;
    return COMMON_OK;
}

void common_free_file_buffer(uint8_t *buffer) {
    if (buffer != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
}
