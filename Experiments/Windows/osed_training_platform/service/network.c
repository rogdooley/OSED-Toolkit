#include "service.h"

#include <stdio.h>
#include <string.h>
#include <ws2tcpip.h>

static int recv_exact(SOCKET client, unsigned char *buffer, size_t need)
{
    size_t got = 0;

    while (got < need) {
        int rc = recv(client, (char *)buffer + got, (int)(need - got), 0);
        if (rc <= 0) {
            return -1;
        }
        got += (size_t)rc;
    }

    return 0;
}

static int recv_frame(SOCKET client, unsigned char *buffer, size_t buffer_size, size_t *frame_len)
{
    OSEDTP_FRAME_HEADER header;

    if (recv_exact(client, (unsigned char *)&header, sizeof(header)) != 0) {
        return -1;
    }

    if (header.total_length > buffer_size) {
        service_log_warn("network", "frame too large: %u", (unsigned)header.total_length);
        return -1;
    }

    memcpy(buffer, &header, sizeof(header));

    if (header.total_length > sizeof(header)) {
        if (recv_exact(client,
                       buffer + sizeof(header),
                       header.total_length - sizeof(header)) != 0) {
            return -1;
        }
    }

    *frame_len = header.total_length;
    return 0;
}

extern int service_dispatch_frame(SOCKET client, OSEDTP_SESSION *session, const OSEDTP_PARSED_FRAME *frame);

static int serve_client(SOCKET client, const OSEDTP_SERVICE_CONFIG *cfg)
{
    unsigned char buffer[OSEDTP_MAX_FRAME];
    OSEDTP_SESSION session;

    (void)cfg;
    service_session_init(&session);

    for (;;) {
        OSEDTP_PARSED_FRAME frame;
        char reason[64];
        size_t frame_len = 0;

        memset(&frame, 0, sizeof(frame));
        if (recv_frame(client, buffer, sizeof(buffer), &frame_len) != 0) {
            return 0;
        }

        if (osedtp_parse_frame(buffer, frame_len, &frame, reason, sizeof(reason)) != 0) {
            service_log_warn("protocol", "reject: %s", reason);
            return -1;
        }

        session.request_count++;
        if (service_dispatch_frame(client, &session, &frame) != 0) {
            return -1;
        }
    }
}

int service_run(const OSEDTP_SERVICE_CONFIG *cfg)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    SOCKET listen_sock = INVALID_SOCKET;
    WSADATA wsa;

    if (!cfg) {
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        service_log_error("network", "WSAStartup failed");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(cfg->bind_ip, NULL, &hints, &result) != 0) {
        service_log_error("network", "getaddrinfo failed");
        WSACleanup();
        return -1;
    }

    listen_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listen_sock == INVALID_SOCKET) {
        service_log_error("network", "socket failed");
        freeaddrinfo(result);
        WSACleanup();
        return -1;
    }

    {
        struct sockaddr_in addr;
        int reuse = 1;

        memcpy(&addr, result->ai_addr, sizeof(addr));
        addr.sin_port = htons(cfg->bind_port);

        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

        if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            service_log_error("network", "bind failed");
            closesocket(listen_sock);
            freeaddrinfo(result);
            WSACleanup();
            return -1;
        }
    }

    freeaddrinfo(result);

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        service_log_error("network", "listen failed");
        closesocket(listen_sock);
        WSACleanup();
        return -1;
    }

    service_log_info("network", "%s listening on %s:%u",
                     cfg->service_name,
                     cfg->bind_ip,
                     (unsigned)cfg->bind_port);

    for (;;) {
        SOCKET client = accept(listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) {
            service_log_warn("network", "accept failed");
            continue;
        }

        service_log_info("network", "client connected");
        (void)serve_client(client, cfg);
        closesocket(client);
        service_log_info("network", "client closed");
    }

    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
