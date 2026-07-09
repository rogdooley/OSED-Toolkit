#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stddef.h>
#include <stdint.h>

#include <winsock2.h>

#include "osedtp_protocol.h"

#define OSEDTP_DEFAULT_BIND_IP "127.0.0.1"
#define OSEDTP_DEFAULT_BIND_PORT 11460u
#define OSEDTP_SESSION_NAME_MAX 64u

typedef struct OSEDTP_SERVICE_CONFIG {
    const char *bind_ip;
    uint16_t bind_port;
    const char *service_name;
    uint32_t auth_token;
} OSEDTP_SERVICE_CONFIG;

typedef struct OSEDTP_SESSION {
    int authenticated;
    uint32_t request_count;
    uint32_t auth_token;
    char client_name[OSEDTP_SESSION_NAME_MAX];
} OSEDTP_SESSION;

int service_config_load(OSEDTP_SERVICE_CONFIG *cfg);
void service_session_init(OSEDTP_SESSION *session);
int service_session_authenticate(OSEDTP_SESSION *session, uint32_t token, const char *client_name);
int service_run(const OSEDTP_SERVICE_CONFIG *cfg);
void service_log_info(const char *tag, const char *fmt, ...);
void service_log_warn(const char *tag, const char *fmt, ...);
void service_log_error(const char *tag, const char *fmt, ...);
