/*
 * service.h - internal declarations shared across VulnSvc translation units.
 */
#ifndef VULNSVC_SERVICE_H
#define VULNSVC_SERVICE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN   /* winsock2.h must win over the legacy winsock.h */
#endif
#include <winsock2.h>
#include <stdint.h>
#include "protocol.h"

#define MAX_USERNAME   32
#define SESSION_TOKEN  16

/*
 * Per-connection state. Note that `authenticated` gates the vulnerable
 * handler, so an attacker must send a valid OP_AUTH first. This is the
 * "authentication/session noise" that makes triage realistic - the bug is
 * not reachable from an unauthenticated cold packet.
 */
typedef struct _Client {
    SOCKET   sock;
    int      authenticated;
    char     username[MAX_USERNAME];
    uint8_t  token[SESSION_TOKEN];
    uint32_t requests_handled;
    uint32_t bytes_in;
    uint32_t bytes_out;
    int      trace;                 /* per-connection verbose logging       */
} Client;

/* net.c ------------------------------------------------------------------ */
int  net_recv_all(SOCKET s, void *buf, int len);
int  net_send_all(SOCKET s, const void *buf, int len);
int  net_read_header(Client *c, PACKET_HEADER *hdr);
int  net_read_body(Client *c, const PACKET_HEADER *hdr, uint8_t *body);
int  send_status(Client *c, uint16_t status, const char *msg);
int  send_error(Client *c, const char *msg);

/* dispatch.c ------------------------------------------------------------- */
int  dispatch_request(Client *c, const PACKET_HEADER *hdr, uint8_t *body);
void connection_loop(Client *c);

/* handlers.c ------------------------------------------------------------- */
int  handle_ping(Client *c);
int  handle_auth(Client *c, const uint8_t *body, uint32_t body_len);
int  handle_status(Client *c, const uint8_t *body, uint32_t body_len);
int  handle_config_get(Client *c, const uint8_t *body, uint32_t body_len);
int  handle_config_set(Client *c, const uint8_t *body, uint32_t body_len); /* VULN */
int  handle_log_upload(Client *c, const uint8_t *body, uint32_t body_len);
int  handle_compress(Client *c, const uint8_t *body, uint32_t body_len);
int  handle_stats(Client *c);

/* parser.c --------------------------------------------------------------- */
int  parse_status_query(const char *body);                 /* bounded  (safe) */
int  parse_log_upload(const char *body, size_t len);       /* checked  (safe) */
int  parse_config_set(const char *body);                   /* UNBOUNDED (bug) */
int  parse_auth_line(const char *body, char *user_out, size_t user_cap);

/* config.c --------------------------------------------------------------- */
int         config_set(const char *key, const char *value);
const char *config_get(const char *key);
void        config_init(void);

/* logging.c -------------------------------------------------------------- */
void log_init(const char *path);
void log_msg(const char *level, const char *fmt, ...);
void log_hex(const char *label, const uint8_t *data, size_t len);

/* globals (main.c) ------------------------------------------------------- */
extern volatile long g_total_requests;
extern volatile long g_total_connections;

#endif /* VULNSVC_SERVICE_H */
