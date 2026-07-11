/*
 * dispatch.c - the opcode router and the per-connection request loop.
 *
 * This is the file a triager reads first: it tells you which opcodes exist and
 * which handlers they reach. Most opcodes are safe. Exactly one path
 * (OP_CONFIG_SET, and only after OP_AUTH) reaches the vulnerable parser.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "service.h"
#include "protocol.h"

/* Optional decompression of the body when FLAG_COMPRESSED is set. This is more
 * "realistic control flow" - a red herring for the analyst, since the
 * decompressed output still flows into the same handlers. */
__declspec(dllimport) int Decompress(const unsigned char *in, unsigned long in_len,
                                     unsigned char *out, unsigned long *out_len);

int dispatch_request(Client *c, const PACKET_HEADER *hdr, uint8_t *body)
{
    InterlockedIncrement(&g_total_requests);
    c->requests_handled++;

    if (hdr->flags & FLAG_TRACE)
        c->trace = 1;

    if (c->trace)
        log_hex("body", body, hdr->body_len);

    switch (hdr->opcode) {
    case OP_PING:
        return handle_ping(c);

    case OP_AUTH:
        return handle_auth(c, body, hdr->body_len);

    case OP_STATUS:
        return handle_status(c, body, hdr->body_len);

    case OP_CONFIG_GET:
        return handle_config_get(c, body, hdr->body_len);

    case OP_CONFIG_SET:
        /* Reachable, but handler enforces c->authenticated first. */
        return handle_config_set(c, body, hdr->body_len);

    case OP_LOG_UPLOAD:
        return handle_log_upload(c, body, hdr->body_len);

    case OP_COMPRESS:
        return handle_compress(c, body, hdr->body_len);

    case OP_STATS:
        return handle_stats(c);

    case OP_QUIT:
        return -1;   /* signal the loop to close */

    default:
        return send_status(c, ST_NOT_FOUND, "unknown opcode");
    }
}

void connection_loop(Client *c)
{
    /* One heap body buffer per connection, sized to the transport cap plus a
     * NUL slot. The overflow does NOT happen here - body is heap, large, and
     * bounds-checked on the wire. It happens when a handler copies from `body`
     * into a small STACK buffer without a width limit. */
    uint8_t *body = (uint8_t *)malloc(VULNSVC_MAX_BODY + 1);
    if (!body)
        return;

    for (;;) {
        PACKET_HEADER hdr;

        if (net_read_header(c, &hdr) != 0)
            break;
        if (net_read_body(c, &hdr, body) != 0)
            break;

        if (hdr.flags & FLAG_COMPRESSED) {
            /* Decompress in place into a scratch buffer, then continue. */
            static __declspec(thread) uint8_t scratch[VULNSVC_MAX_BODY + 1];
            unsigned long out_len = VULNSVC_MAX_BODY;
            if (Decompress(body, hdr.body_len, scratch, &out_len) == 0) {
                memcpy(body, scratch, out_len);
                body[out_len] = '\0';
                ((PACKET_HEADER *)&hdr)->body_len = out_len;
            }
        }

        if (dispatch_request(c, &hdr, body) < 0)
            break;
    }

    free(body);
}
