/*
 * handlers.c - one function per opcode.
 *
 * Triage map (this is what the analyst is trying to reconstruct):
 *
 *   handle_ping         no input           safe
 *   handle_auth         bounded copy       safe (but GATES the vuln)
 *   handle_status       -> parse_status_query()   bounded %63s   safe
 *   handle_config_get   table lookup       safe
 *   handle_config_set   -> parse_config_set()     UNBOUNDED %s   *** BUG ***
 *   handle_log_upload   -> parse_log_upload()     length-checked memcpy  safe
 *   handle_compress     round-trips DLL     safe
 *   handle_stats        counters only       safe
 *
 * The bug is reachable only via OP_CONFIG_SET AND only after a successful
 * OP_AUTH. Everything else is there to make triage feel like real software.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "service.h"
#include "protocol.h"

__declspec(dllimport) unsigned long ComputeChecksum(const unsigned char *data, unsigned long len);
__declspec(dllimport) int           Compress(const unsigned char *in, unsigned long in_len,
                                             unsigned char *out, unsigned long *out_len);

/* ---- OP_PING ---------------------------------------------------------- */
int handle_ping(Client *c)
{
    return send_status(c, ST_OK, "pong");
}

/* ---- OP_AUTH ---------------------------------------------------------- */
/*
 * Body format: "USER <name>\n" (name up to 31 chars). Any non-empty username
 * is accepted - this is a lab, not an authentication system. The point is that
 * the vulnerable handler will not run until this flips c->authenticated.
 */
int handle_auth(Client *c, const uint8_t *body, uint32_t body_len)
{
    char user[MAX_USERNAME];
    (void)body_len;

    if (parse_auth_line((const char *)body, user, sizeof(user)) != 0)
        return send_status(c, ST_BAD_REQUEST, "expected: USER <name>");

    strncpy(c->username, user, MAX_USERNAME - 1);
    c->username[MAX_USERNAME - 1] = '\0';
    c->authenticated = 1;

    /* Derive a throwaway session token from the username + a counter. */
    {
        unsigned long h = ComputeChecksum((const unsigned char *)c->username,
                                          (unsigned long)strlen(c->username));
        int i;
        for (i = 0; i < SESSION_TOKEN; i++)
            c->token[i] = (uint8_t)((h >> ((i % 4) * 8)) ^ (i * 0x1b));
    }

    log_msg("INFO", "auth ok for '%s'", c->username);
    return send_status(c, ST_OK, "authenticated");
}

/* ---- OP_STATUS -------------------------------------------------------- */
int handle_status(Client *c, const uint8_t *body, uint32_t body_len)
{
    (void)body_len;
    if (parse_status_query((const char *)body) != 0)
        return send_status(c, ST_BAD_REQUEST, "expected: module=<name>");
    return send_status(c, ST_OK, "running");
}

/* ---- OP_CONFIG_GET ---------------------------------------------------- */
int handle_config_get(Client *c, const uint8_t *body, uint32_t body_len)
{
    char key[64];
    const char *val;
    (void)body_len;

    /* Bounded read - width-limited copy into a local, then a table lookup. */
    if (sscanf((const char *)body, "get %63s", key) != 1)
        return send_status(c, ST_BAD_REQUEST, "expected: get <key>");

    val = config_get(key);
    if (!val)
        return send_status(c, ST_NOT_FOUND, "no such key");
    return send_status(c, ST_OK, val);
}

/* ---- OP_CONFIG_SET  ***  THE VULNERABLE PATH  *** --------------------- */
/*
 * The handler itself looks innocuous: check auth, hand the body to a parser.
 * The unbounded copy lives one call deeper, in parse_config_set(). This is
 * deliberate: the dispatcher and handler do not reveal the bug. You have to
 * follow the bytes into the parser.
 */
int handle_config_set(Client *c, const uint8_t *body, uint32_t body_len)
{
    (void)body_len;

    if (!c->authenticated)
        return send_status(c, ST_NOAUTH, "not authenticated");

    if (parse_config_set((const char *)body) != 0)
        return send_status(c, ST_BAD_REQUEST, "expected: set <key> <value>");

    return send_status(c, ST_OK, "config updated");
}

/* ---- OP_LOG_UPLOAD ---------------------------------------------------- */
/* Looks dangerous (a memcpy of attacker bytes), is actually safe: the parser
 * length-checks before copying. A classic "suspicious but safe" dead end. */
int handle_log_upload(Client *c, const uint8_t *body, uint32_t body_len)
{
    if (parse_log_upload((const char *)body, (size_t)body_len) != 0)
        return send_status(c, ST_BAD_REQUEST, "log too large");
    return send_status(c, ST_OK, "log stored");
}

/* ---- OP_COMPRESS ------------------------------------------------------ */
int handle_compress(Client *c, const uint8_t *body, uint32_t body_len)
{
    static __declspec(thread) uint8_t out[VULNSVC_MAX_BODY];
    unsigned long out_len = sizeof(out);
    char summary[64];

    if (Compress(body, body_len, out, &out_len) != 0)
        return send_status(c, ST_INTERNAL, "compress failed");

    _snprintf(summary, sizeof(summary) - 1, "in=%lu out=%lu",
              (unsigned long)body_len, out_len);
    summary[sizeof(summary) - 1] = '\0';
    return send_status(c, ST_OK, summary);
}

/* ---- OP_STATS --------------------------------------------------------- */
int handle_stats(Client *c)
{
    char line[96];
    _snprintf(line, sizeof(line) - 1,
              "conns=%ld reqs=%ld in=%u out=%u",
              g_total_connections, g_total_requests, c->bytes_in, c->bytes_out);
    line[sizeof(line) - 1] = '\0';
    return send_status(c, ST_OK, line);
}
