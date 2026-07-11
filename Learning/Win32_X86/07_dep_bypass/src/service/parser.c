/*
 * parser.c - three parsers that look alike and behave differently.
 *
 * This file is the whole point of the "Follow Bytes, Not Function Names"
 * lesson. All three take attacker-controlled bytes. Two are safe. One is not.
 * You cannot tell which by grepping for sscanf/memcpy - you have to read the
 * field widths and the length checks.
 *
 *   parse_status_query()  sscanf "module=%63s"    WIDTH-LIMITED   -> safe
 *   parse_log_upload()    memcpy after len check   BOUNDED         -> safe
 *   parse_config_set()    sscanf "set %s %s"       NO WIDTH        -> BUG
 */

#define WIN32_LEAN_AND_MEAN   /* service.h pulls winsock2.h; keep windows.h from
                                 dragging in the conflicting Winsock 1 headers */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "service.h"

/* ---------------------------------------------------------------- safe -- */
/*
 * Looks like the classic vulnerable pattern (sscanf %s into a stack buffer),
 * but the conversion is width-limited to 63 chars for a 64-byte buffer. The
 * NUL always fits. Reject this as a candidate.
 */
int parse_status_query(const char *body)
{
    char module[64];

    if (sscanf(body, "module=%63s", module) != 1)
        return -1;

    log_msg("DEBUG", "status query for module '%s'", module);
    return 0;
}

/* ---------------------------------------------------------------- safe -- */
/*
 * Looks dangerous: a memcpy of attacker bytes into a fixed stack buffer. But
 * the length is checked against the destination size FIRST, and the copy is
 * capped. Reject this too.
 */
int parse_log_upload(const char *body, size_t len)
{
    char log_name[128];

    if (len >= sizeof(log_name))          /* the check that saves it */
        return -1;

    memcpy(log_name, body, len);
    log_name[len] = '\0';

    log_msg("DEBUG", "log upload named '%s' (%u bytes)",
            log_name, (unsigned)len);
    return 0;
}

/* ----------------------------------------------------------------- BUG -- */
/*
 * The real vulnerability.
 *
 *   - `body` is fully attacker-controlled (from the OP_CONFIG_SET body).
 *   - The format string uses %s with NO field width.
 *   - The destinations are fixed-size STACK buffers.
 *
 * sscanf will happily write past `value` (and `name`, and `command`) until it
 * hits whitespace or NUL in the input. A long third token therefore smashes
 * the saved return address of parse_config_set().
 *
 * Because the buffers are consumed by %s, the exploit's overflow string cannot
 * contain any byte that terminates a %s token: 0x00 (NUL), 0x20 (space),
 * 0x09/0x0a/0x0b/0x0c/0x0d (whitespace). That is the bad-character set.
 *
 * Note the ordering: `value` is declared last and is the token that overflows.
 * The exact offset from the start of `value`'s token to the saved return
 * address is what you recover with a cyclic pattern - do not assume it, the
 * compiler chooses the frame layout.
 */
int parse_config_set(const char *body)
{
    char command[32];
    char name[64];
    char value[256];

    /* No width specifiers. This is the entire bug. */
    if (sscanf(body, "%31s %63s %s", command, name, value) != 3)
        return -1;

    /* Only "set" is a valid command, but by the time we check, the overflow
     * has already happened inside sscanf. The check is theatre. */
    if (strcmp(command, "set") != 0)
        return -1;

    return config_set(name, value);
}

/* ------------------------------------------------------------- helper -- */
/* Bounded auth-line parse used by handle_auth. Safe. */
int parse_auth_line(const char *body, char *user_out, size_t user_cap)
{
    char fmt[16];
    /* Build a width-limited "%<cap-1>s" format so the copy can never overflow.
     * e.g. cap 32 -> "USER %31s". */
    _snprintf(fmt, sizeof(fmt) - 1, "USER %%%us", (unsigned)(user_cap - 1));
    fmt[sizeof(fmt) - 1] = '\0';

    if (sscanf(body, fmt, user_out) != 1)
        return -1;
    if (user_out[0] == '\0')
        return -1;
    return 0;
}
