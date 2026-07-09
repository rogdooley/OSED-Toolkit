/*
 * logging.c - append-only text log + a hex dumper. Pure noise for the analyst,
 * but it uses stack buffers with snprintf and width limits, so it is a good
 * example of "uses sprintf-family safely" that should be dismissed during
 * triage.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "service.h"

static FILE           *g_logf = NULL;
static CRITICAL_SECTION g_log_lock;
static int             g_log_ready = 0;

void log_init(const char *path)
{
    if (g_log_ready)
        return;
    InitializeCriticalSection(&g_log_lock);
    g_logf = fopen(path, "a");
    g_log_ready = 1;
}

void log_msg(const char *level, const char *fmt, ...)
{
    char    line[512];
    char    body[400];
    va_list ap;
    time_t  now = time(NULL);
    struct tm *tm = localtime(&now);

    va_start(ap, fmt);
    _vsnprintf(body, sizeof(body) - 1, fmt, ap);   /* width-limited: safe */
    body[sizeof(body) - 1] = '\0';
    va_end(ap);

    _snprintf(line, sizeof(line) - 1, "[%02d:%02d:%02d] %-5s %s\n",
              tm ? tm->tm_hour : 0, tm ? tm->tm_min : 0, tm ? tm->tm_sec : 0,
              level, body);
    line[sizeof(line) - 1] = '\0';

    if (!g_log_ready)
        return;

    EnterCriticalSection(&g_log_lock);
    if (g_logf) {
        fputs(line, g_logf);
        fflush(g_logf);
    }
    fputs(line, stdout);
    LeaveCriticalSection(&g_log_lock);
}

void log_hex(const char *label, const uint8_t *data, size_t len)
{
    char    line[128];
    size_t  i, off = 0;

    if (len > 64)
        len = 64;   /* cap the dump */

    off += _snprintf(line, sizeof(line) - 1, "%s[%u]: ", label, (unsigned)len);
    for (i = 0; i < len && off < sizeof(line) - 3; i++)
        off += _snprintf(line + off, sizeof(line) - 1 - off, "%02x", data[i]);
    line[sizeof(line) - 1] = '\0';

    log_msg("TRACE", "%s", line);
}
