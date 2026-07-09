#include "service.h"

#include <stdarg.h>
#include <stdio.h>

static void log_emit(const char *level, const char *tag, const char *fmt, va_list ap)
{
    if (!tag) {
        tag = "service";
    }

    printf("[%s][%s] ", level, tag);
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
}

void service_log_info(const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_emit("info", tag, fmt, ap);
    va_end(ap);
}

void service_log_warn(const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_emit("warn", tag, fmt, ap);
    va_end(ap);
}

void service_log_error(const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_emit("error", tag, fmt, ap);
    va_end(ap);
}
