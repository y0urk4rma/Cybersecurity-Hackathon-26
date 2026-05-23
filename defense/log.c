#include "hollow_detect.h"
#include <stdarg.h>
#include <time.h>

static void log_write(ENGINE_CONTEXT *ctx,
                      const char *level,
                      const char *color,
                      const char *reset,
                      const char *fmt,
                      va_list args)
{
    /* timestamp */
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);

    /* console */
    fprintf(stdout, "%s[%s][%s]%s ", color, timebuf, level, reset);
    vfprintf(stdout, fmt, args);
    fputc('\n', stdout);

    /* log file */
    if (ctx && ctx->logFile) {
        fprintf(ctx->logFile, "[%s][%s] ", timebuf, level);
        va_list args2;
        va_copy(args2, args);
        vfprintf(ctx->logFile, fmt, args2);
        va_end(args2);
        fputc('\n', ctx->logFile);
        fflush(ctx->logFile);
    }
}

void log_info(ENGINE_CONTEXT *ctx, const char *fmt, ...)
{
    va_list a; va_start(a, fmt);
    log_write(ctx, "INFO ", "\033[36m", "\033[0m", fmt, a);
    va_end(a);
}

void log_warn(ENGINE_CONTEXT *ctx, const char *fmt, ...)
{
    va_list a; va_start(a, fmt);
    log_write(ctx, "WARN ", "\033[33m", "\033[0m", fmt, a);
    va_end(a);
}

void log_error(ENGINE_CONTEXT *ctx, const char *fmt, ...)
{
    va_list a; va_start(a, fmt);
    log_write(ctx, "ERROR", "\033[31m", "\033[0m", fmt, a);
    va_end(a);
}

void log_debug(ENGINE_CONTEXT *ctx, const char *fmt, ...)
{
    if (!ctx || !ctx->verbose) return;
    va_list a; va_start(a, fmt);
    log_write(ctx, "DEBUG", "\033[90m", "\033[0m", fmt, a);
    va_end(a);
}
