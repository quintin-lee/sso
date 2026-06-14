#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;
static FILE *g_fp = NULL;

void log_set_level(log_level_t level) {
    g_level = level;
}

void log_set_file(FILE *fp) {
    g_fp = fp;
}

static const char *level_name(log_level_t l) {
    switch (l) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "?";
    }
}

void log_write(log_level_t level, const char *file, int line,
               int saved_errno, const char *fmt, ...) {
    if (level < g_level) return;

    FILE *out = g_fp ? g_fp : stderr;

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

    fprintf(out, "[%s] [%s] [%s:%d] ", timebuf, level_name(level), file, line);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    if (saved_errno != 0 && level >= LOG_WARN) {
        fprintf(out, " (errno=%d: %s)", saved_errno, strerror(saved_errno));
    }

    fprintf(out, "\n");
    fflush(out);
}
