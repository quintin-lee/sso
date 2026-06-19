#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;
static FILE *g_fp = NULL;
static log_format_t g_format = LOG_FORMAT_TEXT;

void log_set_level(log_level_t level) {
    g_level = level;
}

void log_set_format(log_format_t fmt) {
    g_format = fmt;
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

/* Escape a string for JSON output.  buf must be at least len*2+1 bytes. */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 6 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = '"'; } break;
            case '\\': if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = '\\'; } break;
            case '\b':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'b'; } break;
            case '\f':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'f'; } break;
            case '\n':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'n'; } break;
            case '\r':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'r'; } break;
            case '\t':  if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 't'; } break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    if (j + 1 < dst_size) dst[j++] = (char)c;
                } else {
                    if (j + 6 < dst_size) {
                        snprintf(dst + j, 7, "\\u%04x", c);
                        j += 6;
                    }
                }
        }
    }
    dst[j] = '\0';
}

void log_write(log_level_t level, const char *file, int line,
               int saved_errno, const char *fmt, ...) {
    if (level < g_level) return;

    FILE *out = g_fp ? g_fp : stderr;

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    const struct tm *tm = localtime(&ts.tv_sec);

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

    if (g_format == LOG_FORMAT_JSON) {
        /* JSON format: {"timestamp":"...","level":"...","file":"...","line":N,"message":"..."} */
        va_list ap;
        va_start(ap, fmt);
        char msg_raw[4096];
        vsnprintf(msg_raw, sizeof(msg_raw), fmt, ap);
        va_end(ap);

        char msg_esc[8192];
        json_escape(msg_raw, msg_esc, sizeof(msg_esc));

        char file_esc[512];
        json_escape(file, file_esc, sizeof(file_esc));

        fprintf(out, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"file\":\"%s\",\"line\":%d,\"message\":\"%s\"",
                timebuf, level_name(level), file_esc, line, msg_esc);

        if (saved_errno != 0 && level >= LOG_WARN) {
            fprintf(out, ",\"errno\":%d,\"errno_str\":\"%s\"", saved_errno, strerror(saved_errno));
        }
        fprintf(out, "}\n");
    } else {
        /* Text format (default) */
        fprintf(out, "[%s] [%s] [%s:%d] ", timebuf, level_name(level), file, line);

        va_list ap;
        va_start(ap, fmt);
        vfprintf(out, fmt, ap);
        va_end(ap);

        if (saved_errno != 0 && level >= LOG_WARN) {
            fprintf(out, " (errno=%d: %s)", saved_errno, strerror(saved_errno));
        }

        fprintf(out, "\n");
    }
    fflush(out);
}
