/*
 * logger.h — Structured logging with level filtering and JSON output.
 *
 * Provides a simple logging facade used throughout the SSO system.
 * Each log call captures __FILE__, __LINE__, and errno automatically.
 *
 * The LOG_* macros capture errno at call site; the actual log_write()
 * function formats the output as plain text ("[LEVEL] [file:line] msg")
 * or JSON ({"level":"INFO","file":"main.c","line":42,...}).
 *
 * Thread-safe: a mutex guards the output file between writes.
 */

#ifndef SSO_LOGGER_H
#define SSO_LOGGER_H

#include <stdio.h>
#include <errno.h>

/** Log severity levels, in increasing order of importance. */
typedef enum { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERROR = 3 } log_level_t;

/** Output format: plain text or structured JSON (ELK-friendly). */
typedef enum { LOG_FORMAT_TEXT = 0, LOG_FORMAT_JSON = 1 } log_format_t;

/** Override the global minimum log level (default: LOG_INFO). */
void log_set_level(log_level_t level);
/** Switch between text and JSON output format. */
void log_set_format(log_format_t fmt);
/** Redirect logging to a specific file handle (default: stderr). */
void log_set_file(FILE* fp);
/** Inject a trace/request ID into the next log_write call (thread-local). */
void log_set_request_id(const char* req_id);
/**
 * Core logging function — writes a single formatted log line.
 * @param level  Severity level.
 * @param file   Source file name (__FILE__).
 * @param line   Source line number (__LINE__).
 * @param saved_errno  errno value captured at the call site.
 * @param fmt    printf-style format string.
 */
void log_write(log_level_t level, const char* file, int line, int saved_errno, const char* fmt, ...);

/* Convenience macros — capture file/line/errno automatically. */                                                                                                 \
	do {                                                                                                               \
		int _e = errno;                                                                                                \
		log_write(LOG_DEBUG, __FILE__, __LINE__, _e, __VA_ARGS__);                                                     \
	} while (0)
#define LOG_INFO(...)                                                                                                  \
	do {                                                                                                               \
		int _e = errno;                                                                                                \
		log_write(LOG_INFO, __FILE__, __LINE__, _e, __VA_ARGS__);                                                      \
	} while (0)
#define LOG_WARN(...)                                                                                                  \
	do {                                                                                                               \
		int _e = errno;                                                                                                \
		log_write(LOG_WARN, __FILE__, __LINE__, _e, __VA_ARGS__);                                                      \
	} while (0)
#define LOG_ERROR(...)                                                                                                 \
	do {                                                                                                               \
		int _e = errno;                                                                                                \
		log_write(LOG_ERROR, __FILE__, __LINE__, _e, __VA_ARGS__);                                                     \
	} while (0)

#endif /* SSO_LOGGER_H */
