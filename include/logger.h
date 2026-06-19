#ifndef SSO_LOGGER_H
#define SSO_LOGGER_H

#include <stdio.h>
#include <errno.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} log_level_t;

typedef enum {
    LOG_FORMAT_TEXT = 0,
    LOG_FORMAT_JSON = 1
} log_format_t;

void log_set_level(log_level_t level);
void log_set_format(log_format_t fmt);
void log_set_file(FILE *fp);
void log_write(log_level_t level, const char *file, int line,
               int saved_errno, const char *fmt, ...);

#define LOG_DEBUG(...)  do { int _e = errno; log_write(LOG_DEBUG, __FILE__, __LINE__, _e, __VA_ARGS__); } while(0)
#define LOG_INFO(...)   do { int _e = errno; log_write(LOG_INFO,  __FILE__, __LINE__, _e, __VA_ARGS__); } while(0)
#define LOG_WARN(...)   do { int _e = errno; log_write(LOG_WARN,  __FILE__, __LINE__, _e, __VA_ARGS__); } while(0)
#define LOG_ERROR(...)  do { int _e = errno; log_write(LOG_ERROR, __FILE__, __LINE__, _e, __VA_ARGS__); } while(0)

#endif /* SSO_LOGGER_H */
