#ifndef SSO_INTERN_H
#define SSO_INTERN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the global string interning pool.
 * Should be called once during server startup.
 */
void intern_init(void);

/**
 * @brief Intern a string into the global pool.
 * If the string already exists, returns a pointer to the existing immutable string.
 * If not, duplicates it, stores it, and returns the new pointer.
 *
 * @param str The null-terminated string to intern.
 * @return const char* Pointer to the interned string, or NULL if out of memory.
 */
const char* intern_string(const char* str);

/**
 * @brief Intern a string with a known length.
 */
const char* intern_string_len(const char* str, size_t len);

/**
 * @brief Destroy the global string interning pool and free all memory.
 */
void intern_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* SSO_INTERN_H */
