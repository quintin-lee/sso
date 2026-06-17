#ifndef SSO_ARENA_H
#define SSO_ARENA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct arena_block {
    struct arena_block *next;
    size_t capacity;
    size_t used;
    uint8_t data[];
} arena_block_t;

typedef struct {
    arena_block_t *first;
    arena_block_t *current;
    size_t default_block_size;
} arena_t;

void  arena_init(arena_t *arena, size_t default_block_size);
void *arena_alloc(arena_t *arena, size_t size);
void *arena_calloc(arena_t *arena, size_t num, size_t size);
void *arena_realloc(arena_t *arena, void *ptr, size_t old_size, size_t new_size);
char *arena_strdup(arena_t *arena, const char *str);
void  arena_destroy(arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* SSO_ARENA_H */
