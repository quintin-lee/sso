#include "arena.h"
#include <stdlib.h>
#include <string.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

void arena_init(arena_t *arena, size_t default_block_size) {
    if (!arena) return;
    arena->first = NULL;
    arena->current = NULL;
    arena->default_block_size = default_block_size > 0 ? default_block_size : 4096;
}

static arena_block_t *create_block(size_t size) {
    arena_block_t *block = (arena_block_t *)malloc(sizeof(arena_block_t) + size);
    if (!block) return NULL;
    block->next = NULL;
    block->capacity = size;
    block->used = 0;
    return block;
}

void *arena_alloc(arena_t *arena, size_t size) {
    if (!arena || size == 0) return NULL;
    
    size = ALIGN(size);
    
    // Check if current block has enough space
    if (arena->current && (arena->current->capacity - arena->current->used >= size)) {
        void *ptr = &arena->current->data[arena->current->used];
        arena->current->used += size;
        return ptr;
    }
    
    // Allocate a new block
    size_t block_size = size > arena->default_block_size ? size : arena->default_block_size;
    arena_block_t *block = create_block(block_size);
    if (!block) return NULL;
    
    if (!arena->first) {
        arena->first = block;
    } else {
        arena->current->next = block;
    }
    arena->current = block;
    
    void *ptr = &block->data[block->used];
    block->used += size;
    return ptr;
}

void *arena_calloc(arena_t *arena, size_t num, size_t size) {
    size_t total = num * size;
    void *ptr = arena_alloc(arena, total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void *arena_realloc(arena_t *arena, void *ptr, size_t old_size, size_t new_size) {
    if (!arena) return NULL;
    if (!ptr) return arena_alloc(arena, new_size);
    if (new_size == 0) return NULL;
    
    new_size = ALIGN(new_size);
    old_size = ALIGN(old_size);
    
    // If this is the last allocation in the current block, we might be able to grow it in-place
    if (arena->current && ptr == (void *)&arena->current->data[arena->current->used - old_size]) {
        size_t diff = new_size - old_size;
        if (new_size <= old_size) {
            // shrink in-place
            arena->current->used -= (old_size - new_size);
            return ptr;
        } else if (arena->current->capacity - arena->current->used >= diff) {
            // grow in-place
            arena->current->used += diff;
            return ptr;
        }
    }
    
    // Allocate new space and copy
    void *new_ptr = arena_alloc(arena, new_size);
    if (new_ptr) {
        memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
    }
    return new_ptr;
}

char *arena_strdup(arena_t *arena, const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char *dup = (char *)arena_alloc(arena, len + 1);
    if (dup) {
        memcpy(dup, str, len + 1);
    }
    return dup;
}

void arena_destroy(arena_t *arena) {
    if (!arena) return;
    arena_block_t *block = arena->first;
    while (block) {
        arena_block_t *next = block->next;
        free(block);
        block = next;
    }
    arena->first = NULL;
    arena->current = NULL;
}
