#ifndef SSO_ARENA_H
#define SSO_ARENA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct arena_block
 * @brief Represents a single contiguous block of memory in the arena.
 * 
 * Each block contains a header and a flexible array member for the payload.
 * Blocks are linked together in a singly linked list.
 */
typedef struct arena_block {
    struct arena_block *next;       /**< Pointer to the next block in the chain */
    size_t capacity;                /**< Total capacity of the data buffer in bytes */
    size_t used;                    /**< Number of bytes allocated from this block */
    uint8_t data[];                 /**< Flexible array member holding the raw data buffer */
} arena_block_t;

/**
 * @struct arena_t
 * @brief Context structure managing the arena memory pool.
 * 
 * Tracks the linked list of blocks and records the default block size for
 * new allocations.
 */
typedef struct {
    arena_block_t *first;           /**< Pointer to the first block in the arena */
    arena_block_t *current;         /**< Pointer to the currently active block for allocations */
    size_t default_block_size;      /**< Default capacity for newly allocated blocks */
} arena_t;

/**
 * @brief Initializes the arena allocator context.
 * 
 * Sets the default block size and resets block pointers to NULL.
 * No memory blocks are allocated immediately; they are allocated lazily.
 * 
 * @param arena Pointer to the arena context to initialize.
 * @param default_block_size Default size for new memory blocks (falls back to 4096 if 0).
 */
void  arena_init(arena_t *arena, size_t default_block_size);

/**
 * @brief Allocates aligned memory from the arena.
 * 
 * Lazily allocates blocks if needed, matching 8-byte alignment requirements.
 * 
 * @param arena Pointer to the arena context.
 * @param size Desired allocation size in bytes.
 * @return Pointer to the allocated memory, or NULL if allocation fails.
 */
void *arena_alloc(arena_t *arena, size_t size);

/**
 * @brief Allocates and zero-initializes memory from the arena.
 * 
 * @param arena Pointer to the arena context.
 * @param num Number of elements.
 * @param size Size of each element in bytes.
 * @return Pointer to the allocated and zeroed memory, or NULL if failure.
 */
void *arena_calloc(arena_t *arena, size_t num, size_t size);

/**
 * @brief Reallocates memory in the arena.
 * 
 * Attempts to shrink or grow in-place if the pointer was the last allocation
 * in the current block. Otherwise, performs a new allocation and copies the data.
 * 
 * @param arena Pointer to the arena context.
 * @param ptr Pointer to the memory block to reallocate.
 * @param old_size Previous size of the memory block in bytes.
 * @param new_size Target size in bytes.
 * @return Pointer to the reallocated memory, or NULL if failure.
 */
void *arena_realloc(arena_t *arena, void *ptr, size_t old_size, size_t new_size);

/**
 * @brief Duplicates a string in the arena.
 * 
 * Allocates space in the arena matching the string length + NUL terminator
 * and copies the string.
 * 
 * @param arena Pointer to the arena context.
 * @param str Null-terminated string to duplicate.
 * @return Pointer to the duplicated string, or NULL if failure.
 */
char *arena_strdup(arena_t *arena, const char *str);

/**
 * @brief Destroys the arena, releasing all allocated blocks.
 * 
 * Iterates through the singly linked list of blocks, calling standard `free`
 * on each. Resets all pointers in the arena structure to NULL.
 * 
 * @param arena Pointer to the arena context.
 */
void  arena_destroy(arena_t *arena);

/**
 * @brief Resets the arena used offsets to 0, retaining allocated blocks.
 * 
 * Permits full memory reuse across requests without repeating heap allocations.
 * 
 * @param arena Pointer to the arena context.
 */
void  arena_reset(arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* SSO_ARENA_H */
