#include "arena.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

extern atomic_ullong g_metric_arena_blocks;

/* Allocations are aligned to 16-byte boundaries for SIMD vectorization compatibility. */
#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

/**
 * @brief Initialize the arena memory pool allocator.
 *
 * Sets up basic block pointers. Lazily allocates the actual blocks when needed.
 */
void arena_init(arena_t* arena, size_t default_block_size) {
	if (!arena)
		return;
	arena->first   = NULL;
	arena->current = NULL;
	/* Use a sensible default of 4KB if the provided size is 0 or invalid */
	arena->default_block_size = default_block_size > 0 ? default_block_size : 4096;
}

/**
 * @brief Helper function to allocate a raw block of memory from the heap.
 *
 * Each block has a header of type `arena_block_t` followed by a payload buffer of `size` bytes.
 *
 * @param size Capacity of the new block data buffer in bytes.
 * @return Pointer to the newly allocated block, or NULL on OOM.
 */
static arena_block_t* create_block(size_t size) {
	/* Allocate the header size plus the flexible array payload data size */
	arena_block_t* block = (arena_block_t*)malloc(sizeof(arena_block_t) + size);
	if (!block)
		return NULL;
	block->next		= NULL;
	block->capacity = size;
	block->used		= 0;
	atomic_fetch_add(&g_metric_arena_blocks, 1);
	return block;
}

/**
 * @brief Allocate memory from the arena pool.
 *
 * Walks through alignment checks, grabs memory from the current block if space permits,
 * or dynamically allocates a new block if the current block is full.
 */
void* arena_alloc(arena_t* arena, size_t size) {
	if (!arena || size == 0)
		return NULL;

	/* Align the requested size to the next multiple of ALIGNMENT (8 bytes) */
	size = ALIGN(size);

	/* If the current block has enough remaining space, slice the memory out of it */
	if (arena->current && (arena->current->capacity - arena->current->used >= size)) {
		void* ptr = &arena->current->data[arena->current->used];
		arena->current->used += size;
		return ptr;
	}

	/* Fast-path for large allocations:
	 * If the requested size is substantial, we allocate a dedicated block and insert it
	 * *after* the current block, without advancing `current`. This prevents a single
	 * huge allocation from prematurely closing the active small block. */
	if (size > arena->default_block_size / 2) {
		arena_block_t* large_block = create_block(size);
		if (!large_block)
			return NULL;
		large_block->used = size;

		if (!arena->first) {
			arena->first   = large_block;
			arena->current = large_block;
		} else {
			large_block->next	 = arena->current->next;
			arena->current->next = large_block;
		}
		return large_block->data;
	}

	/* Current block is full. Can we move to the next existing block? */
	while (arena->current && arena->current->next) {
		arena->current = arena->current->next;
		if (arena->current->capacity - arena->current->used >= size) {
			void* ptr = &arena->current->data[arena->current->used];
			arena->current->used += size;
			return ptr;
		}
	}

	/* Current block is full or nonexistent. Allocate a new block. */
	size_t		   block_size = size > arena->default_block_size ? size : arena->default_block_size;
	arena_block_t* block	  = create_block(block_size);
	if (!block)
		return NULL;

	/* Append the new block to the arena's list of blocks */
	if (!arena->first) {
		arena->first = block;
	} else {
		arena->current->next = block;
	}
	arena->current = block;

	/* Allocate from the newly created block */
	void* ptr = &block->data[block->used];
	block->used += size;
	return ptr;
}

/**
 * @brief Allocate zero-initialized memory.
 */
void* arena_calloc(arena_t* arena, size_t num, size_t size) {
	size_t total = num * size;
	void*  ptr	 = arena_alloc(arena, total);
	if (ptr) {
		/* Zero out the allocated space */
		memset(ptr, 0, total);
	}
	return ptr;
}

/**
 * @brief Reallocate a block of memory, prioritizing in-place resizing.
 *
 * Provides an optimization for request body accumulators (like in-progress HTTP chunk reading):
 * if the pointer was the absolute last allocation made in the current block, we can
 * simply grow/shrink the `used` offset in-place without copying data.
 */
void* arena_realloc(arena_t* arena, void* ptr, size_t old_size, size_t new_size) {
	if (!arena)
		return NULL;
	if (!ptr)
		return arena_alloc(arena, new_size);
	if (new_size == 0)
		return NULL;

	new_size = ALIGN(new_size);
	old_size = ALIGN(old_size);

	/* Optimization: Check if this was the last allocation in the active block. */
	if (arena->current && ptr == (void*)&arena->current->data[arena->current->used - old_size]) {
		size_t diff = new_size - old_size;
		if (new_size <= old_size) {
			/* Shrinking in-place: subtract the difference from the used counter */
			arena->current->used -= (old_size - new_size);
			return ptr;
		} else if (arena->current->capacity - arena->current->used >= diff) {
			/* Growing in-place: check if we have enough spare capacity in this block */
			arena->current->used += diff;
			return ptr;
		}
	}

	/* Fallback: allocate new space, copy the contents, and leave the old block in place.
	 * The old block's space will be recovered in bulk when the arena is destroyed. */
	void* new_ptr = arena_alloc(arena, new_size);
	if (new_ptr) {
		memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
	}
	return new_ptr;
}

/**
 * @brief Duplicate a string into arena-managed memory.
 */
char* arena_strdup(arena_t* arena, const char* str) {
	if (!str)
		return NULL;
	size_t len = strlen(str);
	char*  dup = (char*)arena_alloc(arena, len + 1);
	if (dup) {
		memcpy(dup, str, len + 1);
	}
	return dup;
}

/**
 * @brief Destroy the arena and free all associated memory blocks.
 */
void arena_destroy(arena_t* arena) {
	if (!arena)
		return;
	arena_block_t* block = arena->first;
	size_t		   count = 0;
	/* Walk the linked list, freeing every individual block */
	while (block) {
		arena_block_t* next = block->next;
		free(block);
		block = next;
		count++;
	}
	arena->first   = NULL;
	arena->current = NULL;
	if (count > 0) {
		atomic_fetch_sub(&g_metric_arena_blocks, count);
	}
}

void arena_reset(arena_t* arena) {
	if (!arena)
		return;

	arena_block_t* block = arena->first;
	arena_block_t* prev	 = NULL;

	while (block) {
		arena_block_t* next = block->next;

		/* Free abnormally large blocks to prevent memory bloat / high watermark retention */
		if (block->capacity > arena->default_block_size) {
			if (prev) {
				prev->next = next;
			} else {
				arena->first = next;
			}
			free(block);
			atomic_fetch_sub(&g_metric_arena_blocks, 1);
		} else {
			block->used = 0;
			prev		= block;
		}

		block = next;
	}
	arena->current = arena->first;
}

bool arena_contains(const arena_t* arena, const void* ptr) {
	if (!arena || !ptr)
		return false;
	const uint8_t* p = (const uint8_t*)ptr;
	for (arena_block_t* block = arena->first; block; block = block->next) {
		if (p >= block->data && p < block->data + block->capacity) {
			return true;
		}
	}
	return false;
}
