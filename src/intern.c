#include "intern.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define INTERN_INITIAL_CAPACITY 1024

typedef struct intern_node {
	const char*			str;
	size_t				len;
	struct intern_node* next;
} intern_node_t;

static intern_node_t**	g_intern_table	  = NULL;
static size_t			g_intern_capacity = 0;
static size_t			g_intern_count	  = 0;
static pthread_rwlock_t g_intern_lock;

/* FNV-1a hash function for strings */
static size_t hash_string(const char* str, size_t len) {
	size_t hash = 14695981039346656037ULL;
	for (size_t i = 0; i < len; i++) {
		hash ^= (unsigned char)str[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

void intern_init(void) {
	pthread_rwlock_init(&g_intern_lock, NULL);
	g_intern_capacity = INTERN_INITIAL_CAPACITY;
	g_intern_table	  = calloc(g_intern_capacity, sizeof(intern_node_t*));
	g_intern_count	  = 0;
}

const char* intern_string_len(const char* str, size_t len) {
	if (!str)
		return NULL;

	size_t hash = hash_string(str, len);

	/* FAST PATH: Read lock and search */
	pthread_rwlock_rdlock(&g_intern_lock);
	size_t		   idx	= hash & (g_intern_capacity - 1); // capacity is power of 2
	intern_node_t* node = g_intern_table[idx];
	while (node) {
		if (node->len == len && memcmp(node->str, str, len) == 0) {
			const char* res = node->str;
			pthread_rwlock_unlock(&g_intern_lock);
			return res; /* Cache hit! */
		}
		node = node->next;
	}
	pthread_rwlock_unlock(&g_intern_lock);

	/* SLOW PATH: Write lock and insert */
	pthread_rwlock_wrlock(&g_intern_lock);

	/* Double check to prevent race conditions during lock escalation */
	idx	 = hash & (g_intern_capacity - 1);
	node = g_intern_table[idx];
	while (node) {
		if (node->len == len && memcmp(node->str, str, len) == 0) {
			const char* res = node->str;
			pthread_rwlock_unlock(&g_intern_lock);
			return res;
		}
		node = node->next;
	}

	/* Resize if load factor exceeds 75% */
	if (g_intern_count >= g_intern_capacity * 3 / 4) {
		size_t			new_cap	  = g_intern_capacity * 2;
		intern_node_t** new_table = calloc(new_cap, sizeof(intern_node_t*));
		if (new_table) {
			for (size_t i = 0; i < g_intern_capacity; i++) {
				intern_node_t* curr = g_intern_table[i];
				while (curr) {
					intern_node_t* next	   = curr->next;
					size_t		   new_idx = hash_string(curr->str, curr->len) & (new_cap - 1);
					curr->next			   = new_table[new_idx];
					new_table[new_idx]	   = curr;
					curr				   = next;
				}
			}
			free(g_intern_table);
			g_intern_table	  = new_table;
			g_intern_capacity = new_cap;
			idx				  = hash & (g_intern_capacity - 1);
		}
	}

	/* Allocate and copy the string */
	intern_node_t* new_node = malloc(sizeof(intern_node_t));
	if (!new_node) {
		pthread_rwlock_unlock(&g_intern_lock);
		return NULL;
	}

	char* dup = malloc(len + 1);
	if (!dup) {
		free(new_node);
		pthread_rwlock_unlock(&g_intern_lock);
		return NULL;
	}
	memcpy(dup, str, len);
	dup[len] = '\0';

	new_node->str		= dup;
	new_node->len		= len;
	new_node->next		= g_intern_table[idx];
	g_intern_table[idx] = new_node;
	g_intern_count++;

	const char* res = new_node->str;
	pthread_rwlock_unlock(&g_intern_lock);

	return res;
}

const char* intern_string(const char* str) {
	if (!str)
		return NULL;
	return intern_string_len(str, strlen(str));
}

void intern_destroy(void) {
	if (!g_intern_table)
		return;

	/* Since no read locks can be acquired after server shutdown initiates,
	 * no locking is strictly necessary here, but we'll lock for correctness. */
	pthread_rwlock_wrlock(&g_intern_lock);
	for (size_t i = 0; i < g_intern_capacity; i++) {
		intern_node_t* curr = g_intern_table[i];
		while (curr) {
			intern_node_t* next = curr->next;
			free((void*)curr->str);
			free(curr);
			curr = next;
		}
	}
	free(g_intern_table);
	g_intern_table	  = NULL;
	g_intern_capacity = 0;
	g_intern_count	  = 0;
	pthread_rwlock_unlock(&g_intern_lock);

	pthread_rwlock_destroy(&g_intern_lock);
}
