#include "otlp.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>

#define OTLP_BATCH_SIZE 128
#define OTLP_MAX_QUEUE 1024

static otlp_span_t g_span_queue[OTLP_MAX_QUEUE];
static int		   g_queue_head	 = 0;
static int		   g_queue_tail	 = 0;
static int		   g_queue_count = 0;

static pthread_mutex_t g_otlp_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_otlp_cond	= PTHREAD_COND_INITIALIZER;
static pthread_t	   g_otlp_thread;
static int			   g_otlp_running		= 0;
static char			   g_otlp_endpoint[256] = {0};

static uint64_t get_time_ns() {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void otlp_generate_id(char* out_hex, int bytes) {
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < bytes; i++) {
		int r			   = rand() % 256;
		out_hex[i * 2]	   = hex[(r >> 4) & 0x0F];
		out_hex[i * 2 + 1] = hex[r & 0x0F];
	}
	out_hex[bytes * 2] = '\0';
}

void otlp_span_start(otlp_span_t* span, const char* name, const char* parent_trace_id, const char* parent_span_id) {
	memset(span, 0, sizeof(otlp_span_t));
	if (parent_trace_id && parent_trace_id[0] != '\0') {
		strncpy(span->trace_id, parent_trace_id, 32);
	} else {
		otlp_generate_id(span->trace_id, 16);
	}
	if (parent_span_id && parent_span_id[0] != '\0') {
		strncpy(span->parent_id, parent_span_id, 16);
	}
	otlp_generate_id(span->span_id, 8);
	strncpy(span->name, name, 63);
	span->start_time_ns = get_time_ns();
	span->kind			= 2; // SERVER
	span->status_code	= 0; // UNSET
}

void otlp_span_end(otlp_span_t* span, bool is_error) {
	span->end_time_ns = get_time_ns();
	if (is_error) {
		span->status_code = 2; // ERROR
	} else {
		span->status_code = 1; // OK
	}

	if (!g_otlp_running)
		return;

	pthread_mutex_lock(&g_otlp_mutex);
	if (g_queue_count < OTLP_MAX_QUEUE) {
		g_span_queue[g_queue_tail] = *span;
		g_queue_tail			   = (g_queue_tail + 1) % OTLP_MAX_QUEUE;
		g_queue_count++;
		if (g_queue_count >= OTLP_BATCH_SIZE) {
			pthread_cond_signal(&g_otlp_cond);
		}
	} else {
		// Drop span if queue is full
		LOG_WARN("[otlp] Span queue full, dropping span %s", span->name);
	}
	pthread_mutex_unlock(&g_otlp_mutex);
}

static void send_batch(otlp_span_t* batch, int count) {
	if (count == 0 || g_otlp_endpoint[0] == '\0')
		return;

	// A real implementation would use yyjson. Here we construct a minimal JSON string for speed.
	char* payload = malloc(1024 * 1024); // 1MB max
	if (!payload)
		return;

	int pos = snprintf(payload, 1024 * 1024,
					   "{\"resourceSpans\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{"
					   "\"stringValue\":\"sso_system\"}}]},\"scopeSpans\":[{\"spans\":[");

	for (int i = 0; i < count; i++) {
		if (i > 0)
			pos += snprintf(payload + pos, 1024 * 1024 - pos, ",");
		pos += snprintf(payload + pos, 1024 * 1024 - pos,
						"{\"traceId\":\"%s\",\"spanId\":\"%s\",\"name\":\"%s\",\"kind\":%d,\"startTimeUnixNano\":\"%"
						"llu\",\"endTimeUnixNano\":\"%llu\",\"status\":{\"code\":%d}",
						batch[i].trace_id, batch[i].span_id, batch[i].name, batch[i].kind,
						(unsigned long long)batch[i].start_time_ns, (unsigned long long)batch[i].end_time_ns,
						batch[i].status_code);

		if (batch[i].parent_id[0] != '\0') {
			pos += snprintf(payload + pos, 1024 * 1024 - pos, ",\"parentSpanId\":\"%s\"", batch[i].parent_id);
		}
		pos += snprintf(payload + pos, 1024 * 1024 - pos, "}");
	}
	snprintf(payload + pos, 1024 * 1024 - pos, "]}]}]}");

	CURL* curl = curl_easy_init();
	if (curl) {
		struct curl_slist* headers = NULL;
		headers					   = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_URL, g_otlp_endpoint);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L); // 2s timeout
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			LOG_WARN("[otlp] Failed to send traces to %s: %s", g_otlp_endpoint, curl_easy_strerror(res));
		}
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}
	free(payload);
}

static void* otlp_worker(void* arg) {
	(void)arg;
	otlp_span_t batch[OTLP_BATCH_SIZE];

	while (1) {
		pthread_mutex_lock(&g_otlp_mutex);
		while (g_queue_count < OTLP_BATCH_SIZE && g_otlp_running) {
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1; // 1 second batch window
			pthread_cond_timedwait(&g_otlp_cond, &g_otlp_mutex, &ts);
		}

		int batch_count = 0;
		while (g_queue_count > 0 && batch_count < OTLP_BATCH_SIZE) {
			batch[batch_count++] = g_span_queue[g_queue_head];
			g_queue_head		 = (g_queue_head + 1) % OTLP_MAX_QUEUE;
			g_queue_count--;
		}

		int running = g_otlp_running;
		pthread_mutex_unlock(&g_otlp_mutex);

		if (batch_count > 0) {
			send_batch(batch, batch_count);
		}

		if (!running && batch_count == 0) {
			break;
		}
	}
	return NULL;
}

void otlp_init(const char* endpoint) {
	if (!endpoint || endpoint[0] == '\0')
		return;
	strncpy(g_otlp_endpoint, endpoint, sizeof(g_otlp_endpoint) - 1);

	pthread_mutex_lock(&g_otlp_mutex);
	if (!g_otlp_running) {
		g_otlp_running = 1;
		pthread_create(&g_otlp_thread, NULL, otlp_worker, NULL);
		LOG_INFO("[otlp] Initialized exporter to %s", g_otlp_endpoint);
	}
	pthread_mutex_unlock(&g_otlp_mutex);
}

void otlp_shutdown(void) {
	pthread_mutex_lock(&g_otlp_mutex);
	if (g_otlp_running) {
		g_otlp_running = 0;
		pthread_cond_signal(&g_otlp_cond);
		pthread_mutex_unlock(&g_otlp_mutex);
		pthread_join(g_otlp_thread, NULL);
		LOG_INFO("[otlp] Exporter shut down gracefully");
	} else {
		pthread_mutex_unlock(&g_otlp_mutex);
	}
}

#define OTLP_MAX_SPAN_DEPTH 16
typedef struct {
	char trace_id[33];
	char span_ids[OTLP_MAX_SPAN_DEPTH][17];
	int	 depth;
} otlp_trace_context_t;

static _Thread_local otlp_trace_context_t g_otlp_ctx = {0};

void otlp_trace_init_tls(const char* new_trace_id) {
	g_otlp_ctx.depth = 0;
	if (new_trace_id) {
		strncpy(g_otlp_ctx.trace_id, new_trace_id, 32);
		g_otlp_ctx.trace_id[32] = '\0';
	} else {
		otlp_generate_id(g_otlp_ctx.trace_id, 16);
	}
}

void otlp_span_start_tls(otlp_span_t* span, const char* name) {
	const char* parent_span = NULL;
	if (g_otlp_ctx.depth > 0 && g_otlp_ctx.depth < OTLP_MAX_SPAN_DEPTH) {
		parent_span = g_otlp_ctx.span_ids[g_otlp_ctx.depth - 1];
	}
	otlp_span_start(span, name, g_otlp_ctx.trace_id, parent_span);
	if (g_otlp_ctx.depth < OTLP_MAX_SPAN_DEPTH) {
		strncpy(g_otlp_ctx.span_ids[g_otlp_ctx.depth], span->span_id, 16);
		g_otlp_ctx.span_ids[g_otlp_ctx.depth][16] = '\0';
	}
	g_otlp_ctx.depth++;
}

void otlp_span_end_tls(otlp_span_t* span, bool is_error) {
	if (g_otlp_ctx.depth > 0) {
		g_otlp_ctx.depth--;
	}
	otlp_span_end(span, is_error);
}
