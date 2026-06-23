#ifndef SSO_OTLP_H
#define SSO_OTLP_H

#include "sso.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
	char	 trace_id[33]; // 16 bytes hex (32 chars) + null
	char	 span_id[17];  // 8 bytes hex (16 chars) + null
	char	 parent_id[17];
	char	 name[64];
	uint64_t start_time_ns;
	uint64_t end_time_ns;
	int		 kind;		  // 1=INTERNAL, 2=SERVER, 3=CLIENT
	int		 status_code; // 0=UNSET, 1=OK, 2=ERROR
} otlp_span_t;

/* Initialize OTLP exporter background thread */
void otlp_init(const char* endpoint);

/* Shutdown and flush */
void otlp_shutdown(void);

/* Generate a new hex ID */
void otlp_generate_id(char* out_hex, int bytes);

/* Create a new span */
void otlp_span_start(otlp_span_t* span, const char* name, const char* parent_trace_id, const char* parent_span_id);

/* End the span and queue it for export */
void otlp_span_end(otlp_span_t* span, bool is_error);

#endif // SSO_OTLP_H
