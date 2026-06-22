#include "raft_cluster.h"
#include "raft.h"
#include "logger.h"
#include "yyjson.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

struct raft_cluster_t {
	raft_server_t*	   raft;
	storage_backend_t* inner_storage;
	storage_backend_t  proxy_storage;
	sso_context_t*	   ctx;
	pthread_t		   ticker_thread;
	bool			   running;
	pthread_mutex_t	   lock;
};

static sso_error_t raft_apply_dispatch(raft_cluster_t* cluster, const char* json_str, size_t len);

static void* raft_ticker(void* arg) {
	raft_cluster_t* cluster = (raft_cluster_t*)arg;
	while (cluster->running) {
		usleep(100000); /* 100ms */
		pthread_mutex_lock(&cluster->lock);
		raft_periodic(cluster->raft, 100);
		pthread_mutex_unlock(&cluster->lock);
	}
	return NULL;
}

static int raft_send_requestvote_cb(raft_server_t* raft, void* user_data, raft_node_t* node, msg_requestvote_t* m) {
	(void)raft;
	(void)user_data;
	const char* url = (const char*)raft_node_get_udata(node);
	if (!url)
		return 0;

	/* TODO: Serialize m to JSON and POST using libcurl */
	LOG_DEBUG("Raft: Sending RequestVote to %s (term: %d, cand: %d)", url, m->term, m->candidate_id);
	return 0;
}

static int raft_send_appendentries_cb(raft_server_t* raft, void* user_data, raft_node_t* node, msg_appendentries_t* m) {
	(void)raft;
	(void)user_data;
	const char* url = (const char*)raft_node_get_udata(node);
	if (!url)
		return 0;

	/* TODO: Serialize m to JSON and POST using libcurl */
	LOG_DEBUG("Raft: Sending AppendEntries to %s (term: %d)", url, m->term);
	return 0;
}

static int raft_applylog_cb(raft_server_t* raft, void* user_data, raft_entry_t* entry, raft_index_t entry_idx) {
	(void)raft;
	raft_cluster_t* cluster = (raft_cluster_t*)user_data;
	LOG_INFO("Raft: Committing entry %ld (term: %ld)", (long)entry_idx, (long)entry->term);
	if (entry->data.buf && entry->data.len > 0) {
		raft_apply_dispatch(cluster, (const char*)entry->data.buf, entry->data.len);
	}
	return 0;
}

static int raft_persist_vote_cb(raft_server_t* raft, void* user_data, raft_node_id_t vote) {
	(void)raft;
	(void)user_data;
	(void)vote;
	return 0;
}

static int raft_persist_term_cb(raft_server_t* raft, void* user_data, raft_term_t term, raft_node_id_t vote) {
	(void)raft;
	(void)user_data;
	(void)term;
	(void)vote;
	return 0;
}

static int raft_log_offer_cb(raft_server_t* raft, void* user_data, raft_entry_t* entry, raft_index_t entry_idx) {
	(void)raft;
	(void)user_data;
	(void)entry;
	(void)entry_idx;
	return 0;
}

static int raft_log_poll_cb(raft_server_t* raft, void* user_data, raft_entry_t* entry, raft_index_t entry_idx) {
	(void)raft;
	(void)user_data;
	(void)entry;
	(void)entry_idx;
	return 0;
}

static int raft_log_pop_cb(raft_server_t* raft, void* user_data, raft_entry_t* entry, raft_index_t entry_idx) {
	(void)raft;
	(void)user_data;
	(void)entry;
	(void)entry_idx;
	return 0;
}

static sso_error_t raft_cluster_propose_and_wait(raft_cluster_t* cluster, const char* json, size_t len) {
	msg_entry_t entry = {0};
	entry.id		  = rand();
	entry.data.buf	  = (void*)json;
	entry.data.len	  = len;

	msg_entry_response_t response;

	pthread_mutex_lock(&cluster->lock);
	int e = raft_recv_entry(cluster->raft, &entry, &response);
	pthread_mutex_unlock(&cluster->lock);

	if (e != 0) {
		LOG_ERROR("Raft: Failed to append entry: %d", e);
		return SSO_ERR_STORAGE;
	}

	/* TODO: Full implementation should use a cond_var here waiting for entry response.id */
	return SSO_OK;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include "raft_generated.inc"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

sso_error_t raft_cluster_init(sso_context_t* ctx, storage_backend_t* inner_storage, raft_cluster_t** out_cluster) {
	raft_cluster_t* cluster = (raft_cluster_t*)calloc(1, sizeof(raft_cluster_t));
	if (!cluster)
		return SSO_ERR_OUT_OF_MEMORY;

	cluster->ctx		   = ctx;
	cluster->inner_storage = inner_storage;
	pthread_mutex_init(&cluster->lock, NULL);

	raft_cbs_t raft_callbacks = {.send_requestvote	 = raft_send_requestvote_cb,
								 .send_appendentries = raft_send_appendentries_cb,
								 .applylog			 = raft_applylog_cb,
								 .persist_vote		 = raft_persist_vote_cb,
								 .persist_term		 = raft_persist_term_cb,
								 .log_offer			 = raft_log_offer_cb,
								 .log_poll			 = raft_log_poll_cb,
								 .log_pop			 = raft_log_pop_cb};

	cluster->raft = raft_new();
	raft_set_callbacks(cluster->raft, &raft_callbacks, cluster);

	sso_config_t* cfg = sso_get_config(ctx);
	for (int i = 0; i < cfg->raft_node_count; i++) {
		bool is_self = (cfg->raft_nodes[i].id == cfg->raft_node_id);
		raft_add_node(cluster->raft, cluster, cfg->raft_nodes[i].id, is_self);
		raft_node_t* node = raft_get_node(cluster->raft, cfg->raft_nodes[i].id);
		raft_node_set_udata(node, strdup(cfg->raft_nodes[i].url));
	}

	/* Set up proxy_storage function pointers */
	cluster->proxy_storage		   = *inner_storage;
	cluster->proxy_storage.context = cluster;
	raft_proxy_init_vtable(&cluster->proxy_storage);

	*out_cluster = cluster;
	return SSO_OK;
}

sso_error_t raft_cluster_start(raft_cluster_t* cluster) {
	cluster->running = true;
	pthread_create(&cluster->ticker_thread, NULL, raft_ticker, cluster);
	return SSO_OK;
}

sso_error_t raft_cluster_stop(raft_cluster_t* cluster) {
	cluster->running = false;
	pthread_join(cluster->ticker_thread, NULL);
	raft_free(cluster->raft);
	pthread_mutex_destroy(&cluster->lock);
	free(cluster);
	return SSO_OK;
}

storage_backend_t* raft_cluster_get_storage(raft_cluster_t* cluster) {
	return &cluster->proxy_storage;
}

sso_error_t handle_raft_request_vote(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	(void)req;
	(void)resp;
	return SSO_OK;
}

sso_error_t handle_raft_append_entries(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	(void)req;
	(void)resp;
	return SSO_OK;
}
