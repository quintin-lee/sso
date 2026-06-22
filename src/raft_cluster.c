#include "raft_cluster.h"
#include "raft_rpc.h"
#include "raft.h"
#include "logger.h"
#include "yyjson.h"
#include "server.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include "role.h"
#include "group.h"
#include "policy.h"

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

pthread_mutex_t* raft_cluster_get_lock(raft_cluster_t* cluster) {
	return &cluster->lock;
}

raft_server_t* raft_cluster_get_server(raft_cluster_t* cluster) {
	return cluster->raft;
}

static int raft_send_requestvote_cb(raft_server_t* raft, void* user_data, raft_node_t* node, msg_requestvote_t* m) {
	(void)raft;
	raft_cluster_t* cluster = (raft_cluster_t*)user_data;
	const char*		url		= (const char*)raft_node_get_udata(node);
	if (!url)
		return 0;

	LOG_DEBUG("Raft: Sending RequestVote to %s (term: %ld, cand: %ld)", url, (long)m->term, (long)m->candidate_id);
	raft_rpc_send_requestvote(cluster, node, m, url);
	return 0;
}

static int raft_send_appendentries_cb(raft_server_t* raft, void* user_data, raft_node_t* node, msg_appendentries_t* m) {
	(void)raft;
	raft_cluster_t* cluster = (raft_cluster_t*)user_data;
	const char*		url		= (const char*)raft_node_get_udata(node);
	if (!url)
		return 0;

	LOG_DEBUG("Raft: Sending AppendEntries to %s (term: %ld)", url, (long)m->term);
	raft_rpc_send_appendentries(cluster, node, m, url);
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
	(void)entry_idx;
	if (entry->data.buf && entry->data.len > 0) {
		void* copy = malloc(entry->data.len + 1);
		memcpy(copy, entry->data.buf, entry->data.len);
		((char*)copy)[entry->data.len] = '\0';
		entry->data.buf = copy;
	} else {
		entry->data.buf = NULL;
	}
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
		if (e == RAFT_ERR_NOT_LEADER) {
			/* Automatically forward to leader */
			raft_node_t* leader = raft_get_current_leader_node(cluster->raft);
			if (leader) {
				const char* leader_url = (const char*)raft_node_get_udata(leader);
				if (leader_url) {
					char exec_url[512];
					snprintf(exec_url, sizeof(exec_url), "%s/api/v1/raft/execute", leader_url);
					
					CURL* curl = curl_easy_init();
					if (curl) {
						curl_easy_setopt(curl, CURLOPT_URL, exec_url);
						curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
						curl_easy_setopt(curl, CURLOPT_POST, 1L);
						curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
						curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
						curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
						
						struct curl_slist* headers = NULL;
						headers = curl_slist_append(headers, "Content-Type: application/json");
						/* Bypass auth for internal RPC */
						headers = curl_slist_append(headers, "Authorization: Bearer internal-rpc"); 
						curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
						
						CURLcode res = curl_easy_perform(curl);
						long http_code = 0;
						curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
						
						curl_slist_free_all(headers);
						curl_easy_cleanup(curl);
						
						if (res == CURLE_OK && http_code == 200) {
							return SSO_OK;
						} else {
							LOG_ERROR("Raft: Forwarding to %s failed! curl_res=%d, http_code=%ld", exec_url, res, http_code);
						}
					} else {
						LOG_ERROR("Raft: Failed to init curl for forwarding");
					}
				} else {
					LOG_ERROR("Raft: Leader URL is NULL");
				}
			} else {
				LOG_ERROR("Raft: No leader currently elected to forward to");
			}
		}
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

static raft_cluster_t* g_cluster = NULL;

sso_error_t raft_cluster_start(raft_cluster_t* cluster) {
	cluster->running = true;
	g_cluster		 = cluster;
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
	if (!g_cluster || !req->body)
		return SSO_ERR_INVALID_PARAM;

	yyjson_doc* doc = yyjson_read(req->body, req->body_len, 0);
	if (!doc)
		return SSO_ERR_INVALID_PARAM;
	yyjson_val* root = yyjson_doc_get_root(doc);

	msg_requestvote_t m = {0};
	m.term				= yyjson_get_int(yyjson_obj_get(root, "term"));
	m.candidate_id		= yyjson_get_int(yyjson_obj_get(root, "candidate_id"));
	m.last_log_idx		= yyjson_get_int(yyjson_obj_get(root, "last_log_idx"));
	m.last_log_term		= yyjson_get_int(yyjson_obj_get(root, "last_log_term"));
	yyjson_doc_free(doc);

	msg_requestvote_response_t r = {0};
	pthread_mutex_lock(&g_cluster->lock);
	int e = raft_recv_requestvote(g_cluster->raft, raft_get_node(g_cluster->raft, m.candidate_id), &m, &r);
	pthread_mutex_unlock(&g_cluster->lock);

	if (e != 0)
		return SSO_ERR_GENERAL;

	yyjson_mut_doc* mut_doc	 = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* mut_root = yyjson_mut_obj(mut_doc);
	yyjson_mut_doc_set_root(mut_doc, mut_root);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "term", r.term);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "vote_granted", r.vote_granted);
	char* json = yyjson_mut_write(mut_doc, 0, NULL);
	yyjson_mut_doc_free(mut_doc);

	sso_response_ok(resp, json);
	free(json);
	return SSO_OK;
}

sso_error_t handle_raft_append_entries(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	if (!g_cluster || !req->body)
		return SSO_ERR_INVALID_PARAM;

	yyjson_doc* doc = yyjson_read(req->body, req->body_len, 0);
	if (!doc)
		return SSO_ERR_INVALID_PARAM;
	yyjson_val* root = yyjson_doc_get_root(doc);

	msg_appendentries_t m = {0};
	m.term				  = yyjson_get_int(yyjson_obj_get(root, "term"));
	m.prev_log_idx		  = yyjson_get_int(yyjson_obj_get(root, "prev_log_idx"));
	m.prev_log_term		  = yyjson_get_int(yyjson_obj_get(root, "prev_log_term"));
	m.leader_commit		  = yyjson_get_int(yyjson_obj_get(root, "leader_commit"));
	m.n_entries			  = yyjson_get_int(yyjson_obj_get(root, "n_entries"));

	yyjson_val* entries_arr = yyjson_obj_get(root, "entries");
	if (m.n_entries > 0 && yyjson_is_arr(entries_arr)) {
		m.entries = calloc(m.n_entries, sizeof(msg_entry_t));
		size_t		idx, max;
		yyjson_val* val;
		yyjson_arr_foreach(entries_arr, idx, max, val) {
			if (idx >= (size_t)m.n_entries)
				break;
			m.entries[idx].term	 = yyjson_get_int(yyjson_obj_get(val, "term"));
			m.entries[idx].id	 = yyjson_get_int(yyjson_obj_get(val, "id"));
			m.entries[idx].type	 = yyjson_get_int(yyjson_obj_get(val, "type"));
			const char* data_str = yyjson_get_str(yyjson_obj_get(val, "data"));
			if (data_str) {
				m.entries[idx].data.buf = strdup(data_str);
				m.entries[idx].data.len = strlen(data_str);
			}
		}
	}

	raft_node_id_t sender_id = yyjson_get_int(yyjson_obj_get(root, "sender_id"));
	raft_node_t* sender_node = raft_get_node(g_cluster->raft, sender_id);

	msg_appendentries_response_t r = {0};

	pthread_mutex_lock(&g_cluster->lock);
	int e = raft_recv_appendentries(g_cluster->raft, sender_node, &m, &r);
	pthread_mutex_unlock(&g_cluster->lock);

	if (m.entries) {
		free(m.entries);
	}
	yyjson_doc_free(doc);

	if (e != 0)
		return SSO_ERR_GENERAL;

	yyjson_mut_doc* mut_doc	 = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* mut_root = yyjson_mut_obj(mut_doc);
	yyjson_mut_doc_set_root(mut_doc, mut_root);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "term", r.term);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "success", r.success);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "current_idx", r.current_idx);
	yyjson_mut_obj_add_int(mut_doc, mut_root, "first_idx", r.first_idx);
	char* json = yyjson_mut_write(mut_doc, 0, NULL);
	yyjson_mut_doc_free(mut_doc);

	sso_response_ok(resp, json);
	free(json);
	return SSO_OK;
}

sso_error_t handle_raft_execute(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Missing payload");
		return SSO_OK;
	}
	raft_cluster_t* cluster = NULL;
	if (!ctx || !ctx->storage_backend) return SSO_ERR_STORAGE;
	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	cluster = (raft_cluster_t*)sb->context;
	if (!cluster) return SSO_ERR_STORAGE;

	sso_error_t err = raft_cluster_propose_and_wait(cluster, req->body, req->body_len);
	if (err == SSO_OK) {
		sso_response_ok(resp, "{\"success\":true}");
	} else {
		sso_response_error(resp, 500, "Raft propose failed");
	}
	return SSO_OK;
}

sso_error_t handle_raft_status(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	raft_cluster_t* cluster = NULL;
	if (!ctx || !ctx->storage_backend) return SSO_ERR_STORAGE;
	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	cluster = (raft_cluster_t*)sb->context;
	if (!cluster) return SSO_ERR_STORAGE;

	pthread_mutex_lock(&cluster->lock);
	int is_leader = raft_is_leader(cluster->raft);
	int state = raft_get_state(cluster->raft);
	raft_term_t term = raft_get_current_term(cluster->raft);
	raft_index_t idx = raft_get_current_idx(cluster->raft);
	int num_nodes = raft_get_num_nodes(cluster->raft);
	raft_node_t* leader_node = raft_get_current_leader_node(cluster->raft);
	const char* leader_url = leader_node ? (const char*)raft_node_get_udata(leader_node) : "";
	pthread_mutex_unlock(&cluster->lock);

	const char* state_str = "unknown";
	if (state == RAFT_STATE_FOLLOWER) state_str = "follower";
	else if (state == RAFT_STATE_CANDIDATE) state_str = "candidate";
	else if (state == RAFT_STATE_LEADER) state_str = "leader";

	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);

	yyjson_mut_obj_add_bool(doc, root, "is_leader", is_leader);
	yyjson_mut_obj_add_str(doc, root, "state", state_str);
	yyjson_mut_obj_add_int(doc, root, "term", term);
	yyjson_mut_obj_add_int(doc, root, "current_idx", idx);
	yyjson_mut_obj_add_int(doc, root, "num_nodes", num_nodes);
	yyjson_mut_obj_add_str(doc, root, "leader_url", leader_url);

	char* json = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);

	sso_response_ok(resp, json);
	free(json);
	return SSO_OK;
}
