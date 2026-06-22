#include "raft_cluster.h"
#include "raft.h"
#include "logger.h"
#include "yyjson.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct rpc_task {
	raft_cluster_t* cluster;
	raft_node_t*	node;
	char			url[256];
	char*			json_payload;
	int				type; // 1 = RequestVote, 2 = AppendEntries
};

struct curl_string {
	char*  ptr;
	size_t len;
};

static void init_string(struct curl_string* s) {
	s->len = 0;
	s->ptr = malloc(s->len + 1);
	if (s->ptr == NULL) {
		fprintf(stderr, "malloc() failed\n");
		exit(EXIT_FAILURE);
	}
	s->ptr[0] = '\0';
}

static size_t curl_writefunc(void* ptr, size_t size, size_t nmemb, struct curl_string* s) {
	size_t new_len = s->len + size * nmemb;
	s->ptr		   = realloc(s->ptr, new_len + 1);
	if (s->ptr == NULL) {
		fprintf(stderr, "realloc() failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr + s->len, ptr, size * nmemb);
	s->ptr[new_len] = '\0';
	s->len			= new_len;
	return size * nmemb;
}

// Declarations to access cluster lock/raft ptr, we will expose them via raft_cluster.h
extern pthread_mutex_t* raft_cluster_get_lock(raft_cluster_t* cluster);
extern raft_server_t*	raft_cluster_get_server(raft_cluster_t* cluster);

static void* rpc_worker_thread(void* arg) {
	struct rpc_task* task = (struct rpc_task*)arg;

	CURL*			   curl;
	CURLcode		   res;
	struct curl_string s;
	init_string(&s);

	curl = curl_easy_init();
	if (curl) {
		struct curl_slist* headers = NULL;
		headers					   = curl_slist_append(headers, "Content-Type: application/json");

		char endpoint[512];
		if (task->type == 1) {
			snprintf(endpoint, sizeof(endpoint), "%s/raft/request_vote", task->url);
		} else {
			snprintf(endpoint, sizeof(endpoint), "%s/raft/append_entries", task->url);
		}

		curl_easy_setopt(curl, CURLOPT_URL, endpoint);
		curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, task->json_payload);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 2 seconds timeout

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			LOG_ERROR("Raft RPC to %s failed: %s", endpoint, curl_easy_strerror(res));
		} else {
			yyjson_doc* doc = yyjson_read(s.ptr, s.len, 0);
			if (!doc) {
				LOG_ERROR("Raft RPC response from %s was not valid JSON. Response: %s", endpoint, s.ptr);
			}
			if (doc) {
				yyjson_val*		 root = yyjson_doc_get_root(doc);
				pthread_mutex_t* lock = raft_cluster_get_lock(task->cluster);
				raft_server_t*	 raft = raft_cluster_get_server(task->cluster);

				pthread_mutex_lock(lock);
				if (task->type == 1) {
					msg_requestvote_response_t r = {0};
					r.term						 = yyjson_get_int(yyjson_obj_get(root, "term"));
					r.vote_granted				 = yyjson_get_int(yyjson_obj_get(root, "vote_granted"));
					raft_recv_requestvote_response(raft, task->node, &r);
				} else if (task->type == 2) {
					msg_appendentries_response_t r = {0};
					r.term						   = yyjson_get_int(yyjson_obj_get(root, "term"));
					r.success					   = yyjson_get_int(yyjson_obj_get(root, "success"));
					r.current_idx				   = yyjson_get_int(yyjson_obj_get(root, "current_idx"));
					r.first_idx					   = yyjson_get_int(yyjson_obj_get(root, "first_idx"));
					raft_recv_appendentries_response(raft, task->node, &r);
				}
				pthread_mutex_unlock(lock);
				yyjson_doc_free(doc);
			}
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	free(s.ptr);
	free(task->json_payload);
	free(task);
	return NULL;
}

void raft_rpc_send_requestvote(raft_cluster_t* cluster, raft_node_t* node, msg_requestvote_t* m, const char* url) {
	yyjson_mut_doc* doc	 = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);
	yyjson_mut_obj_add_int(doc, root, "sender_id", raft_node_get_id(raft_get_my_node(raft_cluster_get_server(cluster))));
	yyjson_mut_obj_add_int(doc, root, "term", m->term);
	yyjson_mut_obj_add_int(doc, root, "candidate_id", m->candidate_id);
	yyjson_mut_obj_add_int(doc, root, "last_log_idx", m->last_log_idx);
	yyjson_mut_obj_add_int(doc, root, "last_log_term", m->last_log_term);
	char* json = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);

	struct rpc_task* task = calloc(1, sizeof(struct rpc_task));
	task->cluster		  = cluster;
	task->node			  = node;
	strncpy(task->url, url, sizeof(task->url) - 1);
	task->json_payload = json;
	task->type		   = 1;

	pthread_t th;
	pthread_create(&th, NULL, rpc_worker_thread, task);
	pthread_detach(th);
}

void raft_rpc_send_appendentries(raft_cluster_t* cluster, raft_node_t* node, msg_appendentries_t* m, const char* url) {
	yyjson_mut_doc* doc	 = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);
	yyjson_mut_obj_add_int(doc, root, "sender_id", raft_node_get_id(raft_get_my_node(raft_cluster_get_server(cluster))));
	yyjson_mut_obj_add_int(doc, root, "term", m->term);
	yyjson_mut_obj_add_int(doc, root, "prev_log_idx", m->prev_log_idx);
	yyjson_mut_obj_add_int(doc, root, "prev_log_term", m->prev_log_term);
	yyjson_mut_obj_add_int(doc, root, "leader_commit", m->leader_commit);
	yyjson_mut_obj_add_int(doc, root, "n_entries", m->n_entries);

	yyjson_mut_val* entries = yyjson_mut_arr(doc);
	for (int i = 0; i < m->n_entries; i++) {
		yyjson_mut_val* e = yyjson_mut_arr_add_obj(doc, entries);
		yyjson_mut_obj_add_int(doc, e, "term", m->entries[i].term);
		yyjson_mut_obj_add_int(doc, e, "id", m->entries[i].id);
		yyjson_mut_obj_add_int(doc, e, "type", m->entries[i].type);
		if (m->entries[i].data.buf) {
			yyjson_mut_obj_add_str(doc, e, "data", (const char*)m->entries[i].data.buf);
		}
	}
	yyjson_mut_obj_add_val(doc, root, "entries", entries);

	char* json = yyjson_mut_write(doc, 0, NULL);
	yyjson_mut_doc_free(doc);

	struct rpc_task* task = calloc(1, sizeof(struct rpc_task));
	task->cluster		  = cluster;
	task->node			  = node;
	strncpy(task->url, url, sizeof(task->url) - 1);
	task->json_payload = json;
	task->type		   = 2;

	pthread_t th;
	pthread_create(&th, NULL, rpc_worker_thread, task);
	pthread_detach(th);
}
