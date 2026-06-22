#ifndef RAFT_CLUSTER_H
#define RAFT_CLUSTER_H

#include "sso.h"
#include "server.h"
#include "storage.h"
#include "config.h"

typedef struct raft_cluster_t raft_cluster_t;

/* Initialize Raft and wrap the underlying storage */
sso_error_t raft_cluster_init(sso_context_t* ctx, storage_backend_t* inner_storage, raft_cluster_t** out_cluster);

/* Start the Raft ticker and cluster operations */
sso_error_t raft_cluster_start(raft_cluster_t* cluster);

/* Stop the Raft cluster */
sso_error_t raft_cluster_stop(raft_cluster_t* cluster);

/* Get the wrapped storage that proxies writes through Raft */
storage_backend_t* raft_cluster_get_storage(raft_cluster_t* cluster);

/* HTTP handlers for Raft inter-node RPC */
sso_error_t handle_raft_request_vote(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_raft_append_entries(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_raft_execute(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

#endif
