#ifndef RAFT_RPC_H
#define RAFT_RPC_H

#include "raft_cluster.h"
#include "raft.h"

void raft_rpc_send_requestvote(raft_cluster_t* cluster, raft_node_t* node, msg_requestvote_t* m, const char* url);
void raft_rpc_send_appendentries(raft_cluster_t* cluster, raft_node_t* node, msg_appendentries_t* m, const char* url);

#endif // RAFT_RPC_H
