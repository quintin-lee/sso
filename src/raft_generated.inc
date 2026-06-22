/* GENERATED FILE - DO NOT EDIT */

static sso_error_t proxy_user_create(storage_backend_t *self, user_t* user) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "user_create");
    /* FIXME: Serialize struct user_t* user */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_user_update(storage_backend_t *self, const user_t* user) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "user_update");
    /* FIXME: Serialize struct user_t* user */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_user_delete(storage_backend_t *self, sso_id_t id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "user_delete");
    yyjson_mut_obj_add_int(doc, root, "id", (int64_t)id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_save_sms_code(storage_backend_t *self, const char* phone, const char* code, sso_timestamp_t expires_at) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "save_sms_code");
    if (phone) yyjson_mut_obj_add_str(doc, root, "phone", phone);
    if (code) yyjson_mut_obj_add_str(doc, root, "code", code);
    yyjson_mut_obj_add_int(doc, root, "expires_at", (int64_t)expires_at);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_delete_sms_code(storage_backend_t *self, const char* phone) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "delete_sms_code");
    if (phone) yyjson_mut_obj_add_str(doc, root, "phone", phone);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_role_create(storage_backend_t *self, role_t* role) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "role_create");
    /* FIXME: Serialize struct role_t* role */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_role_update(storage_backend_t *self, const role_t* role) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "role_update");
    /* FIXME: Serialize struct role_t* role */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_role_delete(storage_backend_t *self, sso_id_t id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "role_delete");
    yyjson_mut_obj_add_int(doc, root, "id", (int64_t)id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_group_create(storage_backend_t *self, group_t* group) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "group_create");
    /* FIXME: Serialize struct group_t* group */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_group_update(storage_backend_t *self, const group_t* group) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "group_update");
    /* FIXME: Serialize struct group_t* group */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_group_delete(storage_backend_t *self, sso_id_t id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "group_delete");
    yyjson_mut_obj_add_int(doc, root, "id", (int64_t)id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_policy_create(storage_backend_t *self, policy_t* policy) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "policy_create");
    /* FIXME: Serialize struct policy_t* policy */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_policy_update(storage_backend_t *self, const policy_t* policy) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "policy_update");
    /* FIXME: Serialize struct policy_t* policy */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_policy_delete(storage_backend_t *self, sso_id_t id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "policy_delete");
    yyjson_mut_obj_add_int(doc, root, "id", (int64_t)id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_assign_role_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "assign_role_user");
    yyjson_mut_obj_add_int(doc, root, "role_id", (int64_t)role_id);
    yyjson_mut_obj_add_int(doc, root, "user_id", (int64_t)user_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_unassign_role_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "unassign_role_user");
    yyjson_mut_obj_add_int(doc, root, "role_id", (int64_t)role_id);
    yyjson_mut_obj_add_int(doc, root, "user_id", (int64_t)user_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_assign_role_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "assign_role_group");
    yyjson_mut_obj_add_int(doc, root, "role_id", (int64_t)role_id);
    yyjson_mut_obj_add_int(doc, root, "group_id", (int64_t)group_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_unassign_role_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "unassign_role_group");
    yyjson_mut_obj_add_int(doc, root, "role_id", (int64_t)role_id);
    yyjson_mut_obj_add_int(doc, root, "group_id", (int64_t)group_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_add_user_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "add_user_group");
    yyjson_mut_obj_add_int(doc, root, "group_id", (int64_t)group_id);
    yyjson_mut_obj_add_int(doc, root, "user_id", (int64_t)user_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_remove_user_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "remove_user_group");
    yyjson_mut_obj_add_int(doc, root, "group_id", (int64_t)group_id);
    yyjson_mut_obj_add_int(doc, root, "user_id", (int64_t)user_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_assign_policy(storage_backend_t *self, sso_id_t policy_id, policy_target_type_t target_type, sso_id_t target_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "assign_policy");
    yyjson_mut_obj_add_int(doc, root, "policy_id", (int64_t)policy_id);
    yyjson_mut_obj_add_int(doc, root, "target_type", (int64_t)target_type);
    yyjson_mut_obj_add_int(doc, root, "target_id", (int64_t)target_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_unassign_policy(storage_backend_t *self, sso_id_t policy_id, policy_target_type_t target_type, sso_id_t target_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "unassign_policy");
    yyjson_mut_obj_add_int(doc, root, "policy_id", (int64_t)policy_id);
    yyjson_mut_obj_add_int(doc, root, "target_type", (int64_t)target_type);
    yyjson_mut_obj_add_int(doc, root, "target_id", (int64_t)target_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_refresh_token_create(storage_backend_t *self, const refresh_token_t* rt) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "refresh_token_create");
    /* FIXME: Serialize struct refresh_token_t* rt */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_refresh_token_revoke(storage_backend_t *self, const char* token_hash) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "refresh_token_revoke");
    if (token_hash) yyjson_mut_obj_add_str(doc, root, "token_hash", token_hash);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_jti_revoke(storage_backend_t *self, const char* jti, sso_timestamp_t expires_at) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "jti_revoke");
    if (jti) yyjson_mut_obj_add_str(doc, root, "jti", jti);
    yyjson_mut_obj_add_int(doc, root, "expires_at", (int64_t)expires_at);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_code_create(storage_backend_t *self, const oauth_auth_code_t* code) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_code_create");
    /* FIXME: Serialize struct oauth_auth_code_t* code */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_code_mark_used(storage_backend_t *self, const char* code) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_code_mark_used");
    if (code) yyjson_mut_obj_add_str(doc, root, "code", code);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_code_cleanup(storage_backend_t *self) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_code_cleanup");
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_audit_log_write(storage_backend_t *self, const audit_log_entry_t* entry) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "audit_log_write");
    /* FIXME: Serialize struct audit_log_entry_t* entry */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_client_create(storage_backend_t *self, oauth_client_t* client) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_client_create");
    /* FIXME: Serialize struct oauth_client_t* client */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_client_update(storage_backend_t *self, const oauth_client_t* client) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_client_update");
    /* FIXME: Serialize struct oauth_client_t* client */
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_oauth_client_delete(storage_backend_t *self, const char* client_id) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "oauth_client_delete");
    if (client_id) yyjson_mut_obj_add_str(doc, root, "client_id", client_id);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t proxy_exec_sql_file(storage_backend_t *self, const char* path) {
    raft_cluster_t* cluster = (raft_cluster_t*)self->context;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "op", "exec_sql_file");
    if (path) yyjson_mut_obj_add_str(doc, root, "path", path);
    size_t len;
    char *json = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);

    /* Append to raft log and wait */
    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);
    free(json);
    return res;
}

static sso_error_t raft_apply_dispatch(raft_cluster_t* cluster, const char* json_str, size_t len) {
    yyjson_doc *doc = yyjson_read(json_str, len, 0);
    if (!doc) return SSO_ERR_INVALID_PARAM;
    yyjson_val *root = yyjson_doc_get_root(doc);
    const char *op = yyjson_get_str(yyjson_obj_get(root, "op"));
    sso_error_t res = SSO_ERR_INVALID_PARAM;

    if (strcmp(op, "user_create") == 0) {
        /* FIXME: Deserialize struct user_t* user */
        user_t* user;
        memset(&user, 0, sizeof(user));
        res = cluster->inner_storage->user_create(cluster->inner_storage, user);
    } else
    if (strcmp(op, "user_update") == 0) {
        /* FIXME: Deserialize struct user_t* user */
        user_t* user;
        memset(&user, 0, sizeof(user));
        res = cluster->inner_storage->user_update(cluster->inner_storage, user);
    } else
    if (strcmp(op, "user_delete") == 0) {
        sso_id_t id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "id"));
        res = cluster->inner_storage->user_delete(cluster->inner_storage, id);
    } else
    if (strcmp(op, "save_sms_code") == 0) {
        const char* phone = yyjson_get_str(yyjson_obj_get(root, "phone"));
        const char* code = yyjson_get_str(yyjson_obj_get(root, "code"));
        sso_timestamp_t expires_at = (sso_timestamp_t)yyjson_get_int(yyjson_obj_get(root, "expires_at"));
        res = cluster->inner_storage->save_sms_code(cluster->inner_storage, phone, code, expires_at);
    } else
    if (strcmp(op, "delete_sms_code") == 0) {
        const char* phone = yyjson_get_str(yyjson_obj_get(root, "phone"));
        res = cluster->inner_storage->delete_sms_code(cluster->inner_storage, phone);
    } else
    if (strcmp(op, "role_create") == 0) {
        /* FIXME: Deserialize struct role_t* role */
        role_t* role;
        memset(&role, 0, sizeof(role));
        res = cluster->inner_storage->role_create(cluster->inner_storage, role);
    } else
    if (strcmp(op, "role_update") == 0) {
        /* FIXME: Deserialize struct role_t* role */
        role_t* role;
        memset(&role, 0, sizeof(role));
        res = cluster->inner_storage->role_update(cluster->inner_storage, role);
    } else
    if (strcmp(op, "role_delete") == 0) {
        sso_id_t id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "id"));
        res = cluster->inner_storage->role_delete(cluster->inner_storage, id);
    } else
    if (strcmp(op, "group_create") == 0) {
        /* FIXME: Deserialize struct group_t* group */
        group_t* group;
        memset(&group, 0, sizeof(group));
        res = cluster->inner_storage->group_create(cluster->inner_storage, group);
    } else
    if (strcmp(op, "group_update") == 0) {
        /* FIXME: Deserialize struct group_t* group */
        group_t* group;
        memset(&group, 0, sizeof(group));
        res = cluster->inner_storage->group_update(cluster->inner_storage, group);
    } else
    if (strcmp(op, "group_delete") == 0) {
        sso_id_t id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "id"));
        res = cluster->inner_storage->group_delete(cluster->inner_storage, id);
    } else
    if (strcmp(op, "policy_create") == 0) {
        /* FIXME: Deserialize struct policy_t* policy */
        policy_t* policy;
        memset(&policy, 0, sizeof(policy));
        res = cluster->inner_storage->policy_create(cluster->inner_storage, policy);
    } else
    if (strcmp(op, "policy_update") == 0) {
        /* FIXME: Deserialize struct policy_t* policy */
        policy_t* policy;
        memset(&policy, 0, sizeof(policy));
        res = cluster->inner_storage->policy_update(cluster->inner_storage, policy);
    } else
    if (strcmp(op, "policy_delete") == 0) {
        sso_id_t id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "id"));
        res = cluster->inner_storage->policy_delete(cluster->inner_storage, id);
    } else
    if (strcmp(op, "assign_role_user") == 0) {
        sso_id_t role_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "role_id"));
        sso_id_t user_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "user_id"));
        res = cluster->inner_storage->assign_role_to_user(cluster->inner_storage, role_id, user_id);
    } else
    if (strcmp(op, "unassign_role_user") == 0) {
        sso_id_t role_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "role_id"));
        sso_id_t user_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "user_id"));
        res = cluster->inner_storage->unassign_role_from_user(cluster->inner_storage, role_id, user_id);
    } else
    if (strcmp(op, "assign_role_group") == 0) {
        sso_id_t role_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "role_id"));
        sso_id_t group_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "group_id"));
        res = cluster->inner_storage->assign_role_to_group(cluster->inner_storage, role_id, group_id);
    } else
    if (strcmp(op, "unassign_role_group") == 0) {
        sso_id_t role_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "role_id"));
        sso_id_t group_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "group_id"));
        res = cluster->inner_storage->unassign_role_from_group(cluster->inner_storage, role_id, group_id);
    } else
    if (strcmp(op, "add_user_group") == 0) {
        sso_id_t group_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "group_id"));
        sso_id_t user_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "user_id"));
        res = cluster->inner_storage->add_user_to_group(cluster->inner_storage, group_id, user_id);
    } else
    if (strcmp(op, "remove_user_group") == 0) {
        sso_id_t group_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "group_id"));
        sso_id_t user_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "user_id"));
        res = cluster->inner_storage->remove_user_from_group(cluster->inner_storage, group_id, user_id);
    } else
    if (strcmp(op, "assign_policy") == 0) {
        sso_id_t policy_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "policy_id"));
        policy_target_type_t target_type = (policy_target_type_t)yyjson_get_int(yyjson_obj_get(root, "target_type"));
        sso_id_t target_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "target_id"));
        res = cluster->inner_storage->assign_policy(cluster->inner_storage, policy_id, target_type, target_id);
    } else
    if (strcmp(op, "unassign_policy") == 0) {
        sso_id_t policy_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "policy_id"));
        policy_target_type_t target_type = (policy_target_type_t)yyjson_get_int(yyjson_obj_get(root, "target_type"));
        sso_id_t target_id = (sso_id_t)yyjson_get_int(yyjson_obj_get(root, "target_id"));
        res = cluster->inner_storage->unassign_policy(cluster->inner_storage, policy_id, target_type, target_id);
    } else
    if (strcmp(op, "refresh_token_create") == 0) {
        /* FIXME: Deserialize struct refresh_token_t* rt */
        refresh_token_t* rt;
        memset(&rt, 0, sizeof(rt));
        res = cluster->inner_storage->refresh_token_create(cluster->inner_storage, rt);
    } else
    if (strcmp(op, "refresh_token_revoke") == 0) {
        const char* token_hash = yyjson_get_str(yyjson_obj_get(root, "token_hash"));
        res = cluster->inner_storage->refresh_token_revoke(cluster->inner_storage, token_hash);
    } else
    if (strcmp(op, "jti_revoke") == 0) {
        const char* jti = yyjson_get_str(yyjson_obj_get(root, "jti"));
        sso_timestamp_t expires_at = (sso_timestamp_t)yyjson_get_int(yyjson_obj_get(root, "expires_at"));
        res = cluster->inner_storage->jti_revoke(cluster->inner_storage, jti, expires_at);
    } else
    if (strcmp(op, "oauth_code_create") == 0) {
        /* FIXME: Deserialize struct oauth_auth_code_t* code */
        oauth_auth_code_t* code;
        memset(&code, 0, sizeof(code));
        res = cluster->inner_storage->oauth_code_create(cluster->inner_storage, code);
    } else
    if (strcmp(op, "oauth_code_mark_used") == 0) {
        const char* code = yyjson_get_str(yyjson_obj_get(root, "code"));
        res = cluster->inner_storage->oauth_code_mark_used(cluster->inner_storage, code);
    } else
    if (strcmp(op, "oauth_code_cleanup") == 0) {
        res = cluster->inner_storage->oauth_code_cleanup(cluster->inner_storage);
    } else
    if (strcmp(op, "audit_log_write") == 0) {
        /* FIXME: Deserialize struct audit_log_entry_t* entry */
        audit_log_entry_t* entry;
        memset(&entry, 0, sizeof(entry));
        res = cluster->inner_storage->audit_log_write(cluster->inner_storage, entry);
    } else
    if (strcmp(op, "oauth_client_create") == 0) {
        /* FIXME: Deserialize struct oauth_client_t* client */
        oauth_client_t* client;
        memset(&client, 0, sizeof(client));
        res = cluster->inner_storage->oauth_client_create(cluster->inner_storage, client);
    } else
    if (strcmp(op, "oauth_client_update") == 0) {
        /* FIXME: Deserialize struct oauth_client_t* client */
        oauth_client_t* client;
        memset(&client, 0, sizeof(client));
        res = cluster->inner_storage->oauth_client_update(cluster->inner_storage, client);
    } else
    if (strcmp(op, "oauth_client_delete") == 0) {
        const char* client_id = yyjson_get_str(yyjson_obj_get(root, "client_id"));
        res = cluster->inner_storage->oauth_client_delete(cluster->inner_storage, client_id);
    } else
    if (strcmp(op, "exec_sql_file") == 0) {
        const char* path = yyjson_get_str(yyjson_obj_get(root, "path"));
        res = cluster->inner_storage->exec_sql_file(cluster->inner_storage, path);
    } else
    {
        LOG_ERROR("Unknown Raft OP: %s", op);
    }
    yyjson_doc_free(doc);
    return res;
}

static void raft_proxy_init_vtable(storage_backend_t* proxy) {
    proxy->user_create = proxy_user_create;
    proxy->user_update = proxy_user_update;
    proxy->user_delete = proxy_user_delete;
    proxy->save_sms_code = proxy_save_sms_code;
    proxy->delete_sms_code = proxy_delete_sms_code;
    proxy->role_create = proxy_role_create;
    proxy->role_update = proxy_role_update;
    proxy->role_delete = proxy_role_delete;
    proxy->group_create = proxy_group_create;
    proxy->group_update = proxy_group_update;
    proxy->group_delete = proxy_group_delete;
    proxy->policy_create = proxy_policy_create;
    proxy->policy_update = proxy_policy_update;
    proxy->policy_delete = proxy_policy_delete;
    proxy->assign_role_to_user = proxy_assign_role_user;
    proxy->unassign_role_from_user = proxy_unassign_role_user;
    proxy->assign_role_to_group = proxy_assign_role_group;
    proxy->unassign_role_from_group = proxy_unassign_role_group;
    proxy->add_user_to_group = proxy_add_user_group;
    proxy->remove_user_from_group = proxy_remove_user_group;
    proxy->assign_policy = proxy_assign_policy;
    proxy->unassign_policy = proxy_unassign_policy;
    proxy->refresh_token_create = proxy_refresh_token_create;
    proxy->refresh_token_revoke = proxy_refresh_token_revoke;
    proxy->jti_revoke = proxy_jti_revoke;
    proxy->oauth_code_create = proxy_oauth_code_create;
    proxy->oauth_code_mark_used = proxy_oauth_code_mark_used;
    proxy->oauth_code_cleanup = proxy_oauth_code_cleanup;
    proxy->audit_log_write = proxy_audit_log_write;
    proxy->oauth_client_create = proxy_oauth_client_create;
    proxy->oauth_client_update = proxy_oauth_client_update;
    proxy->oauth_client_delete = proxy_oauth_client_delete;
    proxy->exec_sql_file = proxy_exec_sql_file;
}

