#!/usr/bin/env python3
import re
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: gen_raft_proxy.py <storage.h> <output.inc>")
        sys.exit(1)
        
    storage_h = sys.argv[1]
    output_inc = sys.argv[2]
    
    with open(storage_h, "r") as f:
        content = f.read()

    # Match typedefs like:
    # typedef sso_error_t (*storage_user_create_fn)(storage_backend_t *self, user_t *user);
    pattern = re.compile(r'typedef\s+(sso_error_t|void|bool)\s*\(\*storage_([a-zA-Z0-9_]+)_fn\)\s*\(([^)]+)\);')
    
    methods = []
    for match in pattern.finditer(content):
        ret_type = match.group(1).strip()
        method_name = match.group(2).strip()
        args_str = match.group(3).strip()
        
        args = []
        for arg in args_str.split(','):
            arg = arg.strip()
            # extract type and name. e.g. "storage_backend_t *self" -> type: "storage_backend_t *", name: "self"
            # e.g. "const char *name" -> type: "const char *", name: "name"
            # e.g. "size_t *count"
            m = re.match(r'^(.*?)\s*(\*?\w+)?$', arg)
            if m:
                typ = m.group(1).strip()
                name_with_ptr = m.group(2)
                if not name_with_ptr:
                    # just a type with no name (should not happen in well-formed headers, but just in case)
                    continue
                if name_with_ptr.startswith('*'):
                    typ += '*'
                    name = name_with_ptr[1:]
                else:
                    name = name_with_ptr
                    
                args.append({"type": typ, "name": name})

        # Skip read-only methods
        if any(re.search(substring, method_name) for substring in [r'_get_', r'_get$', r'_list_', r'_list$', r'_is_revoked', r'^get_', r'^open$', r'^close$', r'^begin$', r'^commit$', r'^rollback$', r'thread_']):
            continue
            
        methods.append({
            "ret_type": ret_type,
            "name": method_name,
            "args": args
        })

    with open(output_inc, "w") as out:
        out.write("/* GENERATED FILE - DO NOT EDIT */\n\n")
        
        # 1. Generate Proxy Functions
        for m in methods:
            func_sig = f"static {m['ret_type']} proxy_{m['name']}("
            sig_args = []
            for arg in m['args']:
                if arg['name'] == 'self':
                    sig_args.append(f"storage_backend_t *self")
                else:
                    sig_args.append(f"{arg['type']} {arg['name']}")
            func_sig += ", ".join(sig_args) + ") {"
            out.write(f"{func_sig}\n")
            
            out.write("    raft_cluster_t* cluster = (raft_cluster_t*)self->context;\n")
            
            # Serialize arguments to JSON using yyjson
            out.write("    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);\n")
            out.write("    yyjson_mut_val *root = yyjson_mut_obj(doc);\n")
            out.write("    yyjson_mut_doc_set_root(doc, root);\n")
            out.write(f'    yyjson_mut_obj_add_str(doc, root, "op", "{m["name"]}");\n')
            
            # Simple heuristic serialization
            for arg in m['args'][1:]: # skip self
                t = arg['type'].replace('const ', '').strip()
                n = arg['name']
                if 'char*' in t or 'char *' in t:
                    out.write(f'    if ({n}) yyjson_mut_obj_add_str(doc, root, "{n}", {n});\n')
                elif 'int' in t or 'size_t' in t or 'sso_timestamp_t' in t or 'sso_id_t' in t or 'policy_target_type_t' in t:
                    out.write(f'    yyjson_mut_obj_add_int(doc, root, "{n}", (int64_t){n});\n')
                else:
                    # structs (user_t*, role_t*, etc.)
                    # Note: Full struct serialization requires custom logic per struct.
                    # For MVP, we will cast the struct ptr to base64 or raw bytes, or log a FIXME.
                    out.write(f'    /* FIXME: Serialize struct {t} {n} */\n')
            
            out.write("    size_t len;\n")
            out.write("    char *json = yyjson_mut_write(doc, 0, &len);\n")
            out.write("    yyjson_mut_doc_free(doc);\n\n")
            
            out.write("    /* Append to raft log and wait */\n")
            out.write("    sso_error_t res = raft_cluster_propose_and_wait(cluster, json, len);\n")
            out.write("    free(json);\n")
            
            if m['ret_type'] != 'void':
                out.write("    return res;\n")
            out.write("}\n\n")

        # 2. Generate Apply Log Dispatcher
        out.write("static sso_error_t raft_apply_dispatch(raft_cluster_t* cluster, const char* json_str, size_t len) {\n")
        out.write("    yyjson_doc *doc = yyjson_read(json_str, len, 0);\n")
        out.write("    if (!doc) return SSO_ERR_INVALID_PARAM;\n")
        out.write("    yyjson_val *root = yyjson_doc_get_root(doc);\n")
        out.write("    const char *op = yyjson_get_str(yyjson_obj_get(root, \"op\"));\n")
        out.write("    sso_error_t res = SSO_ERR_INVALID_PARAM;\n\n")
        
        for m in methods:
            out.write(f'    if (strcmp(op, "{m["name"]}") == 0) {{\n')
            # deserialize args
            for arg in m['args'][1:]:
                t = arg['type'].replace('const ', '').strip()
                n = arg['name']
                if 'char*' in t or 'char *' in t:
                    out.write(f'        const char* {n} = yyjson_get_str(yyjson_obj_get(root, "{n}"));\n')
                elif 'int' in t or 'size_t' in t or 'sso_timestamp_t' in t or 'sso_id_t' in t or 'policy_target_type_t' in t:
                    out.write(f'        {t} {n} = ({t})yyjson_get_int(yyjson_obj_get(root, "{n}"));\n')
                else:
                    out.write(f'        /* FIXME: Deserialize struct {t} {n} */\n')
                    out.write(f'        {t} {n};\n')
                    out.write(f'        memset(&{n}, 0, sizeof({n}));\n')

            field_name = m['name']
            if field_name == "assign_role_user": field_name = "assign_role_to_user"
            elif field_name == "unassign_role_user": field_name = "unassign_role_from_user"
            elif field_name == "assign_role_group": field_name = "assign_role_to_group"
            elif field_name == "unassign_role_group": field_name = "unassign_role_from_group"
            elif field_name == "add_user_group": field_name = "add_user_to_group"
            elif field_name == "remove_user_group": field_name = "remove_user_from_group"

            args_call = ["cluster->inner_storage"] + [arg['name'] for arg in m['args'][1:]]
            if m['ret_type'] != 'void':
                out.write(f"        res = cluster->inner_storage->{field_name}({', '.join(args_call)});\n")
            else:
                out.write(f"        cluster->inner_storage->{field_name}({', '.join(args_call)});\n")
                out.write("        res = SSO_OK;\n")
            out.write("    } else\n")

        out.write("    {\n        LOG_ERROR(\"Unknown Raft OP: %s\", op);\n    }\n")
        out.write("    yyjson_doc_free(doc);\n")
        out.write("    return res;\n")
        out.write("}\n\n")

        # 3. Generate VTable initialization
        out.write("static void raft_proxy_init_vtable(storage_backend_t* proxy) {\n")
        for m in methods:
            field_name = m['name']
            if field_name == "assign_role_user": field_name = "assign_role_to_user"
            elif field_name == "unassign_role_user": field_name = "unassign_role_from_user"
            elif field_name == "assign_role_group": field_name = "assign_role_to_group"
            elif field_name == "unassign_role_group": field_name = "unassign_role_from_group"
            elif field_name == "add_user_group": field_name = "add_user_to_group"
            elif field_name == "remove_user_group": field_name = "remove_user_from_group"
            out.write(f"    proxy->{field_name} = proxy_{m['name']};\n")
        out.write("}\n\n")

if __name__ == "__main__":
    main()
