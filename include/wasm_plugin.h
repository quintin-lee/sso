#ifndef SSO_WASM_PLUGIN_H
#define SSO_WASM_PLUGIN_H

#include "sso.h"

/* 
 * Initializes the WebAssembly Micro Runtime (WAMR) engine.
 * Should be called once during server startup.
 */
sso_error_t wasm_engine_init(void);

/*
 * Destroys the Wasm engine and frees resources.
 */
void wasm_engine_destroy(void);

/*
 * Evaluates a custom security policy written in Wasm.
 * @param plugin_path: Absolute path to the .wasm compiled module
 * @param context_json: The authentication context (user, IP, risk score) serialized as JSON
 * @return: 1 if ALLOWED, 0 if DENIED, -1 on ERROR.
 */
int wasm_policy_evaluate(const char* plugin_path, const char* context_json);

#endif // SSO_WASM_PLUGIN_H
