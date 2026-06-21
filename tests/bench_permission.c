#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sso.h"
#include "permission.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "storage.h"

static long long time_in_us() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int main(int argc, char** argv) {
	int iterations = 100000;
	if (argc > 1) {
		iterations = atoi(argv[1]);
	}
	printf("Starting Permission Engine Benchmark (%d iterations)...\n", iterations);
	printf("Setting up in-memory SQLite and multi-strategy policies...\n");

	storage_backend_t* storage;
	storage_sqlite_create(&storage);
	storage->open(storage, ":memory:");

	sso_context_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.storage_backend = storage;

	user_manager_t* umgr;
	user_manager_create(&umgr, &ctx);
	ctx.user_mgr = umgr;
	role_manager_t* rmgr;
	role_manager_create(&rmgr, &ctx);
	ctx.role_mgr = rmgr;
	policy_manager_t* pmgr;
	policy_manager_create(&pmgr, &ctx);
	ctx.policy_mgr = pmgr;
	permission_engine_t* pengine;
	perm_engine_create(&pengine, &ctx);
	ctx.perm_engine = pengine;

	/* Setup Data */
	user_t user;
	user_create(umgr, "benchuser", "p", "a@e.c", "A", &user);

	/* 1. API Policy (Wildcard Matching) */
	policy_t	p_api;
	const char* rules_api = "{\"endpoints\":[{\"method\":\"GET\",\"path\":\"/api/v1/data/*\",\"effect\":\"allow\"}]}";
	policy_create(pmgr, "API Access", PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 1, rules_api, &p_api);
	policy_assign_to(pmgr, p_api.id, POLICY_TARGET_USER, user.id);

	/* 2. LBAC Policy (Location / IP checking) */
	policy_t	p_loc;
	const char* rules_loc = "{\"allowed_ips\":[\"192.168.0.0/16\", \"10.0.0.0/8\"], \"effect\":\"allow\"}";
	policy_create(pmgr, "Intranet Only", PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW, 2, rules_loc, &p_loc);
	policy_assign_to(pmgr, p_loc.id, POLICY_TARGET_USER, user.id);

	eval_context_t ectx;
	memset(&ectx, 0, sizeof(ectx));
	ectx.user_id = user.id;
	strcpy(ectx.params.api.http_method, "GET");
	strcpy(ectx.params.api.request_path, "/api/v1/data/123");
	strcpy(ectx.params.location.source_ip, "10.1.2.3");

	printf("Executing benchmark loop...\n");
	long long start = time_in_us();

	for (int i = 0; i < iterations; i++) {
		bool allowed = false;
		/* Toggle path slightly to prevent pure static branch prediction caching */
		if (i % 2 == 0) {
			strcpy(ectx.params.api.request_path, "/api/v1/data/123");
		} else {
			strcpy(ectx.params.api.request_path, "/api/v1/data/456");
		}

		perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
	}

	long long end	  = time_in_us();
	long long elapsed = end - start;
	double	  qps	  = (double)iterations * 1000000.0 / (double)elapsed;

	printf("\n=========================================\n");
	printf("         Permission Engine Benchmark\n");
	printf("=========================================\n");
	printf(" Total iterations : %d ops\n", iterations);
	printf(" Total elapsed    : %lld us (%.2f ms)\n", elapsed, elapsed / 1000.0);
	printf(" Average latency  : %.2f us/op\n", (double)elapsed / iterations);
	printf(" Throughput (QPS) : %.2f ops/sec\n", qps);
	printf("=========================================\n\n");

	perm_engine_destroy(pengine);
	policy_manager_destroy(pmgr);
	role_manager_destroy(rmgr);
	user_manager_destroy(umgr);
	storage->close(storage);
	free(storage);

	return 0;
}
