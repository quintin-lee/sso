# SSO 系统设计文档

## 目录

1. [设计原则](#1-设计原则)
2. [设计模式](#2-设计模式)
3. [数据结构设计](#3-数据结构设计)
4. [令牌设计](#4-令牌设计)
5. [权限评估模型](#5-权限评估模型)
6. [策略插件系统](#6-策略插件系统)
7. [缓存设计](#7-缓存设计)
8. [并发与线程安全](#8-并发与线程安全)
9. [安全设计](#9-安全设计)
10. [内存管理](#10-内存管理)
11. [错误处理哲学](#11-错误处理哲学)
12. [配置系统](#12-配置系统)
13. [构建系统设计](#13-构建系统设计)
14. [设计权衡与决策记录](#14-设计权衡与决策记录)

---

## 1. 设计原则

### 1.1 核心原则

| 原则 | 具体体现 |
|------|----------|
| **性能至上** | 零拷贝 JSON 解析、预编译规则、三级缓存、arena 分配器、无锁计数器 |
| **安全封闭** | DENY-Override 模型、Argon2id 哈希、sodium 内存锁定、fail-closed |
| **存储无关** | 存储后端 vtable 抽象、业务层不感知具体数据库 |
| **可扩展** | 策略插件系统（注册新策略只需实现 4 个函数） |
| **最小意外** | 遵循 HTTP 语义、标准 OAuth 2.0/OIDC、自包含 JWT |

### 1.2 编码约束

- C11 标准（`-std=c11`），严格 `-Wall -Wextra -Wpedantic`
- BSD 风格缩进（制表符缩进，4 列宽度）
- `snake_case` 命名空间前缀（`perm_engine_`, `token_`, `sso_`）
- 所有分配必须检查返回值（`malloc`/`calloc` 不可失败假设）
- 字符串安全：`sso_strlcpy` 宏保证始终以 NUL 结尾

---

## 2. 设计模式

### 2.1 VTable 模式 — 存储抽象层

**问题**：系统需要支持多种数据库后端（SQLite、PostgreSQL、Redis、内存），业务代码不应耦合于特定数据库。

**解决方案**：使用函数指针结构体（VTable）实现纯虚接口。

```c
// storage_backend 是一个包含~40个函数指针的结构体
// 每个具体后端实现填充这些指针
// 业务代码始终通过 storage_backend->user_create() 调用

struct storage_backend {
    storage_user_create_fn  user_create;
    storage_user_get_by_id_fn user_get_by_id;
    // ... 约 40 个函数指针
    void *handle;  // 后端私有状态
};
```

**优点**：
- 新增后端只需实现一个 `.c` 文件，无需修改业务代码
- 编译时依赖分离（SQLite 后端只在链接 libsqlite3 时生效）
- 测试时可用内存后端，无需真实数据库

### 2.2 策略模式 — 权限策略注册表

**问题**：7 种权限策略共享相同的评估生命周期（init → compile → evaluate → destroy），但每种策略的实现逻辑完全不同。

**解决方案**：定义 `permission_strategy_t` 接口，每种策略独立实现该接口。

```c
// 统一的策略接口
typedef struct {
    perm_strategy_type_t type;
    sso_error_t (*compile_rules)(..., const char *rules_json, void **compiled);
    sso_error_t (*evaluate)(..., eval_context_t *, const policy_t *,
                            void *compiled, bool *result);
    // ...
} permission_strategy_t;
```

**优点**：
- 新增策略只需写一个 `.c` 文件 + 在 `perm_engine_create()` 中注册
- 运行时按类型查找，O(1) 调度
- 每种策略独立管理自己的预编译规则结构

### 2.3 外观模式 — sso_context_t

**问题**：权限引擎需要访问用户管理器、角色管理器、策略管理器等 7+ 子系统。

**解决方案**：`sso_context_t` 作为统一的外观，持有所有子系统指针。

```c
typedef struct {
    storage_backend_t  *storage_backend;
    token_manager_t    *token_mgr;
    user_manager_t     *user_mgr;
    role_manager_t     *role_mgr;
    group_manager_t    *group_mgr;
    policy_manager_t   *policy_mgr;
    permission_engine_t *perm_engine;
    rate_limiter_t     *rate_limiter;
    void               *config;  // sso_config_t
} sso_context_t;
```

### 2.4 工厂模式 — 存储后端创建

```c
// 统一的工厂函数，根据配置创建对应后端
if (strcmp(cfg->database_type, "postgres") == 0)
    err = storage_postgres_create(&storage);
else if (strcmp(cfg->database_type, "redis") == 0)
    err = storage_redis_create(&storage);
else
    err = storage_sqlite_create(&storage);
```

### 2.5 直接索引哈希表 — 缓存

**问题**：策略 ID 和用户 ID 是密集的递增整数序列，通用哈希函数增加了不必要的计算开销。

**解决方案**：利用 ID 的密集性，使用模运算直接索引 + 线性探测处理冲突。

```c
// L0 缓存: 策略规则编译缓存
size_t idx = (size_t)policy_id % MAX_POLICY_CACHE;  // 256
// 以 policy_id 为键直接模运算定位槽位
// 线性探测处理冲突

// L1 缓存: 策略解析缓存
size_t idx = ctx->user_id % POLICY_RES_CACHE_SIZE;  // 128

// L2 缓存: 决策结果缓存
uint32_t hash = hash_params(ctx);  // DJB2 哈希
size_t idx = hash % RESULT_CACHE_SIZE;  // 1024
```

**优点**：模运算比通用哈希快一个数量级，对密集 ID 序列几乎无冲突。

---

## 3. 数据结构设计

### 3.1 核心实体关系

```
用户 ──┬──▶ 角色 (多对多, 通过分配表)
      │     └──▶ 角色层级 (父-子自引用)
      │
      └──▶ 组 (多对多, 通过成员表)
            └──▶ 组层级 (父-子自引用)

角色 ──▶ 策略 (多对多, 通过分配表)
组   ──▶ 策略 (多对多, 通过分配表)
用户 ──▶ 策略 (直接分配, 多对多)

策略 ──▶ 策略类型 (FUNCTIONAL/API/DATA/RBAC/LOCATION/ABAC/LBAC)
```

### 3.2 策略结构

```c
struct policy {
    sso_id_t              id;
    char                  name[SSO_MAX_POLICY_NAME];   // 128
    perm_strategy_type_t  strategy_type;                // 7 种策略类型
    policy_effect_t       default_effect;               // ALLOW 或 DENY
    int                   priority;                     // 优先级值（越高越优先）
    char                  rules[SSO_MAX_RULES_JSON];    // 4096 字节 JSON
    policy_status_t       status;                       // 启用/禁用
    // ...
};
```

### 3.3 评估上下文

```c
typedef struct {
    const user_t  *user;
    sso_id_t       user_id;
    char           environment[256];  // 环境标签（"production", "staging"）

    union {
        // 功能权限参数: function_code
        struct { char function_code[128]; } functional;

        // API 权限参数: http_method + request_path
        struct { char http_method[16]; char request_path[512]; } api;

        // 数据权限参数: resource_type + record + field_filter
        struct { char resource_type[64]; char *record; ... } data;

        // RBAC 参数: role_name
        struct { char role_name[128]; } rbac;

        // 位置参数: source_ip + geo_country
        struct { char source_ip[64]; char geo_country[4]; } location;

        // ABAC 参数: subject_attrs + resource_attrs + action
        struct { char subject_attrs[512]; char resource_attrs[512]; char action[64]; } abac;

        // LBAC 参数: user_labels + resource_label
        struct { char user_labels[256]; char resource_label[64]; } lbac;
    } params;

    void *userdata;  // 策略运行时私有数据
} eval_context_t;
```

### 3.4 令牌内部结构

```c
struct token {
    char            token_str[SSO_MAX_TOKEN_STR];  // 原始 JWT 字符串
    char            jti[64];                       // 唯一令牌 ID
    sso_id_t        user_id;                       // 用户 ID
    sso_timestamp_t issued_at;                     // 签发时间
    sso_timestamp_t expires_at;                    // 过期时间
    sso_id_t       *role_ids;                      // 令牌内缓存的角色 ID 数组
    size_t          role_count;                    // 角色数量
    sso_id_t       *group_ids;                     // 令牌内缓存的组 ID 数组
    size_t          group_count;                   // 组数量
    uint64_t        nonce;                         // 用户令牌 nonce 版本
    char            jkt[64];                       // DPoP 公钥指纹
    char            raw_refresh_token[128];        // 刷新令牌字符串
};
```

**为什么在令牌中嵌入角色和组？** — 避免每次请求都查询数据库。令牌在认证时签发一次，后续请求直接解码即可获取用户的角色/组信息，零数据库开销。

---

## 4. 令牌设计

### 4.1 设计决策：自包含（Stateless）令牌

**选择 JWT 而非 Session**：

| 维度 | JWT（自包含） | Session（状态化） |
|------|-------------|-----------------|
| 验证延迟 | 一次 HMAC 验证，无数据库查询 | 每次请求需查询数据库/缓存 |
| 伸缩性 | 天然无状态，水平扩展零额外成本 | 需共享 Session 存储（Redis/DB） |
| 撤销 | 需维护撤销列表（O(log N)） | 删除 Session 即可 |
| 负载 | 令牌中可嵌入角色/组信息 | 每次请求需重新查询 |

**结论**：选择 JWT 作为主要令牌格式，配合撤销列表实现即时撤销能力。

### 4.2 签名选择：HS256 vs RS256

| | HS256 | RS256 |
|--|-------|-------|
| 性能 | 快（对称加密） | 慢（约 10x，非对称） |
| 密钥分发 | 共享密钥（需保护） | 公钥随意分发 |
| 验证方 | 只有 SSO 可验证 | 任何持有公钥的服务可验证 |
| 推荐场景 | 单服务部署 | 微服务架构（API 网关验证） |

**设计决策**：支持两者，通过配置自动选择。HS256 为默认，`SSO_PRIVATE_KEY` 设置时自动升级到 RS256。

### 4.3 Nonce 撤销机制

```c
// 每个用户维护一个 nonce 计数器
// 令牌签发时嵌入当前 nonce
// 验证时检查 nonce 是否匹配
// token_bump_nonce() → nonce++ → 该用户全部令牌立即失效

// 用于 "logout all" 场景
// O(1) 时间复杂度，无需遍历撤销列表
```

### 4.4 撤销列表

```
撤销列表维护 revoked JTIs 的排序数组：
  - 追加时无序插入 → O(1)
  - 验证时先排好序 → 二分查找 O(log N)
  - 定期清理过期条目
  - 使用 pthread_mutex 保护
```

### 4.5 会话管理

```
每个用户最多 SSO_MAX_CONCURRENT_SESSIONS (3) 个活动会话：
  - 签发新令牌时注册会话
  - 超过限制时自动撤销最旧会话的 JTI
  - 通过 session_track_t 结构追踪
```

---

## 5. 权限评估模型

### 5.1 模型选择：DENY-Override

```
输入: 策略列表（按优先级降序）

评估逻辑:
  对于每个策略 policy in policies:
    如果策略禁用 → 跳过
    如果策略不匹配 → 跳过
    如果策略评估为 DENY → 立即返回 DENY
    如果策略评估为 ALLOW → 记录已匹配

  最终: 如果有任意 ALLOW → 返回 ALLOW
        否则 → 返回 DENY (默认拒绝)
```

**为什么是 DENY-Override 而非 ALLOW-Override？**

| 模型 | 行为 | 安全性 |
|------|------|--------|
| DENY-Override | 任何 DENY 立即否决 | **Fail-Closed**（安全） |
| ALLOW-Override | 任何 ALLOW 立即放行 | Fail-Open（危险） |

- DENY-Override 确保即使配置错误，未授权的操作也被拒绝
- 符合最小权限原则
- 符合企业合规要求（默认拒绝）

### 5.2 策略优先级解析

```
策略解析 chain:
  1. 用户直接分配的策略
  2. 用户所属角色的策略（含角色继承链上的祖先角色）
  3. 用户所属组的策略（含组继承链上的祖先组）

所有策略按 priority 值降序合并排序（值越大优先级越高）。
```

### 5.3 策略冲突解决

```json
// 示例：admin 角色配置了 "user:delete" → deny
// member 角色配置了 "profile:edit" → allow
// 管理员同时拥有两个角色，执行 "user:delete" 时：
//   1. admin 策略匹配 → result = DENY
//   2. DENY-Override → 立即返回 DENY
```

---

## 6. 策略插件系统

### 6.1 策略生命周期

```
初始化阶段:
    perm_engine_create()
      └─ perm_engine_register_strategy(&func_perm_strategy)
           └─ strategy->init()             ← 策略初始化

策略创建阶段（用户操作）:
    policy_create()
      └─ strategy->validate_rules()        ← 验证规则 JSON 格式
      └─ strategy->compile_rules()         ← 预编译为内存结构
           └─ perm_engine_cache_rule()     ← 缓存编译结果

运行时评估:
    perm_engine_evaluate()
      └─ perm_engine_evaluate_policy()
           └─ strategy->evaluate()          ← 零 JSON 解析

策略更新:
    policy_update() 或 policy_delete()
      └─ perm_engine_cache_invalidate_policy()  ← 清除编译缓存
           └─ strategy->free_compiled_rules()   ← 释放旧编译结构
```

### 6.2 预编译示例：Functional 策略

```json
// 规则 JSON（用户保存的原始格式）
{
  "functions": [
    {"code": "admin:*", "effect": "allow"},
    {"code": "user:create", "effect": "allow"},
    {"code": "user:delete", "effect": "deny"}
  ]
}
```

```c
// 编译后的内存结构（运行时使用的格式）
typedef struct {
    char    code[128];    // "admin:*"
    bool    is_allow;     // true
} func_rule_item_t;

typedef struct {
    func_rule_item_t *items;  // 3 个规则项
    size_t            count;  // 3
} func_compiled_rule_t;
```

**运行时评估**：`wildcard_match("admin:*", function_code)` — 纯字符串匹配，无 JSON 解析开销。

### 6.3 API 策略通配

```
模式: {method, path, effect}

path 支持 3 种通配符:
  /api/v1/*          → 单级通配（匹配 /api/v1/xxx，不匹配 /api/v1/xxx/yyy）
  /api/v1/**         → 多级通配（匹配 /api/v1/xxx/yyy/zzz）
  /api/v1/:id        → 命名参数（匹配 /api/v1/42，捕获 42 到 params）
```

---

## 7. 缓存设计

### 7.1 三级缓存时序

```
请求 → L2 (30s) → miss → L1 (60s) → miss → 数据库查询 → 编译 → 评估
        ↓ hit          ↓ hit
      返回结果       跳过查询
```

**为什么三级缓存？**

| 级别 | 容量 | TTL | 命中率预期 | 避免的开销 |
|------|------|-----|-----------|-----------|
| L0 | 256 | 永久(主动失效) | ~100% | JSON 解析 + 规则编译 |
| L1 | 128 | 60s | 高 | 策略解析数据库查询 |
| L2 | 1024 | 30s | 高 | 完整评估链 |

### 7.2 缓存一致性

**场景**：管理员修改了某个策略 → 该策略影响的所有用户的决策立即需要更新。

```
perm_engine_cache_invalidate_policy(policy_id):
  1. 从 L0 策略缓存中移除该策略的编译规则（并调用 free_compiled_rules 释放内存）
  2. 清空 L1 策略解析缓存（所有用户的策略列表）
  3. 清空 L2 决策结果缓存（所有用户的决策缓存）

为什么清空 L1 和 L2？
  - 策略变更可能影响任意用户，逐个清理计算复杂度过高
  - L1 仅 128 项、L2 仅 1024 项，清空代价很小
  - 下一次请求自动重新计算并填充缓存
```

### 7.3 缓存并发控制

```c
// L1/L2 缓存使用 pthread_rwlock_t:
//   - 读取：持读锁（多个线程可以同时读）
//   - 写入：持写锁（完全互斥）

// Phase 1: L2 检查（读锁）
pthread_rwlock_rdlock(&engine->lock);
if (engine->result_cache[...].valid && ...) {
    // 命中 → 返回
}
pthread_rwlock_unlock(&engine->lock);

// Phase 2: L1 检查（读锁）→ 未命中则释放锁，执行数据库查询

// Phase 3: 更新 L1/L2（写锁）
pthread_rwlock_wrlock(&engine->lock);
// 写入缓存
pthread_rwlock_unlock(&engine->lock);
```

**双重检查锁定（Double-Checked Locking）**：L1 未命中时，在升级到写锁之前会重新检查一次缓存，防止多个线程同时为同一个用户查询数据库。

---

## 8. 并发与线程安全

### 8.1 锁使用总览

| 数据结构 | 锁类型 | 用途 |
|----------|--------|------|
| 权限引擎 | `pthread_rwlock_t` | 保护策略注册表 + 各级缓存 |
| 令牌管理器 nonce | `pthread_mutex_t` | 保护 nonce 数组 |
| 令牌管理器 rev | `pthread_mutex_t` | 保护撤销列表 |
| 令牌管理器 session | `pthread_mutex_t` | 保护会话追踪 |
| 速率限制器 | `pthread_mutex_t` | 保护 DJB2 哈希表 |
| 审计日志文件 | `PTHREAD_MUTEX_INITIALIZER` | 保护日志文件写入 |
| 多租户注册表 | `pthread_mutex_t` | 保护租户上下文数组 |
| 指标计数器 | `atomic_fetch_add` | 无锁更新 |

### 8.2 无锁设计

- **请求 ID 生成**：`atomic_fetch_add(&g_request_counter, 1)` — 全局递增计数器
- **指标收集**：`atomic_fetch_add(&engine->metrics.total_evals, 1)` — 零开销监控
- **全局指标**：`atomic_int` / `atomic_ullong` 声明

### 8.3 线程局部存储（TLS）

```c
static _Thread_local arena_t   t_arena;         // 线程局部 arena 分配器
static _Thread_local bool      t_arena_init;    // 线程局部初始化标志

// 每个线程第一次被调度时初始化 arena
// HTTP 请求处理期间从 arena 分配内存
// 请求结束后 arena_reset() 一次释放

// 请求 ID 也通过 TLS 传播：
log_set_request_id(req.request_id);
// 此后该线程的所有 LOG_* 自动包含此 request_id（无需参数传递）
```

### 8.4 线程池工作模型

```
主线程: accept → pool_submit (O(1) 入队, cond_signal)
工作线程: wait (cond_wait) → dequeue → handle_client → 返回等待
```

**性能优势**：
- 无动态线程创建开销（固定线程池）
- 任务队列为有界环形缓冲区，避免无限积压
- `pthread_cond_signal` 通知而非轮询，CPU 空闲时零占用

---

## 9. 安全设计

### 9.1 密码安全

| 层级 | 技术 | 说明 |
|------|------|------|
| **哈希算法** | Argon2id | libsodium 实现，抗 GPU/ASIC 攻击 |
| **参数配置** | opslimit=3, memlimit=256MB | 可配置，生产建议使用 MODERATE |
| **传输保护** | TLS | 可选 HTTPS 传输加密 |
| **速率限制** | 5次/分钟/IP | 防止暴力破解 |

### 9.2 密钥安全

```c
// 1. 秘钥加载到内存后立即锁定
if (sodium_mlock(secret, SSO_SECRET_BYTES) != 0) {
    // 防止操作系统将密钥交换到磁盘
}

// 2. 使用完成后立即安全擦除
sodium_memzero(secret, SSO_SECRET_BYTES);

// 3. 令牌 secret 仅存在于 token_manager 内部结构
//    sso_config_t 中的拷贝在初始化后立即 sodium_memzero 擦除
```

### 9.3 HTTP 安全头

所有响应默认包含安全头：

| 头部 | 值 | 目的 |
|------|-----|------|
| `X-Content-Type-Options` | `nosniff` | 防 MIME 类型嗅探 |
| `X-Frame-Options` | `SAMEORIGIN` | 防点击劫持 |
| `Content-Security-Policy` | `default-src 'self'; ...` | 防 XSS |
| `Permissions-Policy` | `geolocation=(), ...` | 限制 API 权限 |
| `Strict-Transport-Security` | `max-age=31536000` | TLS 仅限 |

### 9.4 CORS

- 动态 Origin 回显：响应 `Access-Control-Allow-Origin` 设置为请求的 `Origin`
- 支持凭据：`Access-Control-Allow-Credentials: true`
- 预检请求处理：OPTIONS 请求返回允许的 Methods

### 9.5 速率限制

```c
// 滑动窗口算法
// 数据结构: DJB2 哈希表 (key=IP地址, value=请求时间戳数组)
// 窗口: 可配置（登录默认 1分钟）
// 阈值: 可配置（登录默认 5次）
// 成功登录后自动 reset：rate_limiter_reset(rl, ip)
```

### 9.6 审计追踪

所有权限决策和关键管理操作均记录到审计日志：

```json
// 权限决策审计
{"action":"eval","timestamp_ms":...,"user_id":1,
 "decision":"DENY","duration_ms":0.5,"cache_hit":false,
 "trace":"[Policy View Access] Strategy api: DENY"}

// 管理操作审计
{"action":"admin","timestamp_ms":...,"user_id":1,
 "username":"admin","operation":"policy_create",
 "resource":"policy","status":"success"}
```

### 9.7 密码策略

`password_policy_t` 支持以下约束：

| 规则 | 字段 | 说明 |
|------|------|------|
| 最小长度 | `min_length` | 密码最短字符数 |
| 大写字母 | `require_uppercase` | 至少包含一个大写字母 |
| 数字 | `require_digit` | 至少包含一个数字 |
| 特殊字符 | `require_special` | 至少包含一个特殊字符 |
| 历史 | `history_check` | 不可与最近 N 次密码重复 |

---

## 10. 内存管理

### 10.1 Arena 分配器

**核心思想**：以请求为生命周期单位，预分配大块内存，请求处理完后一次性释放。

```c
// 每线程、每请求的 arena
static _Thread_local arena_t t_arena;
arena_init(&t_arena, 4096);  // 初始化 4KB 块

// 请求处理中分配
char* buf = arena_alloc(&t_arena, 100);  // 从 arena 切分
char* str = arena_strdup(&t_arena, "hello");  // 复制字符串到 arena

// 请求处理完后
arena_reset(&t_arena);  // 重置 arena，不调用 free
```

| 对比 | malloc/free | Arena |
|------|------------|-------|
| 每次分配开销 | 系统调用 + 内存管理元数据 | 指针移动（O(1)） |
| 释放开销 | 每个对象逐一 free | 一次性 reset |
| 内存碎片 | 累积碎片 | 无碎片（整块分配） |
| 适用场景 | 长生命周期对象 | 短生命周期（请求级别） |

### 10.2 内存安全

- 所有 `malloc`/`calloc` 返回值检查
- `sso_strlcpy` 保证目标字符串始终 NUL 终止
- 令牌密钥使用 `sodium_mlock` 锁定在 RAM
- 敏感数据使用 `sodium_memzero` 安全擦除
- 全局指标使用原子操作，防止数据竞争

---

## 11. 错误处理哲学

### 11.1 错误码体系

```c
typedef enum {
    SSO_OK = 0,              // 成功
    SSO_ERR_GENERAL,         // 通用错误
    SSO_ERR_NOT_FOUND,       // 资源未找到
    SSO_ERR_ALREADY_EXISTS,  // 资源已存在
    SSO_ERR_INVALID_PARAM,   // 参数无效
    SSO_ERR_NO_PERMISSION,   // 权限拒绝
    SSO_ERR_AUTH_FAILED,     // 认证失败
    SSO_ERR_TOKEN_EXPIRED,   // 令牌过期
    SSO_ERR_TOKEN_INVALID,   // 令牌无效
    SSO_ERR_STORAGE,         // 存储错误
    SSO_ERR_RATE_LIMIT,      // 速率限制
    SSO_ERR_OUT_OF_MEMORY,   // 内存不足
    SSO_ERR_NOT_IMPLEMENTED, // 未实现
    // ... 共 21 种
} sso_error_t;
```

### 11.2 错误处理规则

1. **永不静默忽略错误**：所有函数返回 `sso_error_t`
2. **调用者必须检查返回值**：除非文档明确说明
3. **传播错误**：下层错误向上层传播，保留原始错误码
4. **日志记录**：关键错误点记录 `LOG_ERROR`
5. **内存错误不可恢复**：`SSO_ERR_OUT_OF_MEMORY` 快速失败

### 11.3 HTTP 错误映射

```c
SSO_OK                   → 200/201
SSO_ERR_INVALID_PARAM   → 400 Bad Request
SSO_ERR_AUTH_FAILED     → 401 Unauthorized
SSO_ERR_TOKEN_EXPIRED   → 401 Unauthorized ("Token expired")
SSO_ERR_NO_PERMISSION   → 403 Forbidden
SSO_ERR_NOT_FOUND       → 404 Not Found
SSO_ERR_RATE_LIMIT      → 429 Too Many Requests
SSO_ERR_OUT_OF_MEMORY   → 500 Internal Server Error
```

---

## 12. 配置系统

### 12.1 三层优先级

```
1. 环境变量覆盖（最高优先级）
   SSO_HOST=0.0.0.0 SSO_PORT=9090 ./sso_system --server

2. TOML 配置文件（中间优先级）
   ./sso_system -c /etc/sso/config.toml

3. 默认值（最低优先级）
   sso_config_default() → host="0.0.0.0", port=8080, ...
```

### 12.2 配置节

| 配置节 | 配置项数 | 关键配置 |
|--------|----------|----------|
| `[server]` | 6 | host, port, thread_pool_size, max_body_size |
| `[database]` | 4 | path, database_type, database_url |
| `[security]` | 8 | token_secret, token_ttl_ms, private_key_pem |
| `[oauth]` | 5 | client_id, client_secret, redirect_uris, issuer |
| `[logging]` | 2 | log_level, log_format |
| `[ratelimit]` | 1 | max_ips |
| `[sms]` | 2 | gateway_url, api_key |
| `[password_policy]` | 1 | 内嵌 policy 结构 |

---

## 13. 构建系统设计

### 13.1 Makefile 构建目标

| 目标 | 说明 | 编译标志 |
|------|------|----------|
| `make` | Release 构建 | `-O2 -DSSO_RELEASE` |
| `make debug` | Debug 构建 | `-O0 -g -DDEBUG` |
| `make asan` | ASan 构建 | `-fsanitize=address,undefined` |
| `make test` | 单元测试 | `-O2` + 链接测试文件 |
| `make profile` | 性能分析 | `-O2 -pg` |
| `make size` | 二进制大小统计 | `size` 命令 |

### 13.2 依赖管理

| 库 | 链接选项 | 可选性 |
|----|----------|--------|
| libsodium | `-lsodium` | 必需 |
| libssl/crypto | `-lssl -lcrypto` | 必需 |
| libsqlite3 | `-lsqlite3` | 可选（SQLite 后端） |
| libcurl | `-lcurl` | 可选（短信网关） |
| libmicrohttpd | `-lmicrohttpd` | 可选（HTTP 服务器） |
| libpthread | `-lpthread` | 必需 |

---

## 14. 设计权衡与决策记录

### 14.1 为什么不用 C++？

- 项目目标是嵌入式/轻量级 SSO 服务，C 的链接体积更小
- 函数指针 vtable 可以完全替代虚函数
- 避免 C++ 的 ABI 不稳定
- 与系统库（OpenSSL, libsodium, libcurl）的 C API 天然兼容

### 14.2 为什么自有 HTTP 服务器而非嵌入 Nginx/Apache？

- 独立部署，零外部依赖
- 控制权完全在项目手中（可针对 SSO 场景深度优化）
- libmicrohttpd 是成熟的嵌入式 HTTP 库

### 14.3 为什么使用 JWT 而非 Session Cookie？

- 微服务友好：其他服务可自行验证令牌
- 无状态：服务器重启不影响活动令牌
- 减少数据库负载：认证检查无需查询

### 14.4 为什么策略规则用 JSON 而非 DSL？

- JSON 普适性强，前端/管理工具无需特殊解析器
- 配合 yyjson 实现零拷贝、高性能解析
- 规则结构简单，JSON 足够表达

### 14.5 为什么缓存失效清空而非精确更新？

- 策略变更影响范围不确定（可能影响所有用户）
- L1 仅 128 项、L2 仅 1024 项，清空开销极小
- 精确追踪依赖关系的复杂度远高于重新计算

### 14.6 Thread Pool vs Event Loop？

| | Thread Pool | Event Loop |
|--|------------|------------|
| 模型 | 一个线程处理一个请求 | 单线程处理所有请求 |
| CPU 密集任务 | 不阻塞其他请求 | 阻塞所有请求 |
| 代码复杂度 | 需处理线程同步 | 简单（无锁） |
| 方案选择 | 选择 Thread Pool | - |

**决策**：权限评估是 CPU 密集型操作（JSON 编译、字符串通配匹配），使用线程池避免单个慢请求拖垮全局。
