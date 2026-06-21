# SSO 系统架构文档

## 目录

1. [系统概述](#1-系统概述)
2. [整体架构](#2-整体架构)
3. [模块分层](#3-模块分层)
4. [核心流程](#4-核心流程)
5. [存储抽象层](#5-存储抽象层)
6. [权限引擎](#6-权限引擎)
7. [缓存架构](#7-缓存架构)
8. [令牌系统](#8-令牌系统)
9. [HTTP 服务器与线程模型](#9-http-服务器与线程模型)
10. [认证策略体系](#10-认证策略体系)
11. [多租户架构](#11-多租户架构)
12. [可观测性](#12-可观测性)
13. [部署架构](#13-部署架构)

---

## 1. 系统概述

SSO（Single Sign-On）系统是一个用 C11 编写的高性能、企业级单点登录与授权服务。它提供统一的**身份认证**和**细粒度权限控制**，专为高并发微服务架构设计。

### 核心特性

| 维度 | 能力 |
|------|------|
| **认证** | 密码认证（Argon2id）、短信验证码、WebAuthn/FIDO2 免密码认证、TOTP 多因素认证 |
| **授权** | 7 种权限策略：功能权限、API 端点、数据范围、RBAC、位置/IP、ABAC、LBAC |
| **协议** | OAuth 2.0（授权码流程）、OpenID Connect（OIDC）、DPoP 绑定令牌 |
| **性能** | 单核 35K+ QPS，权限评估亚 30μs 延迟 |
| **存储** | SQLite、PostgreSQL、Redis、内存 — 插件式替换 |
| **安全** | Argon2id 密码哈希、HMAC-SHA256/RS256 令牌签名、TLS、速率限制、审计日志 |

### 版本信息

当前版本：v1.1.0，基于 C11 标准（`-std=c11`），编译于 `-Wall -Wextra -Wpedantic`。

---

## 2. 整体架构

### 2.1 架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                         客户端层                                  │
│  浏览器 / 移动 App / 微服务 / curl / 第三方应用                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     API 网关 / 反向代理                            │
│              Nginx / Envoy / Cloud LB                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │ http(s) + Bearer Token / DPoP
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SSO 系统 (C11)                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    HTTP 服务器层                           │   │
│  │   libmicrohttpd (首选) / POSIX Socket (回退)               │   │
│  │   线程池 · 请求解析 · TLS · CORS · 速率限制                 │   │
│  └────────────────────┬─────────────────────────────────────┘   │
│                       │                                         │
│                       ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    路由 & 认证中间件                       │   │
│  │   路由匹配（O(1) per-method hash）· JWT 验证 · DPoP 验证   │   │
│  └────────────────────┬─────────────────────────────────────┘   │
│                       │                                         │
│                       ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 HTTP Handler 层                           │   │
│  │   认证处理器 · 用户/角色/组/策略 CRUD · OAuth/OIDC · 权限检查  │   │
│  └────────────────────┬─────────────────────────────────────┘   │
│                       │                                         │
│                       ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   业务逻辑层                               │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐      │   │
│  │  │用户  │ │角色  │ │组    │ │策略  │ │令牌(Token)│      │   │
│  │  │管理器│ │管理器│ │管理器│ │管理器│ │管理器    │      │   │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └────┬─────┘      │   │
│  │     │        │        │        │           │            │   │
│  │     └────────┴────────┴────────┴───────────┘            │   │
│  │                        │                                │   │
│  │                        ▼                                │   │
│  │  ┌──────────────────────────────────────────┐           │   │
│  │  │             权限引擎                      │           │   │
│  │  │  L1/L2 缓存 · 7 策略注册表 · 审计日志      │           │   │
│  │  └──────────────────────────────────────────┘           │   │
│  └────────────────────┬─────────────────────────────────────┘   │
│                       │                                         │
│                       ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               存储抽象层 (Storage Backend VTable)           │   │
│  │               统一接口 · 插件式实现                         │   │
│  └──────────┬──────────┬──────────┬──────────┬──────────────┘   │
│             │          │          │          │                  │
│             ▼          ▼          ▼          ▼                  │
│         SQLite    PostgreSQL   Redis      内存                  │
│         (WAL)     (libpq)   (hiredis)   (hash表)               │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 模块依赖关系

```
sso_init() 初始化顺序（从左到右依赖依赖链）：

  存储 → 速率限制器 → 令牌管理器 → 用户管理器 → 角色管理器
      → 组管理器 → 策略管理器 → 权限引擎

销毁顺序与初始化顺序相反（逆序析构）。
```

### 2.3 项目结构

```
sso/
├── include/          # 公共头文件（API 声明）
│   ├── sso.h        # 核心类型、错误码、eval_context、策略 vtable
│   ├── server.h     # HTTP 服务器抽象、路由调度类型
│   ├── storage.h    # 存储后端 vtable 定义
│   ├── token.h      # JWT 令牌格式、生命周期
│   ├── permission.h # 权限引擎 API
│   ├── policy.h     # 策略定义（规则 JSON、优先级、效果）
│   ├── user.h / role.h / group.h / config.h
│   ├── oauth.h / webauthn.h / mfa.h / dpop.h
│   └── ratelimit.h / risk.h / logger.h / yyjson.h
├── src/              # 实现源码
│   ├── main.c       # 入口点：demo/server/interactive 三种模式
│   ├── sso.c        # 核心生命周期：sso_init(), sso_destroy()
│   ├── server.c     # POSIX socket HTTP 服务器 + 线程池
│   ├── server_mhd.c # libmicrohttpd HTTP 服务器后端
│   ├── permission.c # 权限引擎核心（L1/L2 缓存、策略调度、审计）
│   ├── token.c      # 令牌管理（HMAC-SHA256、二分查找撤销）
│   ├── oauth.c      # OAuth 2.0 / OIDC 端点实现
│   ├── user.c / role.c / group.c / policy.c
│   ├── config.c     # TOML 解析 + 环境变量覆盖
│   ├── ratelimit.c  # 滑动窗口速率限制
│   ├── risk.c       # 自适应风险评估引擎
│   ├── webauthn.c / mfa.c / dpop.c
│   └── storage_sqlite.c / yyjson.c / logger.c
├── strategies/       # 7 种可插拔权限策略
│   ├── func_perm.c   # 功能权限
│   ├── api_perm.c    # API 端点权限
│   ├── data_perm.c   # 数据范围权限
│   ├── rbac_perm.c   # 基于角色的访问控制
│   ├── loc_perm.c    # 位置/IP 权限
│   ├── abac_perm.c   # 基于属性的访问控制
│   └── lbac_perm.c   # 基于标签的访问控制
├── tests/            # 单元测试 + 集成测试
├── frontend/         # Vue.js 管理后台前端
├── Makefile          # 跨平台构建系统
├── Dockerfile        # 多阶段 Docker 构建
└── sso.toml          # 默认 TOML 配置文件
```

---

## 3. 模块分层

### 3.1 核心类型层 (`include/sso.h`)

定义系统核心类型：

- **错误码枚举** `sso_error_t` — 21 种错误码
- **实体结构** — `user_t`, `role_t`, `group_t`, `policy_t`, `token_t`
- **策略 vtable** `permission_strategy_t` — 策略插件的接口契约
- **评估上下文** `eval_context_t` — 传递用户、参数和运行时上下文
- **上下文** `sso_context_t` — 系统全局上下文，持有所有管理器指针
- **HTTP 请求/响应** `http_request_t`, `http_response_t`

### 3.2 存储抽象层 (`storage_backend` vtable)

以函数指针表（vtable）实现存储无关性。所有业务模块通过这个抽象层访问持久化数据，不依赖任何具体数据库实现。

详见[第 5 节 — 存储抽象层](#5-存储抽象层)。

### 3.3 业务逻辑层（管理器模块）

| 管理器 | 职责 | 关键操作 |
|--------|------|----------|
| **用户管理器** | 用户账户 CRUD、密码认证（Argon2id）、角色/组成员查询 | `user_create`, `user_authenticate`, `user_get_roles` |
| **角色管理器** | 角色定义 CRUD、层级继承、用户/组分配 | `role_create`, `role_get_ancestors`, `role_assign_to_user` |
| **组管理器** | 组织单元 CRUD、嵌套层级、成员管理 | `group_create`, `group_get_ancestors`, `group_add_user` |
| **策略管理器** | 策略定义 CRUD、按目标解析（用户/角色/组）、优先级排序 | `policy_create`, `policy_resolve_for_user` |
| **令牌管理器** | JWT 签发/验证、撤销（二分查找）、nonce 追踪、会话管理 | `token_issue`, `token_verify`, `token_revoke` |
| **速率限制器** | 滑动窗口速率限制、基于 DJB2 哈希表 | `rate_limiter_check`, `rate_limiter_reset` |

### 3.4 权限引擎 (`permission_engine`)

核心评估引擎，负责策略注册、规则编译缓存（L0）、策略解析缓存（L1）和决策缓存（L2）。

详见[第 6 节 — 权限引擎](#6-权限引擎)。

### 3.5 HTTP 服务器层

参见[第 9 节 — HTTP 服务器与线程模型](#9-http-服务器与线程模型)。

---

## 4. 核心流程

### 4.1 登录认证流程

```
客户端                          SSO 系统                         存储
  │                                │                              │
  │  POST /api/v1/auth/login        │                              │
  │  {username, password}           │                              │
  │ ──────────────────────────────▶ │                              │
  │                                │                              │
  │                                ├── rate_limiter_check()        │
  │                                │   (5次/分钟/IP)               │
  │                                │                              │
  │                                ├── user_get_by_username()     │
  │                                │ ────────────────────────────▶│
  │                                │◀────────────────────────────│
  │                                │                              │
  │                                ├── crypto_pwhash_str_verify() │
  │                                │   (Argon2id)                 │
  │                                │                              │
  │                                ├── risk_evaluate_login()      │
  │                                │   (异常检测)                  │
  │                                │                              │
  │                                ├── token_issue()              │
  │                                │   (HMAC-SHA256 / RS256)      │
  │                                │                              │
  │  {token, refresh_token,        │                              │
  │   user}                        │                              │
  │ ◀──────────────────────────────│                              │
```

### 4.2 权限检查流程

```
服务调用方                          SSO 系统
  │                                │
  │ POST /api/v1/check/functional  │
  │ Bearer: <token>                │
  │ {function_code: "admin:*"}     │
  │ ──────────────────────────────▶ │
  │                                │
  │  ┌── Phase 1: L2 结果缓存 ──┐  │
  │  │  hash(params) % 1024     │  │
  │  │  hit → 直接返回决策       │  │
  │  └──────────────────────────┘  │
  │                                │
  │  ┌── Phase 2: L1 策略解析缓存 ┐│
  │  │  user_id % 128            │  │
  │  │  hit → 跳过策略解析       │  │
  │  │  miss → policy_resolve_   │  │
  │  │         for_user()        │  │
  │  └──────────────────────────┘  │
  │                                │
  │  ┌── Phase 3: 逐策略评估 ────┐ │
  │  │  按优先级排序              │ │
  │  │  ↓                        │ │
  │  │  策略 -> 策略注册表查找    │ │
  │  │  ↓                        │ │
  │  │  编译规则 (L0 缓存)       │ │
  │  │  ↓                        │ │
  │  │  strategy->evaluate()     │ │
  │  │  ↓                        │ │
  │  │  DENY 覆盖: 任一 DENY     │ │
  │  │  → 立即返回 DENY          │ │
  │  └──────────────────────────┘  │
  │                                │
  │  ┌── Phase 4: 缓存 + 审计 ──┐ │
  │  │  L2 缓存决策结果          │ │
  │  │  审计日志记录              │ │
  │  └──────────────────────────┘  │
  │                                │
  │  {allowed: true/false}         │
  │ ◀──────────────────────────────│
```

### 4.3 OAuth 2.0 授权码流程

```
资源所有者(浏览器)         SSO (OAuth Provider)          第三方应用
     │                         │                           │
     │                         │                           │
     │                         │  redirect to authorize    │
     │                         │◀──────────────────────────│
     │                         │                           │
     │  GET /api/v1/oauth/     │                           │
     │  authorize?response_    │                           │
     │  type=code&client_id=   │                           │
     │  &redirect_uri=&scope=  │                           │
     │◀────────────────────────│                           │
     │                         │                           │
     │  用户认证并授权           │                           │
     │ ───────────────────────▶│                           │
     │                         │                           │
     │  redirect with code     │                           │
     │◀────────────────────────│                           │
     │                         │                           │
     │                         │  POST /api/v1/oauth/     │
     │                         │  token?code=&redirect_   │
     │                         │  uri=&code_verifier=     │
     │                         │  (PKCE)                  │
     │                         │◀──────────────────────────│
     │                         │                           │
     │                         │  {access_token,           │
     │                         │   refresh_token,          │
     │                         │   id_token}               │
     │                         │ ──────────────────────────▶│
```

### 4.4 令牌刷新与 DPoP 绑定

```
刷新令牌流程:

  POST /api/v1/auth/refresh
  Bearer: <expired_or_near_expiry_token>
  ───▶ token_verify() → token_refresh() → 新令牌

令牌撤销流程:

  POST /api/v1/auth/logout
  ───▶ token_revoke() → 将 JTI 插入撤销列表 (O(log N) 二分查找)
  POST /api/v1/auth/logout_all
  ───▶ token_bump_nonce() → 递增 nonce → 旧令牌全部失效

DPoP 绑定流程:

  1. 登录时客户端生成密钥对，计算 JWK Thumbprint (jkt)
  2. 令牌签发时将 jkt 嵌入令牌 claims
  3. 每次请求头带 DPoP Proof JWT，包含当前 HTTP 方法 + URL
  4. 服务端验证签名 & jkt 匹配 → 确保证据令牌未被窃取使用
```

---

## 5. 存储抽象层

### 5.1 VTable 设计

存储后端通过纯虚函数表（函数指针结构体）实现存储无关性：

```c
struct storage_backend {
    char name[32];           // 后端名称标识

    // 生命周期
    open_fn     open;
    close_fn    close;
    begin_fn    begin;
    commit_fn   commit;
    rollback_fn rollback;

    // 用户 CRUD（7 个函数指针）
    // 角色 CRUD（6 个函数指针）
    // 组 CRUD（6 个函数指针）
    // 策略 CRUD（6 个函数指针）
    // 分配表（15 个函数指针）
    // 层级查询（3 个函数指针）
    // OAuth 授权码（4 个函数指针）
    // 客户端管理（5 个函数指针）
    // 刷新令牌（3 个函数指针）
    // JTI 撤销（2 个函数指针）
    // 审计日志（2 个函数指针）

    void *handle;  // 后端私有数据（sqlite3*, FILE*, hashtable*）
};
```

### 5.2 实现后端

| 后端 | 实现文件 | 特点 |
|------|----------|------|
| **SQLite** | `src/storage_sqlite.c` | WAL 模式、递归 CTE 实现层级查询、生产主力 |
| **PostgreSQL** | `src/storage_postgres.c` | libpq、连接池、适合集群部署 |
| **Redis** | `src/storage_redis.c` | libhiredis、内存级速度、适合缓存场景 |
| **内存** | `src/storage_memory.c` | 哈希表实现、不可持久化、测试用 |

### 5.3 SQLite 模式特性

- **WAL（Write-Ahead Logging）**：并发读不堵塞写
- **递归 CTE（Common Table Expression）**：一条 SQL 查询完整角色/组继承链
- **外键约束**：保证引用完整性
- **即时事务**：每个写操作自动 begin/commit

---

## 6. 权限引擎

### 6.1 策略注册表

权限引擎维护一个策略数组 `strategies[MAX_STRATEGIES]`（最多 16 个），以 `pthread_rwlock_t` 保护。

7 种内置策略在引擎创建时自动注册：

| 注册顺序 | 策略类型 | enum 值 | 用途 |
|----------|----------|---------|------|
| 1 | Functional | `PERM_STRATEGY_FUNCTIONAL` | 菜单/按钮/功能开关 |
| 2 | API | `PERM_STRATEGY_API` | HTTP 方法 + 路径匹配 |
| 3 | Data | `PERM_STRATEGY_DATA` | 行级/字段级数据过滤 |
| 4 | RBAC | `PERM_STRATEGY_RBAC` | 角色继承 + 层级 |
| 5 | Location | `PERM_STRATEGY_LOCATION` | IP/地理区域 |
| 6 | ABAC | `PERM_STRATEGY_ABAC` | 属性表达式 |
| 7 | LBAC | `PERM_STRATEGY_LBAC` | 标签/密级 |

### 6.2 策略 vtable 接口

```c
typedef struct {
    perm_strategy_type_t type;          // 策略类型标识
    const char          *name;          // 策略名称
    sso_error_t (*init)(...);           // 初始化
    void        (*destroy)(...);        // 销毁
    sso_error_t (*compile_rules)(...);  // 编译规则 JSON → 内存结构（仅一次）
    void        (*free_compiled_rules)(...); // 释放编译后规则
    sso_error_t (*evaluate)(...);       // 运行时评估（key path）
    sso_error_t (*validate_rules)(...); // 验证规则 JSON 语法
    void *userdata;                     // 策略实例私有数据
} permission_strategy_t;
```

**关键设计原则**：`compile_rules` 在策略创建时执行一次，将 JSON 规则解析为内存中的预编译结构。运行时的 `evaluate` 不再接触 JSON，实现零拷贝评估。

### 6.3 评估模型：DENY-Override

```
输入: 策略列表（按优先级降序排列）

过程:
  对于每个策略：
    跳过禁用策略
    查找策略对应的注册策略
    执行评估 (compile → evaluate)
    如果返回 DENY → 立即返回 DENY（fail-closed）
    如果返回 ALLOW → 继续评估下一个策略
    如果策略不匹配 → 跳过

输出: 最后一个匹配的 ALLOW，或默认 DENY（无匹配策略时）
```

**安全含义**：任何一条策略的 DENY 立即覆盖所有 ALLOW。这确保权限配置是**封闭式的**（fail-closed）——未明确授权的操作都被拒绝。

---

## 7. 缓存架构

三级缓存体系，分层递进，从快到慢：

### 7.1 L0 — 规则编译缓存

- **容量**：256 个策略
- **键**：`policy_id`
- **值**：`per_strategy_t->compile_rules()` 输出的预编译结构
- **寻址**：直接索引哈希表 `policy_id % 256` + 线性探测
- **TTL**：持久有效，直到 `perm_engine_cache_invalidate_policy()` 被调用
- **目的**：规则 JSON 只编译一次，运行时零 JSON 解析

### 7.2 L1 — 策略解析缓存

- **容量**：128 个用户
- **键**：`user_id`
- **值**：`policy_resolve_for_user()` 的结果（该用户的全部策略列表）
- **寻址**：直接索引 `user_id % 128`
- **TTL**：60 秒
- **目的**：避免每次检查都从数据库加载策略

### 7.3 L2 — 决策结果缓存

- **容量**：1024 项
- **键**：`(user_id, params_hash)`
- **值**：最终决策 `{allowed: bool}`
- **寻址**：`hash(params) % 1024`
- **TTL**：30 秒
- **目的**：完全相同的请求参数 30 秒内直接命中

### 7.4 缓存失效策略

| 触发操作 | 失效范围 |
|----------|----------|
| 策略创建/更新/删除 | 清除 L2 所有 + L1 所有 + L0 该策略 |
| 角色分配/取消分配 | 清除 L2 所有 + L1 所有 |
| 用户状态变更 | 清除该用户的 L2 + L1 条目 |
| 全局失效调用 | 清空所有缓存 |

### 7.5 并发安全

- L1/L2 缓存使用 `pthread_rwlock_t`：读操作持读锁，写操作持写锁
- L0 缓存在策略变更时使用写锁
- 指标计数器使用 C11 `atomic_fetch_add` 无锁操作

---

## 8. 令牌系统

### 8.1 令牌格式

```
base64({
  "jti":    "<UUID>",      // 唯一令牌标识符
  "sub":    "<user_id>",   // 用户 ID
  "iat":    <issued_ms>,   // 签发时间（毫秒）
  "exp":    <expires_ms>,  // 过期时间（毫秒）
  "roles":  [<id>, ...],   // 角色 ID 列表
  "groups": [<id>, ...],   // 组 ID 列表
  "nonce":  <nonce>,       // 用户的令牌 nonce 版本
  "jkt":    "<thumbprint>" // DPoP 公钥指纹（可选）
})
+ "." + HMAC_SHA256(payload, secret)
```

### 8.2 签名模式

| 模式 | 密钥类型 | 环境变量 | 适用场景 |
|------|----------|----------|----------|
| **HS256** | 对称（共享密钥） | `SSO_TOKEN_SECRET` | 开发/小规模部署 |
| **RS256** | 非对称（RSA 密钥对） | `SSO_PRIVATE_KEY` + `SSO_PUBLIC_KEY` | 生产/多服务验证 |

系统自动检测：当 `SSO_PRIVATE_KEY` 设置了 PEM 密钥时使用 RS256，否则回退到 HS256。

### 8.3 安全特性

- **内存锁定**：`sodium_mlock()` 锁定令牌密钥 RAM，防止交换到磁盘
- **安全擦除**：`sodium_memzero()` 在 `sso_destroy()` 时清零密钥
- **Nonce 机制**：每个用户维护一个递增 nonce，`token_bump_nonce()` 立即作废该用户所有令牌
- **会话限制**：默认每个用户最多 3 个并发会话，超出时自动撤销最旧会话
- **撤销列表**：O(log N) 二分查找，支持过期条目自动清理

### 8.4 刷新令牌

- 默认 TTL：30 天（可通过配置调整）
- 存储于后端数据库（哈希存储 `SHA-256(token)`）
- 旋转策略：每次刷新时旧刷新令牌立即撤销，签发新令牌和新刷新令牌

---

## 9. HTTP 服务器与线程模型

### 9.1 双后端设计

| 后端 | 实现文件 | 启用条件 | 特点 |
|------|----------|----------|------|
| **libmicrohttpd** | `src/server_mhd.c` | 链接 libmicrohttpd | 生产首选，多线程，epoll |
| **POSIX Socket** | `src/server.c` | 无 libmicrohttpd | 回退方案，自带线程池 |

两个后端共享同一套 `route_t` 路由表和处理函数，API 完全一致。

### 9.2 线程池架构

```
主线程 (accept) → 任务队列 (有界环形缓冲区) → 工作线程池
                                                    │
                                              ┌──────┼──────┐
                                              ▼      ▼      ▼
                                           线程1   线程2   线程3 ... 线程N
                                           │       │       │
                                           ▼       ▼       ▼
                                     ┌─── 每个线程 ─────────────┐
                                     │ - 线程局部 arena 分配器   │
                                     │ - 线程局部 request_id    │
                                     │ - handle_client()       │
                                     └─────────────────────────┘
```

### 9.3 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `thread_pool_size` | 8 | 工作线程数（范围 1-256） |
| `queue_size` | 1024 | 任务队列容量 |
| `request_timeout_ms` | 30000 | 请求超时（毫秒） |
| `max_body_size` | 1048576 (1MB) | 最大请求体大小 |

### 9.4 请求生命周期

```
accept → pool_submit → 取任务 → 解析请求 → 多租户路由 → CORS
→ 路由匹配 → 认证(可选) → handler → 发送响应 → arena 回收
```

### 9.5 内存管理：Arena 分配器

每个 HTTP 请求使用 `arena_t` 线性分配器（`_Thread_local` 线程局部存储）：

- 预分配 4KB 块
- 请求处理期间的所有临时分配从 arena 分配
- 请求处理完毕后一次性释放（`arena_reset`），无需逐块 free
- 大幅减少 `malloc`/`free` 频率，提升吞吐量

---

## 10. 认证策略体系

### 10.1 支持的认证方式

| 认证方式 | 实现文件 | 特点 |
|----------|----------|------|
| **密码登录** | `src/user.c` | Argon2id 哈希、速率限制 5次/分钟/IP |
| **短信验证码** | `src/handlers.c` | libcurl 发送、自动注册新用户、速率限制 1次/分钟/IP |
| **WebAuthn/FIDO2** | `src/webauthn.c` | 公钥认证、无密码、支持硬件安全密钥 |
| **TOTP MFA** | `src/mfa.c` | RFC 6238 TOTP、支持 Google Authenticator/Authy |
| **OAuth 2.0 / OIDC** | `src/oauth.c` | 授权码流程、PKCE、token introspection、token revocation |
| **DPoP 绑定** | `src/dpop.c` | OAuth 2.0 DPoP（RFC 9449）、防令牌窃取 |

### 10.2 自适应风险引擎 (`risk.h`)

在登录时评估风险分数（0-100），可用于触发额外验证步骤：

| 风险因素 | 检测内容 |
|----------|----------|
| 地理位置异常 | 登录 IP 与历史记录对比 |
| 设备指纹 | User-Agent 与历史记录对比 |
| 失败次数 | 近期登录失败次数 |
| 时间异常 | 非正常时段的登录尝试 |

---

## 11. 多租户架构

### 11.1 基于 Host 头的租户路由

系统通过 HTTP `Host` 头自动识别租户：

```
Host: tenant-a.example.com
  ───▶ 解析 "tenant-a" 作为租户 ID
  ───▶ 自动创建隔离的 sso_context_t（冷启动）
  ───▶ 独立的数据源（tenant-a.db）

Host: tenant-b.example.com
  ───▶ 解析 "tenant-b" 作为租户 ID
  ───▶ 独立数据源（tenant-b.db）
```

### 11.2 租户隔离

每个租户拥有完全隔离的：
- `sso_context_t`（权限引擎、令牌管理器、各管理器实例）
- 持久化数据库（基于主库 URL 注入后缀 `.{tenant_id}.db`）
- 策略规则和用户数据

### 11.3 租户上限

- 默认最大 64 个租户（`MAX_TENANTS`）
- 超过上限的所有 Host 路由到默认租户上下文

---

## 12. 可观测性

### 12.1 指标 (`/metrics`)

Prometheus 兼容格式，通过原子计数器无开销收集：

| 指标 | 类型 | 说明 |
|------|------|------|
| `sso_perm_evals_total` | Counter | 权限评估总次数 |
| `sso_perm_cache_hits_total{level="l1"}` | Counter | L1 缓存命中数 |
| `sso_perm_cache_hits_total{level="l2"}` | Counter | L2 缓存命中数 |
| `sso_perm_decisions_total{effect="allow"}` | Counter | ALLOW 决策总次数 |
| `sso_perm_decisions_total{effect="deny"}` | Counter | DENY 决策总次数 |
| `sso_perm_eval_duration_us_total` | Counter | 累计评估耗时（微秒） |

### 12.2 审计日志

所有权限决策以 JSON 格式记录到 `audit.log`：

```json
{"timestamp_ms": 1712345678000, "user_id": 1, "decision": "DENY",
 "duration_ms": 0, "cache_hit": false, "trace": "..."}
```

- 文件自动轮转：最大 10MB，保留 5 个备份
- 64KB 写缓冲区减少文件 I/O
- 每 100 次写入检查一次文件大小

### 12.3 日志系统

- 支持文本和 JSON 格式（通过配置切换）
- 5 个日志级别：DEBUG, INFO, WARN, ERROR, FATAL
- 线程局部请求 ID 自动注入：
  - 每次 HTTP 请求生成唯一 `request_id`（`req-{timestamp}-{counter}`）
  - 请求处理期间的 `LOG_*` 宏自动包含该 ID
  - 写回 `X-Request-Id` 响应头

### 12.4 健康检查

`GET /api/v1/health` 返回基本存活探针，适用于 Kubernetes/Docker 健康检查。

---

## 13. 部署架构

### 13.1 单机部署

```
[客户端] ───▶ [SSO System :8080] ───▶ [SQLite .db 文件]
                         │
                         └──▶ [audit.log]
```

### 13.2 生产部署（高可用）

```
                        ┌──────────────────┐
                        │   负载均衡器      │
                        │  Nginx / HAProxy  │
                        └────────┬─────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
   │ SSO Instance │     │ SSO Instance │     │ SSO Instance │
   │   Node 1     │     │   Node 2     │     │   Node 3     │
   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
           │                   │                    │
           └───────────────────┼────────────────────┘
                               │
                     ┌─────────▼─────────┐
                     │   PostgreSQL       │
                     │   (共享数据库)     │
                     └───────────────────┘
```

### 13.3 CI/CD 流水线

```
代码提交 → GitHub Actions
  ├── 静态分析 (cppcheck + clang-tidy)
  ├── 构建 (Release + Debug)
  ├── 单元测试
  ├── 性能基准测试
  ├── AddressSanitizer
  ├── 集成测试
  ├── 前端构建 (Vue.js)
  └── Docker 镜像构建
```

### 13.4 Docker 部署

```yaml
# docker-compose.yml
services:
  sso:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SSO_TOKEN_SECRET=${SSO_TOKEN_SECRET}
    volumes:
      - sso-data:/app/sso_server.db
      - ./audit.log:/app/audit.log
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
      interval: 30s
      timeout: 3s
      retries: 3
```

- 多阶段构建（builder → runner）
- 以 `nobody` 用户运行
- 内置 `HEALTHCHECK`
- 数据通过 Docker volume 持久化
