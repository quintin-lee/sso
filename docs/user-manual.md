# SSO 系统用户手册

## 目录

1. [系统简介](#1-系统简介)
2. [快速开始](#2-快速开始)
3. [安装指南](#3-安装指南)
4. [配置说明](#4-配置说明)
5. [运行模式](#5-运行模式)
6. [API 使用指南](#6-api-使用指南)
7. [权限策略管理](#7-权限策略管理)
8. [OAuth 2.0 / OIDC 使用指南](#8-oauth-20--oidc-使用指南)
9. [WebAuthn 免密码登录](#9-webauthn-免密码登录)
10. [多因素认证 (MFA)](#10-多因素认证-mfa)
11. [管理后台](#11-管理后台)
12. [监控与运维](#12-监控与运维)
13. [迁移与升级](#13-迁移与升级)
14. [故障排除](#14-故障排除)
15. [常见问题](#15-常见问题)

---

## 1. 系统简介

SSO 系统是一个高性能的企业级单点登录和权限管理服务。它提供：

- **统一认证**：用户名密码、短信验证码、免密码 WebAuthn、多因素认证（MFA）
- **细粒度权限控制**：7 种权限策略，支持功能级、API 级、数据级访问控制
- **开放协议**：OAuth 2.0、OpenID Connect（OIDC）
- **低延迟高并发**：单核 35K+ QPS，评估延迟亚 30μs
- **零外部运行时依赖**：自包含 HTTP 服务器，Docker 一键启动

---

## 2. 快速开始

### 2.1 下载并运行（最短路径）

```bash
# 1. 克隆仓库
git clone https://github.com/quintin-lee/sso.git
cd sso

# 2. 安装依赖（Ubuntu/Debian）
sudo apt-get install libsqlite3-dev libssl-dev libsodium-dev \
  libcurl4-openssl-dev libmicrohttpd-dev build-essential

# 3. 编译
make

# 4. 运行演示模式
./sso_system

# 5. 启动服务器模式
export SSO_TOKEN_SECRET=$(openssl rand -hex 32)
./sso_system --server
```

启动后访问：
- **登录页面**：http://localhost:8080/
- **管理后台**：http://localhost:8080/admin
- **API 健康检查**：http://localhost:8080/api/v1/health

### 2.2 Docker 部署

```bash
# 使用 Docker Compose
docker-compose up -d

# 或手动构建
docker build -t sso-system .
docker run -d -p 8080:8080 \
  -e SSO_TOKEN_SECRET=$(openssl rand -hex 32) \
  sso-system
```

### 2.3 默认管理员

首次启动时系统会自动创建管理员账户：

- **用户名**：`admin`
- **密码**：自动生成并打印到控制台

```
⚠️  WARNING: No SSO_ADMIN_PASSWORD set in environment.
⚠️  Generated initial admin password: admin-a1b2c3d4
```

> **重要**：请在首次登录前通过环境变量 `SSO_ADMIN_PASSWORD` 设置自定义管理员密码。

---

## 3. 安装指南

### 3.1 系统要求

- **操作系统**：Linux（推荐）、macOS
- **C 编译器**：GCC >= 4.9 或 Clang >= 3.5（C11 支持）
- **内存**：最低 128MB RAM
- **磁盘**：50MB（不含数据库）

### 3.2 依赖安装

#### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  libsqlite3-dev \
  libssl-dev \
  libsodium-dev \
  libcurl4-openssl-dev \
  libmicrohttpd-dev
```

#### Alpine

```bash
apk add sqlite-dev openssl-dev libsodium-dev \
  curl-dev libmicrohttpd-dev gcc musl-dev make
```

#### macOS（Homebrew）

```bash
brew install sqlite openssl libsodium curl libmicrohttpd
```

#### 可选依赖

| 依赖 | 安装命令 | 用途 |
|------|----------|------|
| PostgreSQL | `apt install libpq-dev` | PostgreSQL 存储后端 |
| hiredis | `apt install libhiredis-dev` | Redis 存储后端 |

### 3.3 编译选项

```bash
# Release 构建（推荐生产使用）
make

# Debug 构建（调试用）
make debug

# AddressSanitizer 构建（开发阶段内存检查）
make asan

# 性能分析构建
make profile

# 静态分析（需要 cppcheck + clang-tidy）
make static-analysis
```

### 3.4 验证安装

```bash
# 运行演示模式测试权限引擎
./sso_system

# 运行单元测试
make test && ./sso_test

# 运行集成测试
make integration-test && ./sso_test_integration

# 运行全部检查
make check
```

---

## 4. 配置说明

### 4.1 配置文件

默认配置文件为 `sso.toml`，可通过 `-c` 参数指定自定义路径。

#### 完整配置示例

```toml
[server]
host = "0.0.0.0"
port = 8080
thread_pool_size = 8
queue_size = 1024
request_timeout_ms = 30000
max_body_size = 1048576

[database]
path = "sso_server.db"
use_memory = false
database_type = "sqlite"
database_url = "sso_server.db"

[security]
token_secret = ""
token_ttl_ms = 3600000
tls_enabled = false
tls_cert_file = ""
tls_key_file = ""

[sms]
sms_gateway_url = ""
sms_api_key = ""

[logging]
log_level = 1
log_format = 0
audit_log_path = "audit.log"

[oauth]
oauth_client_id = "sso-cli"
oauth_client_secret = ""
oauth_redirect_uris = "http://localhost:8080/callback"
oauth_issuer = "http://localhost:8080"
oauth_auth_code_ttl_ms = 300000

[ratelimit]
max_ips = 10000

[password_policy]
min_length = 8
require_uppercase = true
require_digit = true
require_special = false
history_check = 3
max_age_days = 90
```

### 4.2 环境变量

所有配置均可通过环境变量覆盖。命名规则：`SSO_` + 配置项大写。

#### 必需设置

| 变量 | 说明 | 示例 |
|------|------|------|
| `SSO_TOKEN_SECRET` | 令牌签名密钥（32+ 字符随机字符串） | `$(openssl rand -hex 32)` |

#### 可选设置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SSO_HOST` | `0.0.0.0` | 绑定地址 |
| `SSO_PORT` | `8080` | HTTP 端口 |
| `SSO_ADMIN_PASSWORD` | 自动生成 | 初始管理员密码 |
| `SSO_LOG_LEVEL` | `1` | 日志级别：0=DEBUG, 1=INFO, 2=WARN, 3=ERROR |
| `SSO_TLS_ENABLED` | `false` | 启用 HTTPS |
| `SSO_TLS_CERT_FILE` | — | TLS 证书路径 |
| `SSO_TLS_KEY_FILE` | — | TLS 密钥路径 |

#### 签名密钥配置

**HS256（对称签名，默认）**：
```bash
export SSO_TOKEN_SECRET=$(openssl rand -hex 32)
```

**RS256（非对称签名，推荐生产使用）**：
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
export SSO_PRIVATE_KEY="$(cat private.pem)"
export SSO_PUBLIC_KEY="$(cat public.pem)"
```

> 设置了 `SSO_PRIVATE_KEY` 后系统自动使用 RS256 模式。公钥可通过 `GET /api/v1/auth/certs` 和 `GET /api/v1/auth/jwks` 获取。

---

## 5. 运行模式

### 5.1 演示模式

```bash
./sso_system
```

快速验证系统功能。创建演示用户和权限，执行全面的权限检查测试和缓存压力测试。

### 5.2 服务器模式（生产）

```bash
export SSO_TOKEN_SECRET=your-secret
./sso_system --server
```

启动 HTTP API 服务，监听在 `host:port`（默认 `0.0.0.0:8080`）。

### 5.3 交互式配置模式

```bash
./sso_system --interactive
```

文本界面用于创建和管理策略，适合快速原型验证。

### 5.4 命令行参数

```bash
./sso_system --help        # 显示帮助
./sso_system --version     # 显示版本
./sso_system -c /path/to/config.toml --server   # 指定配置文件启动服务器
```

---

## 6. API 使用指南

### 6.1 认证 API

#### 用户登录

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "your-password"}'
```

**响应**：
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBh...",
  "user": {
    "id": 1,
    "username": "admin",
    "display_name": "Admin",
    "email": "admin@example.com"
  }
}
```

> **速率限制**：登录接口限制为每 IP 每分钟 5 次请求。

#### 发送短信验证码

```bash
curl -X POST http://localhost:8080/api/v1/auth/send_sms \
  -H 'Content-Type: application/json' \
  -d '{"phone": "13800138000"}'
```

> **速率限制**：短信接口限制为每 IP 每分钟 1 次请求。

#### 短信验证码登录

```bash
curl -X POST http://localhost:8080/api/v1/auth/login_by_sms \
  -H 'Content-Type: application/json' \
  -d '{"phone": "13800138000", "code": "123456"}'
```

#### 用户注册

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "SecurePass123", "email": "alice@example.com"}'
```

### 6.2 令牌管理

#### 验证令牌

```bash
curl -X POST http://localhost:8080/api/v1/auth/verify \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json'
```

#### 刷新令牌

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json'
```

#### 登出

```bash
# 撤销单个令牌
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'

# 撤销所有令牌（所有设备登出）
curl -X POST http://localhost:8080/api/v1/auth/logout_all \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

#### 获取当前用户信息

```bash
curl http://localhost:8080/api/v1/auth/me \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

#### 修改密码

```bash
curl -X POST http://localhost:8080/api/v1/auth/password \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"current_password": "old-pass", "new_password": "new-pass-456"}'
```

### 6.3 权限检查 API

#### 统一权限检查

```bash
curl -X POST http://localhost:8080/api/v1/check \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{
    "strategy": "functional",
    "params": {"function_code": "admin:*"}
  }'
```

#### 特定策略检查

```bash
# 功能性权限检查
curl -X POST http://localhost:8080/api/v1/check/functional \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"function_code": "user:create"}'

# API 端点权限检查
curl -X POST http://localhost:8080/api/v1/check/api \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"method": "GET", "path": "/api/v1/users"}'

# 数据范围权限检查
curl -X POST http://localhost:8080/api/v1/check/data \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"resource_type": "order", "record": {"amount": 1000}}'

# RBAC 检查
curl -X POST http://localhost:8080/api/v1/check/rbac \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"role_name": "admin"}'

# 位置检查
curl -X POST http://localhost:8080/api/v1/check/location \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"source_ip": "192.168.1.100"}'

# ABAC 检查（基于属性的访问控制）
curl -X POST http://localhost:8080/api/v1/check/abac \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"resource_attrs": "{\"department\": \"finance\", \"amount\": 50000}"}'

# LBAC 检查（基于标签的访问控制）
curl -X POST http://localhost:8080/api/v1/check/lbac \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"user_labels": "confidential", "resource_label": "top_secret"}'
```

**统一响应格式**：
```json
{
  "allowed": true,
  "trace": "[Policy System API] Strategy api: ALLOW\nResult: ALLOWED"
}
```

### 6.4 用户管理 API

```bash
# 列出用户（带分页和搜索）
curl 'http://localhost:8080/api/v1/users?offset=0&limit=20&q=admin' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'

# 获取用户详情
curl http://localhost:8080/api/v1/users/1 \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'

# 创建用户
curl -X POST http://localhost:8080/api/v1/users \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"username": "bob", "password": "Pass123!", "email": "bob@example.com", "display_name": "Bob"}'

# 更新用户
curl -X PUT http://localhost:8080/api/v1/users/2 \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"display_name": "Bob Updated"}'

# 删除用户
curl -X DELETE http://localhost:8080/api/v1/users/2 \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

### 6.5 角色管理 API

```bash
# 列出角色
curl http://localhost:8080/api/v1/roles \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'

# 创建角色
curl -X POST http://localhost:8080/api/v1/roles \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"name": "manager", "description": "Manager role", "parent_role_id": 1}'

# 分配角色给用户
curl -X POST 'http://localhost:8080/api/v1/roles/1/assign' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"user_id": 2}'

# 取消分配角色
curl -X POST 'http://localhost:8080/api/v1/roles/1/unassign' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"user_id": 2}'
```

### 6.6 组管理 API

```bash
# 创建组
curl -X POST http://localhost:8080/api/v1/groups \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"name": "Engineering", "description": "Engineering Department", "parent_group_id": 0}'

# 添加用户到组
curl -X POST http://localhost:8080/api/v1/groups/1/members \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"user_id": 3}'

# 从组移除用户
curl -X DELETE http://localhost:8080/api/v1/groups/1/members/3 \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

### 6.7 策略管理 API

```bash
# 创建功能性权限策略
curl -X POST http://localhost:8080/api/v1/policies \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Finance Access",
    "strategy_type": "functional",
    "default_effect": "allow",
    "priority": 80,
    "rules": "{\"functions\":[{\"code\":\"finance:*\",\"effect\":\"allow\"},{\"code\":\"finance:delete\",\"effect\":\"deny\"}]}"
  }'

# 创建 API 端点策略
curl -X POST http://localhost:8080/api/v1/policies \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Read API Access",
    "strategy_type": "api",
    "default_effect": "allow",
    "priority": 60,
    "rules": "{\"endpoints\":[{\"method\":\"GET\",\"path\":\"/api/v1/*\",\"effect\":\"allow\"}]}"
  }'

# 将策略分配给角色
curl -X POST 'http://localhost:8080/api/v1/policies/1/assign' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"target_type": "role", "target_id": 2}'
```

### 6.8 监控与健康检查

```bash
# 健康检查
curl http://localhost:8080/api/v1/health

# 响应：{"status": "ok", "version": "1.1.0"}

# Prometheus 指标
curl http://localhost:8080/metrics

# 审计日志
curl http://localhost:8080/api/v1/audit/logs \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

### 6.9 响应状态码

| 状态码 | 含义 |
|--------|------|
| 200 | 成功 |
| 201 | 创建成功 |
| 400 | 请求参数错误 |
| 401 | 认证失败/令牌过期 |
| 403 | 权限拒绝 |
| 404 | 资源不存在 |
| 429 | 请求速率超限 |
| 500 | 服务器内部错误 |

---

## 7. 权限策略管理

### 7.1 策略类型概述

| 策略类型 | 用途 | 适用场景 |
|----------|------|----------|
| **功能（Functional）** | 控制功能/菜单/按钮的访问 | 页面元素可见性、功能开关 |
| **API 端点（API）** | 控制 HTTP API 的访问 | 微服务间调用控制 |
| **数据范围（Data）** | 行级/字段级数据过滤 | 多租户数据隔离、敏感字段隐藏 |
| **RBAC** | 基于角色的访问控制 | 标准企业角色管理 |
| **位置（Location）** | 基于 IP/地理位置的访问控制 | 办公网络限制、区域合规 |
| **ABAC** | 基于属性的访问控制 | 复杂业务规则、动态策略 |
| **LBAC** | 基于标签的安全控制 | 军事级密级分类、文档安全 |

### 7.2 策略规则格式

#### 功能性策略规则

```json
{
  "functions": [
    {"code": "admin:*", "effect": "allow"},
    {"code": "user:create", "effect": "allow"},
    {"code": "user:delete", "effect": "deny"},
    {"code": "report:view", "effect": "allow"}
  ]
}
```

**通配符规则**：
- `*` 匹配任意字符序列
- `admin:*` 匹配 `admin:user`, `admin:setting`, `admin:anything`
- `*:view` 匹配 `report:view`, `dashboard:view`, `user:view`
- `*` 匹配所有功能码

#### API 端点策略规则

```json
{
  "endpoints": [
    {"method": "GET", "path": "/api/v1/users", "effect": "allow"},
    {"method": "*", "path": "/api/v1/public/*", "effect": "allow"},
    {"method": "DELETE", "path": "/api/v1/**", "effect": "deny"}
  ]
}
```

**路径匹配规则**：
- `*` — 匹配单级路径（`/api/v1/*` 匹配 `/api/v1/users`，不匹配 `/api/v1/users/1`）
- `**` — 匹配多级路径（`/api/v1/**` 匹配 `/api/v1/users/1/profile`）
- `:param` — 命名参数匹配（`/api/v1/users/:id` 匹配 `/api/v1/users/42`）

#### 数据范围策略规则

```json
{
  "conditions": [
    {"field": "department", "op": "eq", "value": "${user.department}"},
    {"field": "region", "op": "in", "value": ["North", "South"]},
    {"field": "amount", "op": "lt", "value": 10000}
  ],
  "field_filter": ["name", "email", "department"],
  "mask": [
    {"field": "phone", "mask": "***-****-****"},
    {"field": "email", "mask": "{prefix}@***"}
  ]
}
```

#### ABAC 策略规则

```json
{
  "rules": [
    {
      "condition": "user.department == 'finance' && resource.amount < 100000",
      "effect": "allow"
    },
    {
      "condition": "resource.classification == 'top_secret' && user.clearance < 5",
      "effect": "deny"
    }
  ]
}
```

#### LBAC 策略规则

```json
{
  "access_rules": [
    {"clearance": "unclassified", "max_level": "public"},
    {"clearance": "confidential", "max_level": "internal"},
    {"clearance": "secret", "max_level": "confidential"},
    {"clearance": "top_secret", "max_level": "top_secret"}
  ]
}
```

### 7.3 策略优先级与冲突解决

**优先级规则**：

1. 每个策略有 `priority` 值（0-100，值越大优先级越高）
2. 同一用户的策略合并后按优先级降序排列
3. DENY-Override：任意策略返回 DENY 立即否决

**示例**：

```
用户 alice 拥有 editor 角色和 viewer 角色

editor 角色策略:  priority=80 → "content:delete" → deny
viewer 角色策略:  priority=60 → "content:view"  → allow

alice 执行 "content:delete":
  1. 优先级 80 匹配 → result = DENY
  2. DENY-Override → 返回 DENY

alice 执行 "content:view":
  1. 优先级 80 不匹配 → 跳过
  2. 优先级 60 匹配 → result = ALLOW
  3. 返回 ALLOW
```

### 7.4 最佳实践

1. **最小权限原则**：为每个角色只分配必要的最小策略集
2. **分层策略**：功能策略控制可见性，API 策略控制端点访问，数据策略控制数据范围
3. **显式拒绝**：对敏感操作使用显式 `effect: "deny"` 覆盖
4. **测试验证**：先使用 `check` API 测试策略效果再应用到生产

---

## 8. OAuth 2.0 / OIDC 使用指南

### 8.1 配置 OAuth 客户端

```toml
[oauth]
oauth_client_id = "my-app"
oauth_client_secret = "client-secret-123"
oauth_redirect_uris = "https://myapp.example.com/callback"
oauth_issuer = "https://sso.example.com"
```

### 8.2 授权码流程

**步骤 1：构建授权页面 URL**

```
https://sso.example.com/api/v1/oauth/authorize?
  response_type=code&
  client_id=my-app&
  redirect_uri=https://myapp.example.com/callback&
  scope=openid+profile&
  state=random-state-string&
  code_challenge=E9Melhoa2Ow...&
  code_challenge_method=S256
```

> **PKCE 强制**：系统要求所有授权码流程使用 PKCE（Proof Key for Code Exchange）。

**步骤 2：用户认证并授权**

用户被重定向到 SSO 登录页面，完成认证后授权应用程序。

**步骤 3：兑换授权码**

```bash
curl -X POST https://sso.example.com/api/v1/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&
       code=the-authorization-code&
       redirect_uri=https://myapp.example.com/callback&
       client_id=my-app&
       client_secret=client-secret-123&
       code_verifier=the-original-code-verifier'
```

**响应**：
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBh...",
  "id_token": "eyJraWQiOiIx...",
  "scope": "openid profile"
}
```

### 8.3 令牌自检（Introspection）

```bash
curl -X POST https://sso.example.com/api/v1/oauth/introspect \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=the-access-token'
```

### 8.4 令牌撤销

```bash
curl -X POST https://sso.example.com/api/v1/oauth/revoke \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=the-access-token'
```

### 8.5 OIDC 发现端点

```bash
# 获取 OpenID 配置
curl https://sso.example.com/.well-known/openid-configuration

# 获取 JWKS 公钥集合
curl https://sso.example.com/api/v1/auth/jwks

# 获取用户信息（OIDC）
curl https://sso.example.com/api/v1/auth/userinfo \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs...'
```

---

## 9. WebAuthn 免密码登录

### 9.1 注册安全密钥

**步骤 1：获取注册挑战**

```bash
curl -X POST http://localhost:8080/api/v1/auth/webauthn/register/challenge \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

**响应**：
```json
{
  "challenge": "base64url-encoded-challenge",
  "rp": {"name": "SSO System", "id": "localhost"},
  "user": {"id": "base64-user-id", "name": "admin"}
}
```

**步骤 2：使用 WebAuthn API 注册密钥**

浏览器中调用 `navigator.credentials.create()`，然后将结果提交：

```bash
curl -X POST http://localhost:8080/api/v1/auth/webauthn/register \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{
    "attestation_object": "base64url...",
    "client_data_json": "base64url..."
  }'
```

### 9.2 使用安全密钥登录

**步骤 1：获取登录挑战**

```bash
curl -X POST http://localhost:8080/api/v1/auth/webauthn/login/challenge \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin"}'
```

**步骤 2：使用 WebAuthn API 认证**

```bash
curl -X POST http://localhost:8080/api/v1/auth/webauthn/login \
  -H 'Content-Type: application/json' \
  -d '{
    "authenticator_data": "base64url...",
    "client_data_json": "base64url...",
    "signature": "base64url..."
  }'
```

---

## 10. 多因素认证 (MFA)

### 10.1 设置 TOTP MFA

**步骤 1：获取设置信息**

```bash
curl -X POST http://localhost:8080/api/v1/auth/mfa/setup \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...'
```

**响应**：
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/SSO:admin?secret=JBSWY3DPEHPK3PXP&issuer=SSO"
}
```

**步骤 2：使用认证器 App 扫描二维码**

支持：Google Authenticator、Microsoft Authenticator、Authy、1Password 等。

**步骤 3：验证并启用**

```bash
curl -X POST http://localhost:8080/api/v1/auth/mfa/enable \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -H 'Content-Type: application/json' \
  -d '{"code": "123456"}'
```

### 10.2 MFA 登录

启用 MFA 后，登录需要额外两步：

```bash
# 步骤 1：密码登录
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "your-password"}'

# 响应包含 mfa_required=true

# 步骤 2：验证 MFA 码
curl -X POST http://localhost:8080/api/v1/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "code": "654321"}'
```

---

## 11. 管理后台

### 11.1 访问管理后台

浏览器访问 `http://localhost:8080/admin`，用管理员账号登录。

管理后台提供以下功能：

| 功能 | 说明 |
|------|------|
| **用户管理** | 创建、编辑、删除用户 |
| **角色管理** | 创建角色、设置角色层级、分配用户 |
| **组管理** | 创建组织单元、设置嵌套结构、管理成员 |
| **策略管理** | 创建 7 种策略、分配策略到角色/组/用户 |
| **审计日志** | 查看权限决策和管理操作记录 |

### 11.2 嵌入式 Admin 页面

管理后台完全嵌入在系统二进制中，无额外部署要求。前端使用 Vue.js 构建，通过 REST API 与后端交互。

---

## 12. 监控与运维

### 12.1 日志

默认日志文件写入控制台。可通过配置切换到 JSON 格式：

```toml
[logging]
log_level = 1     # 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
log_format = 1    # 0=text, 1=json
```

JSON 格式示例（可直接输入 ELK 等日志系统）：

```json
{"level":"INFO","timestamp":"2026-01-15T10:30:00.123Z","request_id":"req-123-456","message":"Starting SSO management API"}
```

### 12.2 审计日志

所有权限决策和关键管理操作记录到 `audit.log`：

- 格式：每行一个 JSON 对象
- 自动轮转：最大 10MB，保留 5 个备份
- 可通过 `/api/v1/audit/logs` 接口查询

查看审计日志：

```bash
tail -f audit.log | jq .
```

### 12.3 Prometheus 指标

`/metrics` 端点暴露 Prometheus 兼容指标：

```bash
# 获取指标
curl http://localhost:8080/metrics

# 示例输出：
# HELP sso_perm_evals_total Total number of permission evaluations
# TYPE sso_perm_evals_total counter
# sso_perm_evals_total 1234
# HELP sso_perm_cache_hits_total Total number of cache hits
# TYPE sso_perm_cache_hits_total counter
# sso_perm_cache_hits_total{level="l1"} 800
# sso_perm_cache_hits_total{level="l2"} 400
```

### 12.4 健康检查

```bash
# Kubernetes liveness/readiness probe 示例
curl -f http://localhost:8080/api/v1/health
```

返回 `{"status": "ok", "version": "1.1.0"}` 表示服务正常。

### 12.5 配置热重载

向运行中的 SSO 进程发送 `SIGHUP` 信号可重新加载配置：

```bash
kill -HUP <sso_pid>
```

### 12.6 Docker 健康检查

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
  interval: 30s
  timeout: 3s
  retries: 3
```

---

## 13. 迁移与升级

### 13.1 从 v1.0.x 升级到 v1.1.0

**不兼容变更**：
- `sso_config_t` 增加了 `password_policy` 字段
- `POST /api/v1/auth/login` 响应增加了 `mfa_required` 字段

**升级步骤**：
1. 备份数据库：`cp sso_server.db sso_server.db.bak`
2. 编译新版本：`make`
3. 更新配置文件：添加 `[password_policy]` 配置节
4. 启动新版本：`./sso_system --server`
5. 验证：`curl /api/v1/health`

### 13.2 数据迁移

**SQLite → PostgreSQL**：

1. 使用 PostgreSQL 创建数据库
2. 安装 pgloader 等迁移工具
3. 修改配置文件 `database_type = "postgres"` 和 `database_url`
4. 启动新实例

### 13.3 密钥轮转

```bash
# 1. 生成新密钥
openssl rand -hex 32 > new-secret.txt

# 2. 更新环境变量并重启
export SSO_TOKEN_SECRET=$(cat new-secret.txt)
# 注意：重启后旧令牌将失效，用户需重新登录
```

对于 RS256 模式的密钥轮转，支持双密钥（新旧共存）：
- 新令牌使用新私钥签发
- 旧令牌仍然可以用旧公钥验证
- 直到旧密钥过期后再移除

---

## 14. 故障排除

### 14.1 启动问题

**问题**：`bind() failed on port 8080`

```
原因：端口被占用
解决：lsof -i :8080 查看占用，或修改端口配置
```

**问题**：`Could not load config file`

```
原因：配置文件路径错误或格式不正确
解决：检查文件路径，确保 TOML 格式正确
```

### 14.2 认证问题

**问题**：登录返回 `401 Unauthorized`

```
原因：用户名或密码错误
解决：
  - 确认用户名大小写
  - 管理员密码首次登录检查控制台输出
  - 检查速率限制（429 Too Many Requests）
```

**问题**：令牌验证返回 `Token expired`

```
原因：令牌 TTL 默认 1 小时
解决：
  - 使用 refresh_token 刷新
  - 或重新登录
```

### 14.3 性能问题

**问题**：权限检查延迟高（>100ms）

```
排查步骤：
  1. 检查指标：curl /metrics 查看缓存命中率
  2. 检查数据库查询性能
  3. 确认线程池配置合理（默认 8 线程）
  4. 检查磁盘 I/O（审计日志写入）
```

### 14.4 数据库问题

**问题**：`Storage error`

```
原因：数据库文件损坏或磁盘空间不足
解决：
  - 检查磁盘空间：df -h
  - 尝试 SQLite 恢复：sqlite3 sso_server.db ".recover"
  - 从备份恢复
```

---

## 15. 常见问题

**Q：如何修改管理员密码？**

A：登录后调用 `POST /api/v1/auth/password` 接口，或通过管理后台修改。

**Q：如何重置管理员密码？**

A：停止服务，删除数据库文件重新启动，系统会重新生成管理员账户和密码。

**Q：令牌有效期多久？**

A：默认 1 小时（可通过 `token_ttl_ms` 配置）。刷新令牌有效期 30 天。

**Q：支持多因素认证吗？**

A：支持。TOTP（基于时间的一次性密码），兼容 Google Authenticator 等标准应用。

**Q：如何验证 SSO 正在运行？**

A：访问 `/api/v1/health` 返回 `{"status": "ok"}` 表示服务正常。

**Q：可以与其他身份提供商集成吗？**

A：支持通过内部通信与 LDAP/AD 兼容。支持作为 OAuth 2.0/OIDC Provider。

**Q：是否支持集群部署？**

A：支持。使用 PostgreSQL 共享数据库，多个 SSO 实例无状态运行，前端使用负载均衡器分发请求。

**Q：如何获取技术支持？**

A：查看项目 GitHub Issues，提交 Bug 报告或功能请求。
