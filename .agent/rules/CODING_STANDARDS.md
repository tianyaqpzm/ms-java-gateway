---
trigger: always_on
---

# API Gateway (网关层) 开发规范

在生成或审查 API 网关（如 Spring Cloud Gateway）的代码时，必须严格将其定位为流量基础设施层与边缘层，严禁在此层掺杂任何微服务的核心领域逻辑。

## 1. 零业务逻辑原则 (Zero Domain Logic)

严禁越权： 网关严禁包含任何业务状态判断、计算或事务处理代码（例如：严禁在网关层写"如果用户是 VIP 则打八折"的逻辑）。

模型隔离： 网关层不需要也不应该知道后端微服务的 Entity 或 Value Object。网关处理的数据载体只能是无语义的 JSON/XML 文本或基础的 HTTP Request/Response 对象。

## 2. 统一鉴权与防腐层规范 (Authentication & ACL)

身份认证 (Authentication) 统揽： 网关必须负责解析和校验全局 Token（如 JWT），验证其签名、过期时间和基本合法性。

权限校验 (Authorization) 下放： 网关只负责"确认你是谁"，将解析出的用户 ID 或 Role 放入 HTTP Header (如 X-User-Id) 传递给下游微服务。具体的细粒度业务权限（如"该用户是否有权修改这篇帖子"）必须交由下游领域层判定，网关不查数据库比对权限。

请求清洗： 必须在此层拦截非法请求（如黑名单 IP、恶意 XSS 字符、超大 Payload）。

## 3. 数据聚合与 BFF 规范 (Backend for Frontend)

如果网关承担了 BFF（服务前端的后端）聚合职责：

并行调用： 组装多个下游微服务数据时，必须使用异步/并发（如 Java 中的 CompletableFuture 或 WebFlux Mono/Flux），严禁串行阻塞调用。

纯粹拼装： 聚合操作仅限于"裁剪字段"和"合并 JSON 树"。严禁在聚合过程中产生新的领域级校验或状态机流转。

## 4. 弹性与容错机制 (Resilience & Fault Tolerance)

全局超时： 必须为所有下游路由配置合理的 Timeout（如连接超时 3s，读取超时 5s）。

```yaml
spring.cloud.gateway.httpclient:
  connect-timeout: 3000   # 连接超时 3s
  response-timeout: 30s   # 读取超时（SSE 流需要较长时间）
```

- SSE 流式场景下 `response-timeout` 不宜设置过短，建议 ≥ 30s。
- 后续引入 Resilience4j 熔断器时，需单独评估对 SSE 长连接的影响。

熔断与降级策略： 网关路由调用必须包裹在熔断器（如 Resilience4j / Sentinel）中。当下游服务宕机或超时时，网关必须抛出标准化的全局异常响应（如 JSON 格式的统一错误码），绝不能将后端的堆栈报错直接暴露给前端。

重试限制： 只能对下游的幂等请求（GET 等）配置自动重试，严禁对 POST/PUT 等写操作在网关层进行无脑重试。

## 5. 链路追踪与可观测性 (Observability)

网关作为流量第一跳，必须在接收到请求时生成全局唯一的 Trace-ID，并放入 HTTP Header 传递给所有下游微服务，同时记录在网关自身的 Access Log 中。

- `TraceIdFilter` 的 Order 必须 < JwtAuthenticationFilter 的 Order（当前 `-200` vs `-100`），确保所有请求（含认证失败的）都有 Trace-ID。
- 如果上游（如 Nginx 反向代理）已注入 `X-Trace-Id`，必须复用，不得覆盖。
- Trace-ID 格式：32 位 hex（UUID 去除连字符），同时写入请求头（传递给下游）和响应头（方便前端排查）。

---

## 6. 工程结构规范 (Package Structure)

本网关工程必须遵循以下三层包结构，严禁将所有类堆在同一个包下：

```
com.dark.gateway/
├── config/       # 配置类（SecurityConfig、属性绑定、容错配置）
├── filter/       # WebFilter 实现（TraceIdFilter、JwtAuthenticationFilter 等）
└── handler/      # 错误处理器（统一异常响应）
```

- **config 包**：仅存放 `@Configuration` 配置类和 `@ConfigurationProperties` 属性绑定类。
- **filter 包**：仅存放 `WebFilter` 实现，每个 Filter 必须实现 `Ordered` 接口并声明明确的优先级。
- **handler 包**：仅存放错误处理器（如 `AbstractErrorWebExceptionHandler` 的实现）。

## 7. JWT 认证过滤器边界 (JWT Filter Boundary)

网关的 JWT 过滤器仅负责以下三件事，超出此范围的逻辑属于领域侵入：

| ✅ 允许 | ❌ 禁止 |
|---------|---------|
| 校验 JWT 签名与过期时间 | 解析业务级 Claims（如 `name`、`avatar`、`role`） |
| 提取 `sub`（标准 OIDC 字段）并注入 `X-User-Id` 头 | 注入 `X-User-Name`、`X-User-Avatar` 等业务头 |
| 透传原始 JWT（`Authorization: Bearer <token>`）给下游 | 对 Claims 字段进行 fallback 适配（如 `name` → `username`） |
| 白名单路径放行 & OPTIONS 预检放行 | 查询数据库或调用外部服务进行权限校验 |

**关键约束**：如果下游需要用户名、头像等业务信息，必须由下游服务自行从 JWT payload 解析，网关不代劳。

## 8. 统一错误处理规范 (Error Handler)

- 必须继承 `AbstractErrorWebExceptionHandler`，构造函数需注入 `ServerCodecConfigurer` 并调用 `setMessageWriters()` / `setMessageReaders()`。
- 错误响应必须包含标准化字段：`traceId`、`status`、`error`、`message`、`path`、`timestamp`。
- **消息清洗**：异常消息超过 200 字符必须截断；`ConnectException` → `"Service temporarily unavailable"`；`TimeoutException` → `"Service response timeout"`。严禁将原始堆栈暴露给前端。

## 9. 测试规范 (Testing Standards)

- **架构守护测试**（`ArchitectureGuardTest`）：必须覆盖所有 Filter/Config Bean 的装配验证和 Order 值断言，新增 Filter 时必须同步新增守护用例。
- **Filter 功能断言**：断言侧重于 Filter 是否正确放行或拦截（如 `status != 401`），而非下游业务返回码（如 500/404）。当 actuator 等端点启用后，原先预期 404 的白名单断言需改为 `!= 401`。
- **单元测试优先**：纯逻辑 Filter（如 `TraceIdFilter`、`RedirectSaveFilter`）优先使用 `MockServerWebExchange` 进行单元测试，避免启动完整 Spring Context。
- **`AbstractErrorWebExceptionHandler` 注意事项**：自定义错误处理器必须在构造函数中调用 `setMessageWriters()`，否则会在测试启动时抛出 `Property 'messageWriters' is required`。