---
trigger: always_on
---

# API Gateway (网关层) 开发规范

在生成或审查 API 网关（如 Spring Cloud Gateway）的代码时，必须严格将其定位为流量基础设施层与边缘层，严禁在此层掺杂任何微服务的核心领域逻辑。

## 1. 零业务逻辑原则 (Zero Domain Logic)

严禁越权： 网关严禁包含任何业务状态判断、计算或事务处理代码（例如：严禁在网关层写“如果用户是 VIP 则打八折”的逻辑）。

模型隔离： 网关层不需要也不应该知道后端微服务的 Entity 或 Value Object。网关处理的数据载体只能是无语义的 JSON/XML 文本或基础的 HTTP Request/Response 对象。

## 2. 统一鉴权与防腐层规范 (Authentication & ACL)

身份认证 (Authentication) 统揽： 网关必须负责解析和校验全局 Token（如 JWT），验证其签名、过期时间和基本合法性。

权限校验 (Authorization) 下放： 网关只负责“确认你是谁”，将解析出的用户 ID 或 Role 放入 HTTP Header (如 X-User-Id) 传递给下游微服务。具体的细粒度业务权限（如“该用户是否有权修改这篇帖子”）必须交由下游领域层判定，网关不查数据库比对权限。

请求清洗： 必须在此层拦截非法请求（如黑名单 IP、恶意 XSS 字符、超大 Payload）。

## 3. 数据聚合与 BFF 规范 (Backend for Frontend)

如果网关承担了 BFF（服务前端的后端）聚合职责：

并行调用： 组装多个下游微服务数据时，必须使用异步/并发（如 Java 中的 CompletableFuture 或 WebFlux Mono/Flux），严禁串行阻塞调用。

纯粹拼装： 聚合操作仅限于“裁剪字段”和“合并 JSON 树”。严禁在聚合过程中产生新的领域级校验或状态机流转。

## 4. 弹性与容错机制 (Resilience & Fault Tolerance)

全局超时： 必须为所有下游路由配置合理的 Timeout（如连接超时 3s，读取超时 5s）。

熔断与降级策略： 网关路由调用必须包裹在熔断器（如 Resilience4j / Sentinel）中。当下游服务宕机或超时时，网关必须抛出标准化的全局异常响应（如 JSON 格式的统一错误码），绝不能将后端的堆栈报错直接暴露给前端。

重试限制： 只能对下游的幂等请求（GET 等）配置自动重试，严禁对 POST/PUT 等写操作在网关层进行无脑重试。

## 5. 链路追踪与可观测性 (Observability)

Trace ID 注入： 网关作为流量第一跳，必须在接收到请求时生成全局唯一的 Trace-ID，并放入 HTTP Header 传递给所有下游微服务，同时记录在网关自身的 Access Log 中。