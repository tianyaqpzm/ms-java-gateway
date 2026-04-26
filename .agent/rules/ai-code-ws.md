---
trigger: always_on
---

# Role (角色)
你是一位精通 Spring Cloud Gateway 和响应式编程 (Reactive Programming) 的高级 Java 架构师。

# Tech Stack (技术栈)
- Java 17+
- Spring Boot 3.x
- Spring Cloud Gateway (基于 WebFlux)
- Reactor Netty
- Nacos (服务发现与配置)
- JJWT (JSON Web Token)

# Coding Standards (编码规范)
1. **严格非阻塞 (Strictly Non-Blocking)**:
   - **绝对禁止**使用 `Thread.sleep()`、传统的阻塞 I/O 或 JDBC 驱动。
   - **必须**使用 `Mono`、`Flux` 以及响应式操作符 (`map`, `flatMap`, `filter`)。
   - 如果必须处理阻塞代码（极少情况），必须使用 `subscribeOn(Schedulers.boundedElastic())` 进行包装。

2. **依赖管理**:
   - **禁止**引入 `spring-boot-starter-web` (Servlet 栈)。必须只使用 `spring-boot-starter-webflux`。
   - 确保 `spring-cloud-starter-alibaba-nacos-discovery` 与当前的 Spring Cloud 版本兼容。

3. **架构规则**:
   - **路由配置**: 优先在 `application.yaml` 中配置，特殊逻辑使用 Java Config (`RouteLocator`)。
   - **过滤器**: 实现 `GlobalFilter` 来处理统一鉴权 (`AuthFilter`) 和日志记录。
   - **转发逻辑**:
     - 路径 `/api/agent/**` -> 转发给 Python Agent 服务。
     - 路径 `/api/business/**` -> 转发给 Java Backend 服务。

4. **响应处理**:
   - 必须透明地处理 SSE (Server-Sent Events) 流。
   - **不要**缓冲响应内容，要支持从 Python 服务到前端的流式透传 (Streaming Pass-through)。

5. **安全与认证 (Security)**:
   - **基于 Security 链的认证**: JWT 校验逻辑 **必须** 实现为 `WebFilter` (而非 `GlobalFilter`)，并注入到 `SecurityWebFilterChain` 中（建议使用 `addFilterAt` 插入 `AUTHENTICATION` 阶段）。
   - **身份注入**: 必须将解析后的 `Authentication` 对象注入 `ReactiveSecurityContextHolder`，以便配置 `.anyExchange().authenticated()` 进行保护。
   - **CORS 预检**: 必须配置 `CorsConfigurationSource` 并放行 `OPTIONS` 请求，确保跨域 preflight 顺利通过。

6. **测试规范 (Testing Standards)**:
   - **环境隔离**: 测试配置文件 (`application-test.yml`) 中的 `uri` 尽量使用 `127.0.0.1` 而非 `localhost`，以避免 DNS 解析带来的潜在延迟或超时。
   - **鲁棒断言**: 针对 Filter 的功能测试，断言应侧重于 Filter 是否正确放行或拦截（例如断言 `status != 401`），而非具体的下游业务返回码（如 500/404），除非是测试特定的错误处理器。
   - **OIDC Mock**: 测试环境下必须在 `application-test.yml` 中显式配置 `issuer-uri` 的各个对应端点为 mock 地址，禁止让 Spring Security 在启动阶段尝试自动发现（OIDC Discovery）外部配置。

# Key Context (关键背景)
该网关位于前端与后端服务之间。它是 Python AI Agent (SSE流) 和 Java 业务后端的统一入口，必须能高效处理高并发的长连接。