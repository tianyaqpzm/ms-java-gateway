package com.dark.gateway.filter;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final PathMatcher pathMatcher = new AntPathMatcher();

    @org.springframework.beans.factory.annotation.Value("${app.jwt.secret}")
    private String jwtSecret;

    @Autowired
    private IgnoreWhiteProperties ignoreWhiteProperties; // 注入白名单配置

    @org.springframework.beans.factory.annotation.Value("${spring.security.login-url}")
    private String loginUrl;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Skip auth for login or public endpoints if needed
        if (request.getURI().getPath().startsWith("/api/public")) {
            return chain.filter(exchange);
        }
        String url = exchange.getRequest().getURI().getPath();
        // 2. 🔥【关键修复】检查白名单：如果匹配，直接放行，不做 Token 校验
        if (isWhiteList(url)) {
            return chain.filter(exchange);
        }

        String token = null;

        // 1. 优先尝试从 HttpOnly Cookie 中获取 (浏览器环境)
        org.springframework.http.HttpCookie cookie = request.getCookies().getFirst("jwt_token");
        if (cookie != null) {
            token = cookie.getValue();
        }
        // 2. 兜底策略：从 Authorization Header 中获取 (给 Python Agent 或 API 调用使用)
        else {
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
        }

        // 3. 如果什么都没拿到，返回 401 触发重定向重新登录
        if (token == null) {
            return onError(exchange, "Missing Authorization Cookie or Header",
                    HttpStatus.UNAUTHORIZED);
        }
        try {
            validateToken(token);
            // Optionally parse claims and add to headers
            // Claims claims = parseToken(token);
            // request.mutate().header("X-UserId", claims.getSubject()).build();
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
        }

        return chain.filter(exchange);
    }

    private void validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        // Return JSON error with redirect URL
        String jsonResponse =
                String.format("{\"url\": \"%s\", \"message\": \"%s\"}", loginUrl, err);
        byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        response.getHeaders().add("Content-Type", "application/json");

        return response.writeWith(Mono.just(buffer));
    }

    /**
     * 判断路径是否在白名单中
     */
    private boolean isWhiteList(String url) {
        // 遍历配置中的白名单列表
        for (String pattern : ignoreWhiteProperties.getUrls()) {
            // 使用 AntPathMatcher 支持 ** 通配符
            if (pathMatcher.match(pattern, url)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return -100; // High priority
    }
}
