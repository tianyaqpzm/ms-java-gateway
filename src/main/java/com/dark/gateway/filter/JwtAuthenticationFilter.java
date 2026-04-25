package com.dark.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements WebFilter, Ordered {

    private final PathMatcher pathMatcher = new AntPathMatcher();

    @org.springframework.beans.factory.annotation.Value("${app.jwt.secret}")
    private String jwtSecret;

    @Autowired
    private IgnoreWhiteProperties ignoreWhiteProperties;

    @org.springframework.beans.factory.annotation.Value("${spring.security.login-url}")
    private String loginUrl;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String url = request.getURI().getPath();

        // 0. 放行 OPTIONS 请求 (CORS 预检)
        if (org.springframework.http.HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        // 1. 检查白名单
        if (isWhiteList(url)) {
            return chain.filter(exchange);
        }

        String token = extractToken(request);

        // 2. 如果没拿到 Token，交由后面的 Security 拦截器处理 (会触发 401/重定向)
        if (token == null) {
            return chain.filter(exchange);
        }

        try {
            Claims claims = validateAndParseToken(token);
            String userId = claims.getSubject();
            
            log.debug("【JwtFilter】Token validated for user: {}", userId);

            // 3. 构建 Authentication 对象并注入 SecurityContext
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userId, null, Collections.emptyList());

            // 透明透传用户信息给下游微服务 (通过 Mutate Request)
            String username = claims.get("name", String.class);
            if (username == null) username = claims.get("username", String.class);
            String avatar = claims.get("picture", String.class);
            if (avatar == null) avatar = claims.get("avatar", String.class);

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-User-Name", username != null ? username : "")
                    .header("X-User-Avatar", avatar != null ? avatar : "")
                    .build();

            // 将认证信息存入 ReactiveSecurityContextHolder，并继续过滤链
            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        } catch (Exception e) {
            log.error("【JwtFilter】Token validation failed: {}", e.getMessage());
            // Token 校验失败，直接返回 401
            return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
        }
    }

    private String extractToken(ServerHttpRequest request) {
        // 1. 优先从 HttpOnly Cookie 获取
        org.springframework.http.HttpCookie cookie = request.getCookies().getFirst("jwt_token");
        if (cookie != null) return cookie.getValue();

        // 2. 兜底从 Authorization Header 获取
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private Claims validateAndParseToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        String jsonResponse = String.format("{\"url\": \"%s\", \"message\": \"%s\"}", loginUrl, err);
        return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8))));
    }

    private boolean isWhiteList(String url) {
        for (String pattern : ignoreWhiteProperties.getUrls()) {
            if (pathMatcher.match(pattern, url)) return true;
        }
        return false;
    }

    @Override
    public int getOrder() {
        return -100; // High priority
    }
}
