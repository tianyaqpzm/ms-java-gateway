package com.dark.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements WebFilter, Ordered {

    private static final String ALREADY_FILTERED =
            JwtAuthenticationFilter.class.getName() + ".FILTERED";
    private final PathMatcher pathMatcher = new AntPathMatcher();

    @Value("${app.jwt.secret:default-secret-placeholder-must-be-long-enough}")
    private String jwtSecret;

    @Autowired
    private IgnoreWhiteProperties ignoreWhiteProperties;

    @Value("${spring.security.login-url:/login}")
    private String loginUrl;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getAttribute(ALREADY_FILTERED) != null) {
            return chain.filter(exchange);
        }
        exchange.getAttributes().put(ALREADY_FILTERED, true);

        ServerHttpRequest request = exchange.getRequest();
        String url = request.getURI().getPath();

        // 0. 放行 OPTIONS 请求 (CORS 预检)
        if (org.springframework.http.HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        // 1. 检查白名单
        if (isWhiteList(url)) {
            log.info("【JwtFilter】Whitelist pass: {}", url);
            return chain.filter(exchange);
        }

        String token = extractToken(request);

        // 2. 如果没拿到 Token，交由后面的 Security 拦截器处理 (会触发 401/重定向)
        if (token == null) {
            log.info("【JwtFilter】No token found (Cookie or Authorization header) for protected resource: {}", url);
            return chain.filter(exchange);
        }

        try {
            Claims claims = validateAndParseToken(token);
            String userId = claims.getSubject();

            log.info("【JwtFilter】Token validated for user: {}", userId);

            // 3. 构建 Authentication 对象并注入 SecurityContext
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList());

            // 透明透传用户信息给下游微服务
            String username = claims.get("name", String.class);
            if (username == null)
                username = claims.get("username", String.class);
            String avatar = claims.get("picture", String.class);
            if (avatar == null)
                avatar = claims.get("avatar", String.class);

            ServerHttpRequest mutatedRequest =
                    request.mutate().header("X-User-Id", userId != null ? userId : "")
                            .header("X-User-Name", username != null ? username : "")
                            .header("X-User-Avatar", avatar != null ? avatar : "").build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        } catch (Exception e) {
            log.error("【JwtFilter】Token validation failed for {}: {}, Reason: {}", url, token.substring(0, Math.min(token.length(), 10)) + "...", e.getMessage());
            return onError(exchange, "Invalid Token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private String extractToken(ServerHttpRequest request) {
        // 1. 优先从 HttpOnly Cookie 获取
        org.springframework.http.HttpCookie cookie = request.getCookies().getFirst("jwt_token");
        if (cookie != null)
            return cookie.getValue();

        // 2. 兜底从 Authorization Header 获取
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private Claims validateAndParseToken(String token) {
        byte[] secretBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        SecretKey key = Keys.hmacShaKeyFor(secretBytes);
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String jsonResponse = String.format("{\"url\": \"%s\", \"message\": \"%s\"}",
                loginUrl, err);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory()
                .wrap(jsonResponse.getBytes(StandardCharsets.UTF_8))));
    }

    private boolean isWhiteList(String url) {
        if (ignoreWhiteProperties == null || ignoreWhiteProperties.getUrls() == null)
            return false;
        for (String pattern : ignoreWhiteProperties.getUrls()) {
            if (pathMatcher.match(pattern, url))
                return true;
        }
        return false;
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
