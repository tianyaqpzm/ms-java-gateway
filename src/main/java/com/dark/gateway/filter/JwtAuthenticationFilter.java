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

import com.dark.gateway.config.IgnoreWhiteProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * JWT 认证过滤器：校验签名与过期时间，注入 X-User-Id 并透传原始 Token。
 * <p>
 * 网关仅负责"确认你是谁"（Authentication），不解析任何领域级业务字段。
 * 用户名、头像等业务信息由下游微服务从 JWT payload 自行解析。
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements WebFilter, Ordered {

    private static final String ALREADY_FILTERED =
            JwtAuthenticationFilter.class.getName() + ".FILTERED";
    private final PathMatcher pathMatcher = new AntPathMatcher();

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Autowired
    private IgnoreWhiteProperties ignoreWhiteProperties;

    @Value("${spring.security.login-url}")
    private String loginUrl;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getAttribute(ALREADY_FILTERED) != null) {
            return chain.filter(exchange);
        }
        exchange.getAttributes().put(ALREADY_FILTERED, true);

        ServerHttpRequest request = exchange.getRequest();
        String url = request.getURI().getPath();

        // 放行 OPTIONS 请求 (CORS 预检)
        if (org.springframework.http.HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        // 检查白名单
        if (isWhiteList(url)) {
            log.info("【JwtFilter】Whitelist pass: {}", url);
            return chain.filter(exchange);
        }

        String token = extractToken(request);

        // 如果没拿到 Token，交由后面的 Security 拦截器处理 (会触发 401/重定向)
        if (token == null) {
            log.info("【JwtFilter】No token found for protected resource: {}", url);
            return chain.filter(exchange);
        }

        try {
            Claims claims = validateAndParseToken(token);
            String userId = claims.getSubject();

            log.info("【JwtFilter】Token validated for user: {}", userId);

            // 构建 Authentication 对象并注入 SecurityContext
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList());

            // 网关仅注入用户ID，业务字段由下游从 JWT 自行解析
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", userId != null ? userId : "")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));

        } catch (Exception e) {
            log.error("【JwtFilter】Token validation failed for {}: {}, Reason: {}",
                    url,
                    token.substring(0, Math.min(token.length(), 10)) + "...",
                    e.getMessage());
            return onError(exchange, "Invalid Token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private String extractToken(ServerHttpRequest request) {
        // 优先从 HttpOnly Cookie 获取
        org.springframework.http.HttpCookie cookie = request.getCookies().getFirst("jwt_token");
        if (cookie != null) {
            return cookie.getValue();
        }

        // 兜底从 Authorization Header 获取
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
        if (ignoreWhiteProperties == null || ignoreWhiteProperties.getUrls() == null) {
            return false;
        }
        for (String pattern : ignoreWhiteProperties.getUrls()) {
            if (pathMatcher.match(pattern, url)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
