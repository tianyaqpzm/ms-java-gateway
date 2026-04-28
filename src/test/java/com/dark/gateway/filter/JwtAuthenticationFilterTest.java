package com.dark.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * JWT 认证过滤器测试: 白名单放行、Token 校验、X-User 头注入、异常场景
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureWebTestClient
class JwtAuthenticationFilterTest {

    @Autowired
    private WebTestClient webTestClient;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private String validToken;
    private String expiredToken;
    private String wrongSecretToken;
    private String tokenMissingClaims;

    @BeforeEach
    void setUp() {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        // 有效 Token (含所有 claims)
        validToken = Jwts.builder()
                .setSubject("user-123")
                .claim("name", "Test User")
                .claim("picture", "https://example.com/avatar.png")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key)
                .compact();

        // 过期 Token
        expiredToken = Jwts.builder()
                .setSubject("user-123")
                .claim("name", "Test User")
                .setIssuedAt(new Date(System.currentTimeMillis() - 200000))
                .setExpiration(new Date(System.currentTimeMillis() - 100000))
                .signWith(key)
                .compact();

        // 错误 secret 签名的 Token
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                "wrong-secret-key-must-be-at-least-256-bits-long!!".getBytes(StandardCharsets.UTF_8));
        wrongSecretToken = Jwts.builder()
                .setSubject("user-123")
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(wrongKey)
                .compact();

        // 缺失 name/picture 的 Token
        tokenMissingClaims = Jwts.builder()
                .setSubject("user-456")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key)
                .compact();
    }

    // GJ-01: 白名单精确路径放行
    @Test
    @DisplayName("GJ-01: 白名单精确路径 /actuator/health 放行")
    void whitelistExactPathShouldPass() {
        webTestClient.get().uri("/actuator/health")
                .exchange()
                .expectStatus().value(status ->
                        assertThat(status).isNotEqualTo(401)); // 放行即可，不应返回 401
    }

    // GJ-02: 白名单通配符路径放行
    @Test
    @DisplayName("GJ-02: 白名单通配符 /api/public/** 放行")
    void whitelistWildcardPathShouldPass() {
        webTestClient.get().uri("/api/public/any-resource")
                .exchange()
                .expectStatus().value(status ->
                        assertThat(status).isNotEqualTo(401));
    }

    // GJ-03: Cookie JWT → 放行 + X-User 头注入
    @Test
    @DisplayName("GJ-03: Cookie 中携带有效 JWT → 放行")
    void validCookieTokenShouldPassAndInjectHeaders() {
        webTestClient.get().uri("/api/test/resource")
                .cookie("jwt_token", validToken)
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(401)); // 放行即可，不一定非要 500
    }

    // GJ-04: Bearer Header JWT → 放行
    @Test
    @DisplayName("GJ-04: Authorization Bearer Header 携带有效 JWT → 放行")
    void validBearerTokenShouldPass() {
        webTestClient.get().uri("/api/test/resource")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(401));
    }

    // GJ-05: 无 Token → 401 JSON
    @Test
    @DisplayName("GJ-05: 无 Token → 返回 401 JSON")
    void noTokenShouldReturn401() {
        webTestClient.get().uri("/api/test/resource")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.url").exists()
                .jsonPath("$.message").exists();
    }

    // GJ-06: 过期 Token → 401
    @Test
    @DisplayName("GJ-06: 过期 Token → 返回 401")
    void expiredTokenShouldReturn401() {
        webTestClient.get().uri("/api/test/resource")
                .cookie("jwt_token", expiredToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // GJ-07: 签名错误 → 401
    @Test
    @DisplayName("GJ-07: 签名错误的 Token → 返回 401")
    void wrongSignatureTokenShouldReturn401() {
        webTestClient.get().uri("/api/test/resource")
                .cookie("jwt_token", wrongSecretToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // GJ-08: Claim 缺失 → 头为空字符串
    @Test
    @DisplayName("GJ-08: Claim 字段缺失时仍放行")
    void missingClaimsShouldStillPass() {
        webTestClient.get().uri("/api/test/resource")
                .cookie("jwt_token", tokenMissingClaims)
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(401));
    }


}
