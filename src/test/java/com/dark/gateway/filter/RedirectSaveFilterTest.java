package com.dark.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * RedirectSaveFilter 单元测试：Cookie 存取、logout 过滤、非 OAuth2 路径放行
 */
class RedirectSaveFilterTest {

    private final RedirectSaveFilter filter = new RedirectSaveFilter();

    // GR-01: OAuth2 登录请求携带 redirect 参数 → 存入 Cookie
    @Test
    @DisplayName("GR-01: OAuth2 路径 + redirect 参数 → 存入 Cookie")
    void oauthPathWithRedirectShouldSaveToCookie() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/oauth2/authorization/casdoor?redirect=https://app.example.com/dashboard")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        WebFilterChain chain = filterExchange -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // 验证 Cookie 中存入了重定向地址
        HttpCookie cookie = exchange.getResponse().getCookies().getFirst(RedirectSaveFilter.REDIRECT_URI_COOKIE_NAME);
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue()).isEqualTo("https://app.example.com/dashboard");
    }

    // GR-02: redirect 参数包含 /logout → 不存入 Cookie
    @Test
    @DisplayName("GR-02: redirect 含 /logout → 不存入 Cookie")
    void oauthPathWithLogoutRedirectShouldNotSave() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/oauth2/authorization/casdoor?redirect=https://app.example.com/logout")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        WebFilterChain chain = filterExchange -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // 验证 Cookie 未被存入
        HttpCookie cookie = exchange.getResponse().getCookies().getFirst(RedirectSaveFilter.REDIRECT_URI_COOKIE_NAME);
        assertThat(cookie).isNull();
    }

    // GR-03: 非 OAuth2 路径 → 直接放行
    @Test
    @DisplayName("GR-03: 非 OAuth2 路径 → 直接放行不操作 Cookie")
    void nonOauthPathShouldPassThrough() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/business/orders")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        WebFilterChain chain = filterExchange -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // 验证没有生成 Cookie
        assertThat(exchange.getResponse().getCookies()).doesNotContainKey(RedirectSaveFilter.REDIRECT_URI_COOKIE_NAME);
    }
}
