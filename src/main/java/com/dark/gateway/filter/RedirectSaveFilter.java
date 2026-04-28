package com.dark.gateway.filter;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RedirectSaveFilter implements WebFilter {

    public static final String REDIRECT_URI_COOKIE_NAME = "redirect_uri";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 如果是触发登录的请求
        if (path.startsWith("/oauth2/authorization/casdoor")) {
            // 获取前端传过来的 redirect 参数
            String redirectParam = exchange.getRequest().getQueryParams().getFirst("redirect");

            if (redirectParam != null) {
                // 如果目标地址包含 logout，则忽略，不存入 Cookie
                if (redirectParam.contains("/logout")) {
                    return chain.filter(exchange);
                }

                // 把原页面地址存入 Cookie，供登录成功后使用
                log.info("【RedirectSaveFilter】Saving REDIRECT_URI={} in Cookie", maskUri(redirectParam));
                ResponseCookie cookie = ResponseCookie.from(REDIRECT_URI_COOKIE_NAME, redirectParam)
                        .path("/")
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("Lax")
                        .maxAge(java.time.Duration.ofMinutes(5))
                        .build();
                exchange.getResponse().addCookie(cookie);
            }
        }
        return chain.filter(exchange);
    }

    private String maskUri(String uri) {
        if (uri == null || !uri.contains("?")) {
            return uri;
        }
        return uri.split("\\?")[0] + "?******";
    }
}
