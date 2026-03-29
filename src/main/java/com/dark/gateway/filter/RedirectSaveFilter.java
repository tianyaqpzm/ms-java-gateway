package com.dark.gateway.filter;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 如果是触发登录的请求
        if (path.startsWith("/oauth2/authorization/casdoor")) {
            // 获取前端传过来的 redirect 参数
            String redirectParam = exchange.getRequest().getQueryParams().getFirst("redirect");

            if (redirectParam != null) {
                // 把原页面地址存入 Session，供登录成功后使用
                return exchange.getSession().flatMap(session -> {
                    log.info("【RedirectSaveFilter】Saving CUSTOM_REDIRECT_URI={} in Session ID={}",
                            redirectParam, session.getId());
                    session.getAttributes().put("CUSTOM_REDIRECT_URI", redirectParam);
                    return session.save().thenReturn(session); // 明确触发保存
                }).then(chain.filter(exchange));
            }
        }
        return chain.filter(exchange);
    }
}
