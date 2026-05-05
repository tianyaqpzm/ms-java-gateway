package com.dark.gateway.filter;

import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * 绕过 Chrome Private Network Access (PNA) 限制的拦截器。
 * <p>
 * 当公网域名访问解析到本地/局域网的网关时，Chrome 会触发 PNA 拦截。
 * 通过在所有响应（包含 OPTIONS 预检）中注入 CSP treat-as-public-address，
 * 告诉浏览器将此网关视为公网地址，从而彻底免疫 PNA 报错。
 */
@Component
public class PnaBypassFilter implements WebFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 向所有响应头中注入 CSP 指令
        exchange.getResponse().getHeaders().add("Content-Security-Policy", "treat-as-public-address");
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        // 必须拥有最高优先级，确保在 CorsWebFilter 和 SecurityFilterChain 之前执行
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
