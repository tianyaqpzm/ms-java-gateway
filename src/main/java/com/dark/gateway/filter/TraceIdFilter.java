package com.dark.gateway.filter;

import java.util.UUID;

import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * 链路追踪过滤器：网关作为流量第一跳，生成全局唯一 X-Trace-Id。
 * <p>
 * 如果上游（如 Nginx）已注入 X-Trace-Id，则直接复用；否则生成新的。
 * Trace-ID 同时写入请求头（传递给下游）和响应头（方便前端排查）。
 */
@Slf4j
@Component
public class TraceIdFilter implements WebFilter, Ordered {

    public static final String TRACE_ID_HEADER = "X-Trace-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String traceId = exchange.getRequest().getHeaders().getFirst(TRACE_ID_HEADER);

        if (traceId == null || traceId.isBlank()) {
            traceId = UUID.randomUUID().toString().replace("-", "");
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(TRACE_ID_HEADER, traceId)
                .build();

        // 同时写入响应头，方便前端排查
        exchange.getResponse().getHeaders().add(TRACE_ID_HEADER, traceId);

        String method = exchange.getRequest().getMethod() != null
                ? exchange.getRequest().getMethod().name() : "UNKNOWN";
        String path = exchange.getRequest().getURI().getPath();

        log.info("【Trace】{} {} traceId={}", method, path, traceId);

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return -200; // 在 JWT Filter (-100) 之前执行
    }
}
