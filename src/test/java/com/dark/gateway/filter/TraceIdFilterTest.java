package com.dark.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * TraceIdFilter 单元测试：Trace-ID 生成、上游复用、响应头注入
 */
class TraceIdFilterTest {

    private final TraceIdFilter filter = new TraceIdFilter();

    // GT-01: 无上游 Trace-ID → 自动生成并注入请求头和响应头
    @Test
    @DisplayName("GT-01: 无上游 Trace-ID → 自动生成 32 位 hex")
    void shouldGenerateTraceIdWhenNoneExists() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/business/orders")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // 捕获传递给下游的请求
        final String[] capturedTraceId = {null};
        WebFilterChain chain = filterExchange -> {
            capturedTraceId[0] = filterExchange.getRequest().getHeaders()
                    .getFirst(TraceIdFilter.TRACE_ID_HEADER);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // 验证请求头中注入了 Trace-ID
        assertThat(capturedTraceId[0]).isNotNull().hasSize(32); // UUID 去掉 - 后 32 字符

        // 验证响应头中也有 Trace-ID
        String responseTraceId = exchange.getResponse().getHeaders()
                .getFirst(TraceIdFilter.TRACE_ID_HEADER);
        assertThat(responseTraceId).isEqualTo(capturedTraceId[0]);
    }

    // GT-02: 上游已有 Trace-ID → 直接复用
    @Test
    @DisplayName("GT-02: 上游已有 Trace-ID → 复用不覆盖")
    void shouldReuseExistingTraceId() {
        String existingTraceId = "abc123def456";
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/business/orders")
                .header(TraceIdFilter.TRACE_ID_HEADER, existingTraceId)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        final String[] capturedTraceId = {null};
        WebFilterChain chain = filterExchange -> {
            capturedTraceId[0] = filterExchange.getRequest().getHeaders()
                    .getFirst(TraceIdFilter.TRACE_ID_HEADER);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(capturedTraceId[0]).isEqualTo(existingTraceId);

        String responseTraceId = exchange.getResponse().getHeaders()
                .getFirst(TraceIdFilter.TRACE_ID_HEADER);
        assertThat(responseTraceId).isEqualTo(existingTraceId);
    }

    // GT-03: 上游 Trace-ID 为空白 → 生成新的
    @Test
    @DisplayName("GT-03: 上游 Trace-ID 为空白字符串 → 生成新的")
    void shouldGenerateNewTraceIdWhenBlank() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/business/orders")
                .header(TraceIdFilter.TRACE_ID_HEADER, "   ")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        final String[] capturedTraceId = {null};
        WebFilterChain chain = filterExchange -> {
            capturedTraceId[0] = filterExchange.getRequest().getHeaders()
                    .getFirst(TraceIdFilter.TRACE_ID_HEADER);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(capturedTraceId[0]).isNotBlank().hasSize(32);
    }

    // GT-04: Order 为 -200，在 JwtFilter 之前执行
    @Test
    @DisplayName("GT-04: Order = -200，在 JwtFilter (-100) 之前执行")
    void orderShouldBeNegative200() {
        assertThat(filter.getOrder()).isEqualTo(-200);
    }
}
