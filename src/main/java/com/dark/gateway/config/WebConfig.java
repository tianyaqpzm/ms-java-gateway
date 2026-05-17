package com.dark.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * WebFlux 自定义路由与 Web 交互配置。
 */
@Configuration
public class WebConfig {

    /**
     * 解决浏览器自动请求 favicon.ico 导致的 404 异常日志刷屏问题。
     * 直接返回 204 No Content，避免触发网关异常处理器。
     */
    @Bean
    public RouterFunction<ServerResponse> faviconRouter() {
        return RouterFunctions.route(RequestPredicates.GET("/favicon.ico"),
                request -> ServerResponse.noContent().build());
    }
}
