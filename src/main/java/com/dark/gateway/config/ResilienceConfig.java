package com.dark.gateway.config;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 容错与弹性配置。
 * <p>
 * 全局超时通过 application.yml 中的 spring.cloud.gateway.httpclient 配置，
 * 此类提供 WebProperties Bean 以支持 GatewayErrorHandler 的自动配置。
 * <p>
 * 后续迭代可在此引入 Resilience4j 熔断器。
 */
@Configuration
public class ResilienceConfig {

    /**
     * WebProperties Bean：供 GatewayErrorHandler (AbstractErrorWebExceptionHandler) 使用。
     */
    @Bean
    public WebProperties webProperties() {
        return new WebProperties();
    }
}
