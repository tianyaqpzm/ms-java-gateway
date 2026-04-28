package com.dark.gateway.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 白名单路径配置：列表中的 URL 不需要 JWT 认证。
 * 配置前缀使用 app.security.ignore，避免与 spring.security 官方配置冲突。
 */
@Component
@ConfigurationProperties(prefix = "app.security.ignore")
public class IgnoreWhiteProperties {
    private List<String> urls = new ArrayList<>();

    public List<String> getUrls() {
        return urls;
    }

    public void setUrls(List<String> urls) {
        this.urls = urls;
    }
}
