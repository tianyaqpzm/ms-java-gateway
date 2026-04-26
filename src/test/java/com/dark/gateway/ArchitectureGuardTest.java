package com.dark.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.server.WebFilter;
import com.dark.gateway.filter.IgnoreWhiteProperties;
import com.dark.gateway.filter.JwtAuthenticationFilter;
import com.dark.gateway.filter.RedirectSaveFilter;
import com.dark.gateway.filter.SecurityConfig;

/**
 * 架构守护测试：确保 Bean 装配、接口契约、架构约束不被破坏。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class ArchitectureGuardTest {

    @Autowired
    private ApplicationContext ctx;

    // GA-01: SecurityConfig Bean 成功创建
    @Test
    @DisplayName("GA-01: SecurityConfig Bean 可正常加载")
    public void securityConfigBeanShouldLoad() {
        SecurityConfig config = ctx.getBean(SecurityConfig.class);
        assertThat(config).isNotNull();
    }

    // GA-02: JwtAuthenticationFilter 注册为 WebFilter 且 order = -100
    @Test
    @DisplayName("GA-02: JwtAuthenticationFilter 是 WebFilter 且 order=-100")
    public void jwtFilterShouldBeWebFilterWithCorrectOrder() {
        JwtAuthenticationFilter filter = ctx.getBean(JwtAuthenticationFilter.class);
        assertThat(filter).isInstanceOf(WebFilter.class);
        assertThat(filter).isInstanceOf(Ordered.class);
        assertThat(filter.getOrder()).isEqualTo(-100);
    }

    // GA-03: RedirectSaveFilter 注册为 WebFilter
    @Test
    @DisplayName("GA-03: RedirectSaveFilter 是 WebFilter")
    public void redirectSaveFilterShouldBeWebFilter() {
        RedirectSaveFilter filter = ctx.getBean(RedirectSaveFilter.class);
        assertThat(filter).isInstanceOf(WebFilter.class);
    }

    // GA-04: IgnoreWhiteProperties 正确绑定 YAML list
    @Test
    @DisplayName("GA-04: IgnoreWhiteProperties 正确绑定白名单 URL 列表")
    public void ignoreWhitePropertiesShouldBindUrls() {
        IgnoreWhiteProperties props = ctx.getBean(IgnoreWhiteProperties.class);
        assertThat(props.getUrls()).isNotEmpty().contains("/actuator/health", "/oauth2/**",
                "/logout");
    }

    // GA-05: classpath 不包含 DispatcherServlet (架构约束: 严格非阻塞)
    @Test
    @DisplayName("GA-05: classpath 不含 DispatcherServlet (非阻塞架构)")
    public void shouldNotContainServletStack() {
        boolean hasServlet;
        try {
            Class.forName("org.springframework.web.servlet.DispatcherServlet");
            hasServlet = true;
        } catch (ClassNotFoundException e) {
            hasServlet = false;
        }
        assertThat(hasServlet).as("Gateway 是 WebFlux 架构，不应引入 Servlet 栈").isFalse();
    }
}
