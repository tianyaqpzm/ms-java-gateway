package com.dark.gateway.filter;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class SecurityConfig {

    @Value("${spring.security.login-url}")
    private String loginUrl;

    // 默认兜底地址（如果用户是直接敲网关地址登录的，没有传 redirect 参数，就跳这里）
    @Value("${app.frontend-url}")
    private String defaultFrontendUrl;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.cookie-domain}")
    private String cookieDomain;

    @Bean
    public WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName("DARK_SESSION"); // 统一修改为 DARK_SESSION
        resolver.addCookieInitializer(builder -> builder
                .domain(cookieDomain)
                .path("/")
                .sameSite("Lax") // 解决跨站重定向 Cookie 丢失问题
                .httpOnly(true));
        return resolver;
    }

    private final IgnoreWhiteProperties ignoreWhiteProperties;

    public SecurityConfig(IgnoreWhiteProperties ignoreWhiteProperties) {
        this.ignoreWhiteProperties = ignoreWhiteProperties;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        String[] ignoreUrls = ignoreWhiteProperties.getUrls().toArray(new String[0]);
        log.info("【SecurityConfig】Loaded ignore URLs from properties: {}", (Object) ignoreUrls);

        http
                // 1. 路由权限配置 (Lambda 写法)
                .authorizeExchange(
                        exchanges -> exchanges
                                .pathMatchers(ignoreUrls).permitAll()
                                .anyExchange().authenticated())
                // 2. OAuth2 登录配置 (✅ 最新 Lambda DSL 写法)
                // 使用 Customizer.withDefaults() 启用默认的 OAuth2 登录流程
                .oauth2Login(oauth2 -> oauth2
                        // 👇 处理登录失败
                        .authenticationFailureHandler((webFilterExchange, exception) -> {
                            log.error("【OAuth2 登录失败】原因: {}", exception.getMessage());
                            return Mono.error(exception);
                        })
                        // 👇 完全自定义的成功处理器
                        .authenticationSuccessHandler((webFilterExchange, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

                            // 1. 提取用户信息 (兼容 Casdoor 不同的 Claim 名称)
                            String userId = oAuth2User.getName();
                            String name = oAuth2User.getAttribute("name");
                            if (name == null) {
                                name = oAuth2User.getAttribute("preferred_username");
                            }
                            String picture = oAuth2User.getAttribute("picture");
                            if (picture == null) {
                                picture = oAuth2User.getAttribute("avatar");
                            }

                            // 2. 生成 JWT Token
                            SecretKey key =
                                    Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
                            String token = Jwts.builder().setSubject(userId).claim("name", name)
                                    .claim("picture", picture).setIssuedAt(new Date())
                                    .setExpiration(
                                            new Date(System.currentTimeMillis() + 86400000)) // 1 天 (24小时) 有效期
                                    .signWith(key).compact();

                            var exchange = webFilterExchange.getExchange();
                            var response = exchange.getResponse();

                            // 3. 写入 HttpOnly Cookie
                            response.addCookie(ResponseCookie.from("jwt_token", token)
                                    .httpOnly(true)
                                    .secure(true) // 🔥 必须开启 Secure，否则 HTTPS 浏览器可能拒绝发送
                                    .sameSite("Lax") // 🔥 设置 SameSite，解决跨域/重定向丢失问题
                                    .path("/")
                                    .domain(cookieDomain) // 设置二级域名共享
                                    .maxAge(Duration.ofDays(1)).build());

                            return exchange.getSession().flatMap(session -> {
                                // 1. 尝试从 Session 取出原页面地址，如果没有，就用默认地址兜底
                                String redirectUri = session.getAttributeOrDefault(
                                        "CUSTOM_REDIRECT_URI", defaultFrontendUrl);

                                // 2. 用完即焚，清理 Session，保持干净
                                session.getAttributes().remove("CUSTOM_REDIRECT_URI");

                                // 3. 执行真正的 302 重定向，把用户送回原页面
                                // 🔥【优化】同时把 token 带在 URL 上，方便前端获取并存入 localStorage
                                String finalRedirectUri = redirectUri;
                                if (finalRedirectUri.contains("?")) {
                                    finalRedirectUri += "&token=" + token;
                                } else {
                                    finalRedirectUri += "?token=" + token;
                                }

                                response.setStatusCode(HttpStatus.FOUND);
                                response.getHeaders().setLocation(URI.create(finalRedirectUri));
                                return response.setComplete();
                            });
                        }))
                // 3. 登出配置
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler((webFilterExchange, authentication) -> {
                            var exchange = webFilterExchange.getExchange();
                            var response = exchange.getResponse();
                            // 清除 Cookie
                            response.addCookie(ResponseCookie.from("jwt_token", "")
                                    .maxAge(0).path("/").domain(cookieDomain).build());
                            // 重定向到登录页
                            response.setStatusCode(HttpStatus.FOUND);
                            response.getHeaders().setLocation(URI.create(loginUrl));
                            return response.setComplete();
                        }))
                // 4. 禁用 CSRF (✅ 最新 Lambda DSL 写法)
                .csrf(csrf -> csrf.disable())
                // 5. 自定义未授权处理，返回 401 携带登录跳转链接
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(serverAuthenticationEntryPoint()));

        return http.build();
    }

    private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint() {
        return (exchange, e) -> {
            log.warn("【未授权访问】Path: {}, Reason: {}", exchange.getRequest().getURI().getPath(),
                    e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            String jsonResponse = String.format(
                    "{\"url\": \"%s\", \"message\": \"Authentication required\"}", loginUrl);
            byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }

    // 增加请求头日志打印，帮助排查 Nginx 转发参数
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public WebFilter logFilter() {
        return (exchange, chain) -> {
            var request = exchange.getRequest();
            log.info("【网关接受请求】Path: {}, Host: {}, X-Forwarded-Port: {}, X-Forwarded-Proto: {}",
                    request.getURI().getPath(), request.getHeaders().getFirst("Host"),
                    request.getHeaders().getFirst("X-Forwarded-Port"),
                    request.getHeaders().getFirst("X-Forwarded-Proto"));
            return chain.filter(exchange);
        };
    }
}
