package com.dark.gateway.filter;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

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
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 1. 路由权限配置 (Lambda 写法)
                .authorizeExchange(
                        exchanges -> exchanges.pathMatchers("/api/public/**", "/favicon.ico", "/actuator/**")
                                .permitAll().anyExchange().authenticated())
                // 2. OAuth2 登录配置 (✅ 最新 Lambda DSL 写法)
                // 使用 Customizer.withDefaults() 启用默认的 OAuth2 登录流程
                .oauth2Login(oauth2 -> oauth2
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
                            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
                            String token = Jwts.builder()
                                    .setSubject(userId)
                                    .claim("name", name)
                                    .claim("picture", picture)
                                    .setIssuedAt(new Date())
                                    .setExpiration(new Date(System.currentTimeMillis() + 86400000 * 7)) // 7 天有效期
                                    .signWith(key)
                                    .compact();

                            var exchange = webFilterExchange.getExchange();
                            var response = exchange.getResponse();

                            // 3. 写入 HttpOnly Cookie
                            response.addCookie(ResponseCookie.from("jwt_token", token)
                                    .httpOnly(true)
                                    .path("/")
                                    .domain(cookieDomain) // 设置二级域名共享
                                    .maxAge(Duration.ofDays(7))
                                    .build());

                            return exchange.getSession().flatMap(session -> {
                                // 1. 尝试从 Session 取出原页面地址，如果没有，就用默认地址兜底
                                String redirectUri = session.getAttributeOrDefault(
                                        "CUSTOM_REDIRECT_URI", defaultFrontendUrl);

                                // 2. 用完即焚，清理 Session，保持干净
                                session.getAttributes().remove("CUSTOM_REDIRECT_URI");

                                // 3. 执行真正的 302 重定向，把用户送回原页面
                                response.setStatusCode(HttpStatus.FOUND);
                                response.getHeaders().setLocation(URI.create(redirectUri));
                                return response.setComplete();
                            });
                        }))
                // 3. 禁用 CSRF (✅ 最新 Lambda DSL 写法)
                .csrf(csrf -> csrf.disable())
                // 4. 自定义未授权处理，返回 401 携带登录跳转链接
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(serverAuthenticationEntryPoint()));

        return http.build();
    }

    private ServerAuthenticationEntryPoint serverAuthenticationEntryPoint() {
        return (exchange, e) -> {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            String jsonResponse = String.format(
                    "{\"url\": \"%s\", \"message\": \"Authentication required\"}", loginUrl);
            byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }
}
