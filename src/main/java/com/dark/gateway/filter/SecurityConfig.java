package com.dark.gateway.filter;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@Slf4j
public class SecurityConfig {

    @Value("${app.frontend-url:https://122577.xyz}")
    private String frontendUrl;

    @Value("${spring.security.login-url}")
    private String loginUrl;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.cookie-domain:122577.xyz}")
    private String cookieDomain;

    private final IgnoreWhiteProperties ignoreWhiteProperties;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(IgnoreWhiteProperties ignoreWhiteProperties,
            JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.ignoreWhiteProperties = ignoreWhiteProperties;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        String[] ignoreUrls = ignoreWhiteProperties.getUrls().toArray(new String[0]);

        return http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(exchanges -> exchanges.pathMatchers(HttpMethod.OPTIONS)
                        .permitAll().pathMatchers(ignoreUrls).permitAll()
                        .pathMatchers("/api/public/**", "/favicon.ico", "/actuator/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authenticationFailureHandler((webFilterExchange, exception) -> {
                            log.error("【OAuth2 登录失败】原因: {}", exception.getMessage());
                            return Mono.error(exception);
                        })
                        .authenticationSuccessHandler(authenticationSuccessHandler()))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(serverAuthenticationEntryPoint()))
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessHandler(new RedirectServerLogoutSuccessHandler()))
                .build();
    }

    /**
     * 登录成功处理器：提取用户信息，生成 JWT 并存入 Cookie
     */
    private ServerAuthenticationSuccessHandler authenticationSuccessHandler() {
        return (webFilterExchange, authentication) -> {
            log.info("【登录成功】生成 JWT Token 并写入 Cookie...{}", cookieDomain);

            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            String userId = oidcUser.getSubject();
            String name = oidcUser.getName();
            String picture = oidcUser.getPicture();

            // 1. 生成 JWT
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            String token = Jwts.builder().setSubject(userId).claim("name", name)
                    .claim("picture", picture != null ? picture : "").setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 24小时过期
                    .signWith(key).compact();

            // 2. 写入 HttpOnly Cookie
            ResponseCookie jwtCookie = ResponseCookie.from("jwt_token", token).path("/")
                    .domain(cookieDomain).httpOnly(true).secure(true) // 生产环境必须开启
                    .sameSite("Lax").maxAge(86400).build();


            webFilterExchange.getExchange().getResponse().addCookie(jwtCookie);

            // 3. 处理重定向地址
            return webFilterExchange.getExchange().getSession().flatMap(session -> {
                String redirectUri = session.getAttribute("CUSTOM_REDIRECT_URI");
                if (redirectUri == null) {
                    redirectUri = frontendUrl;
                }
                log.info("【重定向】Redirecting to: {}", redirectUri);
                
                // 同时把 token 带在 URL 上，方便前端获取并存入 localStorage (作为双保险)
                String finalRedirectUri = redirectUri;
                if (finalRedirectUri.contains("?")) {
                    finalRedirectUri += "&token=" + token;
                } else {
                    finalRedirectUri += "?token=" + token;
                }
                
                webFilterExchange.getExchange().getResponse().setStatusCode(HttpStatus.FOUND);
                webFilterExchange.getExchange().getResponse().getHeaders()
                        .setLocation(URI.create(finalRedirectUri));
                return Mono.empty();
            });
        };
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

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOriginPattern("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * 日志过滤器：记录所有进入网关的请求路径
     */
    @Bean
    @org.springframework.core.annotation.Order(-200) // 运行在所有过滤器之前
    public org.springframework.web.server.WebFilter logFilter() {
        return (exchange, chain) -> {
            log.info("【网关请求】{} {}", exchange.getRequest().getMethod(),
                    exchange.getRequest().getURI().getPath());
            return chain.filter(exchange);
        };
    }
}
